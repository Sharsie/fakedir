#include "common.h"
#include "execve.h"


/**
 * @file        fakedir.c
 * @author      Karim Vergnes <me@thesola.io>
 * @copyright   GPLv2
 * @brief       Injection library to fake a directory existing elsewhere.
 *
 * This library swaps system calls which take a path as argument for versions
 * where the specified substitution exists.
 * The end result is a virtual filesystem tree where TARGET exists at PATTERN
 * but will not show up in a directory listing.
 *
 * Due to the sensitive nature of these system calls, heap memory allocation is
 * strictly forbidden. All code below must use memory allocated on the stack.
 */

// Pulled from trivial_replacements. It's useful.
int my_open(char const *name, int flags, int mode);

bool _loaded = false;

bool isdebug = false;

const char *ownpath;

#ifndef STRIP_DEBUG
int debugfd = 2;
#endif

pthread_mutex_t _lock;

const char *pattern;
const char *target;

static void __fakedir_atfork_prepare(void) { pthread_mutex_lock(&_lock); }
static void __fakedir_atfork_parent(void)  { pthread_mutex_unlock(&_lock); }
static void __fakedir_atfork_child(void)   { pthread_mutex_init(&_lock, NULL); }

__attribute__((constructor))
static void __fakedir_init(void)
{
    if (_loaded)
        return;

    isdebug = getenv("FAKEDIR_DEBUG");
    pattern = getenv("FAKEDIR_PATTERN");
    target = getenv("FAKEDIR_TARGET");
    if (! (pattern && target)) {
        dprintf(2, "Variables FAKEDIR_PATTERN and FAKEDIR_TARGET must be set.\n");
        exit(1);
    } else if (! (pattern[0] == '/' && target[0] == '/')) {
        dprintf(2, "Variables FAKEDIR_PATTERN and FAKEDIR_TARGET must be absolute paths.\n");
        exit(1);
    } else if (startswith(pattern, target)) {
        dprintf(2, "Variable FAKEDIR_PATTERN may not be a subset of FAKEDIR_TARGET.\n");
        exit(1);
    }

#   if !defined(STRIP_DEBUG) && defined(DEBUG_FILE)
    char tgt[PATH_MAX];
    sprintf(tgt, "%s.%d", DEBUG_FILE, getpid());
    debugfd = open(tgt, O_CREAT|O_RDWR, 0644);
#   endif

#   ifdef STRIP_DEBUG
    if (isdebug)
        dprintf(2, "[fakedir] WARNING: This build was configured without debug messages.\n");
#   elif defined(ALWAYS_DEBUG)
    dprintf(2, "[fakedir] WARNING: This build was configured with mandatory debug messages.\n");
    isdebug = true;
#   endif

#   define selfname "libfakedir.dylib"
    int nimgs = _dyld_image_count();
    for (int i = 0; i < nimgs; i++) {
        ownpath = _dyld_get_image_name(i);
        if (endswith(selfname, ownpath))
            break;
    }
    DEBUG("I think I am '%s'", ownpath);

    rewrite_init();

    pthread_mutex_init(&_lock, NULL);
    // A fork while another thread sits inside an interposer leaves the
    // child's _lock locked forever - python's test runners fork worker
    // processes from threaded parents and deadlocked on the first
    // interposed syscall. Serialize fork against the lock, and hand the
    // child a fresh mutex.
    pthread_atfork(__fakedir_atfork_prepare,
                   __fakedir_atfork_parent,
                   __fakedir_atfork_child);
    DEBUG("Initialized libfakedir with subtitution '%s' => '%s'", pattern, target);
    _loaded = true;
}

__attribute__((destructor))
static void __fakedir_fini(void)
{
    DEBUG("Closing shop and deleting mutex.");
#   if !defined STRIP_DEBUG && defined(DEBUG_FILE)
    close(debugfd);
#   endif
    pthread_mutex_destroy(&_lock);
}

// startswith/endswith, rewrite_path{,_rev} and the resolve_* family live in
// pathresolve.c so they can be unit-tested off-macOS (`make check`).

// Last-resort store shell for the /bin/sh redirect below: when PATH offers
// no non-protected sh/bash, fall back to any bash in the store (its bin/sh).
// npm/pnpm .bin/* shims are `#!/bin/sh` scripts that `exec node`, and are
// commonly run with a minimal PATH (e.g. a `nix run` wrapper exporting only
// nodejs/bin) - without this the redirect fails, the protected /bin/sh runs
// them, and /nix (hence node) is invisible. Scanned once and cached; returns
// a logical /nix path so normal injection applies, or NULL if none exists.
static char const *store_shell(void)
{
    static char cached[PATH_MAX];
    static int state;   // 0 = unknown, 1 = found, -1 = none
    if (state)
        return state == 1 ? cached : NULL;

    char storedir[PATH_MAX];
    snprintf(storedir, sizeof storedir, "%s/store", target);
    DIR *d = opendir(storedir);
    if (!d) { state = -1; return NULL; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, "-bash-"))
            continue;
        char probe[PATH_MAX];
        snprintf(probe, sizeof probe, "%s/%s/bin/sh", storedir, e->d_name);
        if (access(probe, X_OK) == 0) {
            snprintf(cached, sizeof cached, "%s/store/%s/bin/sh",
                     pattern, e->d_name);
            state = 1;
            closedir(d);
            return cached;
        }
    }
    closedir(d);
    state = -1;
    return NULL;
}

int my_posix_spawn(pid_t *pid, char const *path, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
    // /bin/sh is SIP-protected: exec'ing it strips DYLD_* and the child
    // loses the fakedir view of /nix. If PATH offers another sh/bash
    // (e.g. a store bash inside a nix build), prefer that.
    // (cherry-picked from ToxicPine/fakedir ef647a7)
    char shellbuf[PATH_MAX];
    if (!strcmp(path, "/bin/sh")) {
        char const *pathenv = getenv("PATH");
        if (pathenv && *pathenv) {
            char paths[ARG_MAX];
            strlcpy(paths, pathenv, sizeof paths);
            char *saveptr = NULL;
            for (char *dir = strtok_r(paths, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
                if (!*dir)
                    dir = ".";
                snprintf(shellbuf, sizeof shellbuf, "%s/sh", dir);
                if (strcmp(shellbuf, "/bin/sh") && !access(resolve_symlink(shellbuf), X_OK)) {
                    path = shellbuf;
                    break;
                }
                snprintf(shellbuf, sizeof shellbuf, "%s/bash", dir);
                if (strcmp(shellbuf, "/bin/bash") && !access(resolve_symlink(shellbuf), X_OK)) {
                    path = shellbuf;
                    break;
                }
            }
        }
        // PATH had no usable shell: fall back to a store bash rather than
        // exec the protected /bin/sh and lose the injection.
        if (!strcmp(path, "/bin/sh")) {
            char const *sh = store_shell();
            if (sh)
                path = sh;
        }
    }

    if (pid != PSP_EXEC)
        DEBUG("posix_spawn(%s) was called.", path);
    int tgt = my_open(path, O_RDONLY, 0000);
    char shebang[PATH_MAX];

    // Since we're overriding shebang behavior, we might allow non-executables
    // to be run with a shebang. To prevent that, we skip the shebang parser
    // in files without exec rights and let the real execve() return the error.
    int canexec = ! access(resolve_symlink(path), X_OK);
    read(tgt, shebang, PATH_MAX);
    close(tgt);

    if (canexec && !strncmp(shebang, "#!", 2)) {
        DEBUG("Executable '%s' has a shebang, parsing...", path);
        // Resolve only the parent: the kernel passes the *original* path as
        // the script argument ($0), and multi-call scripts dispatch on its
        // basename. Parent resolution still yields a path a non-injected
        // interpreter can open, without renaming the leaf.
        return pspawn_parse_shebang(pid, resolve_symlink_parent(-1, path), shebang, facts, attrp, argv, envp);
    }

    return pspawn_patch_envp(pid, resolve_symlink(path), facts, attrp, argv, envp);
}


// vim: ft=c.doxygen
