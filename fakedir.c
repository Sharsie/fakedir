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

static char pathbuf[PATH_MAX];
static char rpathbuf[PATH_MAX];
static char linkbuf[PATH_MAX];
static char dedupbuf[PATH_MAX];
pthread_mutex_t _lock;

const char *pattern;
const char *target;

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

    strlcpy(pathbuf, target, PATH_MAX);
    strlcpy(rpathbuf, pattern, PATH_MAX);

    pthread_mutex_init(&_lock, NULL);
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

bool startswith(char const *pattern, char const *msg)
{
    if (strlen(pattern) > strlen(msg))
        return false;
    return ! strncmp(msg, pattern, strlen(pattern));
}

bool endswith(char const *pattern, char const *msg)
{
    if (strlen(pattern) > strlen(msg))
        return false;
    return ! strncmp(msg + strlen(msg) - strlen(pattern), pattern, strlen(pattern));
}

char const *rewrite_path(char const *path)
{
    if (startswith("/.", path))
        path += 2;
    if (pattern && startswith(pattern, path)) {
        size_t target_len = strlen(target);
        strlcpy(pathbuf + target_len, path + strlen(pattern), PATH_MAX - target_len);
        return pathbuf;
    } else {
        if (path != dedupbuf)
            strlcpy(dedupbuf, path, PATH_MAX);
        return dedupbuf;
    }
}

char const *rewrite_path_rev(char const *path)
{
    if (startswith("/.", path))
        path += 2;
    if (target && startswith(target, path)) {
        size_t pattern_len = strlen(pattern);
        strlcpy(rpathbuf + pattern_len, path + strlen(target), PATH_MAX - pattern_len);
        return rpathbuf;
    } else {
        if (path != dedupbuf)
            strlcpy(dedupbuf, path, PATH_MAX);
        return dedupbuf;
    }
}

/*
 * Component-by-component path resolution (like realpath), applying the
 * pattern=>target rewrite before every kernel probe. This is required
 * because symlink *targets* routinely point back into the pattern dir
 * (e.g. a nix profile chain: ~/.nix-profile -> .../profile-2-link ->
 * /nix/store/...-user-environment, whose entries are again symlinks to
 * /nix/store/...). Every intermediate component must therefore be
 * readlink'd through the rewrite, not just prefixes of the original path.
 *
 * `out` accumulates the resolved path in *logical* (un-rewritten) space;
 * rewriting happens only for kernel probes and the final result.
 */
static char resbufs[2][PATH_MAX];
static int resbuf_idx = 0;

static char const *resolve_path_common(int fd, char const *path, bool keep_last)
{
    char rest[PATH_MAX];    // unprocessed components, '/'-separated
    char out[PATH_MAX];     // logical resolved-so-far
    char comp[PATH_MAX];
    char lbuf[PATH_MAX];
    char probe[PATH_MAX];
    char tmp[PATH_MAX];
    int nlinks = 0;
    char *res = resbufs[resbuf_idx];
    resbuf_idx = (resbuf_idx + 1) % 2;

    if (!path || !path[0]) {
        // preserve syscall semantics for the empty path (ENOENT)
        strlcpy(res, path ? path : "", PATH_MAX);
        return res;
    }

    bool is_abs = (path[0] == '/');
    if (fd == AT_FDCWD)
        fd = -1;

    strlcpy(rest, is_abs ? path + 1 : path, PATH_MAX);
    out[0] = 0;

    while (rest[0]) {
        char *slash = strchr(rest, '/');
        if (slash) {
            size_t clen = slash - rest;
            memcpy(comp, rest, clen);
            comp[clen] = 0;
            memmove(rest, slash + 1, strlen(slash + 1) + 1);
        } else {
            strlcpy(comp, rest, PATH_MAX);
            rest[0] = 0;
        }
        if (!comp[0] || !strcmp(comp, "."))
            continue;
        if (!strcmp(comp, "..")) {
            char *ls = strrchr(out, '/');
            if (ls)
                *ls = 0;
            else
                out[0] = 0;
            continue;
        }
        strlcpy(probe, out, PATH_MAX);
        if (is_abs || out[0])
            strlcat(probe, "/", PATH_MAX);
        strlcat(probe, comp, PATH_MAX);

        if (keep_last && !rest[0]) {
            // final component belongs to the caller (create/readlink/etc.)
            strlcpy(out, probe, PATH_MAX);
            break;
        }

        ssize_t ll = readlinkat(fd == -1 ? AT_FDCWD : fd,
                                rewrite_path(probe), lbuf, PATH_MAX - 1);
        if (ll < 0 || ++nlinks > 40) {
            // not a symlink (or ELOOP guard): keep component as-is
            strlcpy(out, probe, PATH_MAX);
            continue;
        }
        lbuf[ll] = 0;
        if (lbuf[0] == '/') {
            out[0] = 0;
            is_abs = true;
            strlcpy(tmp, lbuf + 1, PATH_MAX);
        } else {
            strlcpy(tmp, lbuf, PATH_MAX);
        }
        if (rest[0]) {
            strlcat(tmp, "/", PATH_MAX);
            strlcat(tmp, rest, PATH_MAX);
        }
        strlcpy(rest, tmp, PATH_MAX);
    }

    if (!out[0])
        strlcpy(out, is_abs ? "/" : ".", PATH_MAX);
    strlcpy(res, rewrite_path(out), PATH_MAX);
    DEBUG("resolve%s('%s') = '%s'", keep_last ? "_parent" : "", path, res);
    return res;
}

char const *resolve_symlink_parent(int fd, char const *path)
{
    return resolve_path_common(fd, path, true);
}

char const *resolve_symlink_at(int fd, char const *path)
{
    return resolve_path_common(fd, path, false);
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
