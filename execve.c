#include "common.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>

extern int my_open(char *name, int flags, int mode);
extern int my_posix_spawn(pid_t *pid, char const *path, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *av[], char *ep[]);

#   define dil_match "DYLD_INSERT_LIBRARIES="
#   define dil_size (strlen(dil_match) + (PATH_MAX * 40))
char dil_full[dil_size];

#   define dfp_match "DYLD_FALLBACK_LIBRARY_PATH="
#   define dfp_size (strlen(dfp_match) + (PATH_MAX * 40))
char dfp_full[dfp_size];

// Set during pspawn_patch_envp's closure walk; lets macho_add_dependencies
// report LC_RPATH entries without changing its signature for other callers.
void (*_rpath_collector)(char const *dir) = NULL;

static void add_dfp_entry(char const *dir)
{
    char entry[PATH_MAX + 2];
    entry[0] = ':';
    strlcpy(entry + 1, rewrite_path(dir), PATH_MAX + 1);
    size_t elen = strlen(entry);
    while (elen > 2 && entry[elen - 1] == '/')
        entry[--elen] = 0;

    char *hit = strstr(dfp_full, entry);
    if (hit && (hit[elen] == ':' || hit[elen] == '\0'))
        return;
    // first entry follows '=' directly, no ':' separator
    if (dfp_full[strlen(dfp_full) - 1] == '=')
        strlcat(dfp_full, entry + 1, dfp_size);
    else
        strlcat(dfp_full, entry, dfp_size);
}

void add_dil_rec(char const *lname)
{
    // resolve_symlink returns a shared static buffer which the recursive
    // call below clobbers, so keep a local copy (with ':' separator).
    char entry[PATH_MAX + 2];
    entry[0] = ':';
    strlcpy(entry + 1, resolve_symlink(lname), PATH_MAX + 1);

    // Dedup: nix dylibs form a dense dependency graph; without this the
    // recursion appends the same libraries combinatorially many times and
    // overflows dil_full.
    size_t elen = strlen(entry);
    char *hit = strstr(dil_full, entry);
    if (hit && (hit[elen] == ':' || hit[elen] == '\0'))
        return;

    strlcat(dil_full, entry, dil_size);

    // Also register the library's directory as a fallback dir: requests
    // whose name differs from the file's install name (e.g. renamed
    // references like libiconv.g.dylib) resolve by leaf name only.
    if (_rpath_collector) {
        char dir[PATH_MAX];
        strlcpy(dir, lname, PATH_MAX);
        char *ls = strrchr(dir, '/');
        if (ls && ls != dir) {
            *ls = 0;
            _rpath_collector(dir);
        }
    }

    macho_add_dependencies(lname, add_dil_rec);
}

void macho_add_dependencies(char const *path, void (*step)(char const *d))
{
    int fd = my_open(path, O_RDONLY, 0000);
    if (!fd) return;

    struct mach_header_64 hdr = {};
    struct load_command lcmd = {};

    read(fd, &hdr, sizeof hdr);
    if (hdr.magic != MH_MAGIC_64) {
        DEBUG("Not a Mach-O executable: %s", path);
        close(fd);
        return;
    }

    for (int i = 0; i < hdr.ncmds; i++) {
        read(fd, &lcmd, sizeof lcmd);
        if ( lcmd.cmd == LC_LOAD_DYLIB
          || lcmd.cmd == LC_LOAD_WEAK_DYLIB
          || lcmd.cmd == LC_REEXPORT_DYLIB) {
            char dld[lcmd.cmdsize - sizeof lcmd];
            read(fd, dld, sizeof dld);
            struct dylib *dl = dld;

            const char *lname = dld + dl->name.offset - sizeof lcmd;
            DEBUG("Found library '%s'", lname);
            if (startswith(pattern, lname) && ! endswith(lname, path)) {
                step(lname);
            }
        } else if (lcmd.cmd == LC_RPATH) {
            char dld[lcmd.cmdsize - sizeof lcmd];
            read(fd, dld, sizeof dld);
            // struct rpath_command's lc_str offset is relative to the
            // command start; dld begins after the 8-byte header
            uint32_t off = *(uint32_t *)dld;
            const char *rdir = dld + off - sizeof lcmd;
            DEBUG("Found rpath '%s'", rdir);
            if (_rpath_collector && startswith(pattern, rdir))
                _rpath_collector(rdir);
        } else {
            lseek(fd, lcmd.cmdsize - sizeof lcmd, SEEK_CUR);
        }
    }

    close(fd);

    // Apparently there's a library called libredirect in Nixpkgs which does a
    // very primitive version of our rewriting work, but our rewrite of
    // DYLD_INSERT_LIBRARIES might interfere.
    // AFAICT it is only used in an OpenSSH unit test, and its own tests.
}

int pspawn_patch_envp(pid_t *pid, char const *path, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
    DEBUG("Preparing envp for fakedir library loading");
    int envc = 0;
    int dil_idx = -1;   // DYLD_INSERT_LIBRARIES
    int fpa_idx = -1;   // FAKEDIR_PATTERN
    int fta_idx = -1;   // FAKEDIR_TARGET
    int dfp_idx = -1;   // DYLD_FALLBACK_LIBRARY_PATH


#   define fpa_match "FAKEDIR_PATTERN="
#   define fpa_size strlen(fpa_match) + strlen(pattern) + 1
#   define fta_match "FAKEDIR_TARGET="
#   define fta_size strlen(fta_match) + strlen(target) + 1

    char wpath[PATH_MAX];
    strlcpy(wpath, path, PATH_MAX);

    memset(dil_full, 0, dil_size);
    strncpy(dil_full, dil_match, strlen(dil_match));

    memset(dfp_full, 0, dfp_size);
    strncpy(dfp_full, dfp_match, strlen(dfp_match));

    char fpa_full[fpa_size];
    char fta_full[fta_size];
    memset(fpa_full, 0, fpa_size);
    memset(fta_full, 0, fta_size);
    strncpy(fpa_full, fpa_match, strlen(fpa_match));
    strncpy(fta_full, fta_match, strlen(fta_match));

    // Restore and prevent tampering with fakedir parameters
    strlcat(fpa_full, pattern, fpa_size);
    strlcat(fta_full, target, fta_size);

    for (; envp[envc]; envc++)
        ;
    char *new_envp[envc + 5];
    for (int i = 0; i < envc; i++) {
        if (startswith(dil_match, envp[i]))
            dil_idx = i;
        else if (startswith(fpa_match, envp[i]))
            fpa_idx = i;
        else if (startswith(fta_match, envp[i]))
            fta_idx = i;
        else if (startswith(dfp_match, envp[i]))
            dfp_idx = i;
        new_envp[i] = envp[i];
    }

    // Keep ourselves in DYLD_INSERT_LIBRARIES no matter what
    strlcat(dil_full, ownpath, dil_size);
    // Collect LC_RPATH dirs across the closure so @rpath dependencies
    // resolve by leaf name through DYLD_FALLBACK_LIBRARY_PATH
    _rpath_collector = add_dfp_entry;
    macho_add_dependencies(path, add_dil_rec);
    _rpath_collector = NULL;

    // Preserve any fallback dirs the parent had, then restore dyld's
    // defaults (setting the variable overrides them)
    if (dfp_idx != -1 && envp[dfp_idx][strlen(dfp_match)]) {
        if (dfp_full[strlen(dfp_full) - 1] != '=')
            strlcat(dfp_full, ":", dfp_size);
        strlcat(dfp_full, envp[dfp_idx] + strlen(dfp_match), dfp_size);
    }
    if (dfp_full[strlen(dfp_full) - 1] != '=')
        strlcat(dfp_full, ":", dfp_size);
    strlcat(dfp_full, "/usr/local/lib:/usr/lib", dfp_size);

    DEBUG("Running with %s", dil_full);
    DEBUG("Running with %s", dfp_full);

    new_envp[dil_idx == -1 ? envc++ : dil_idx] = dil_full;
    new_envp[fpa_idx == -1 ? envc++ : fpa_idx] = fpa_full;
    new_envp[fta_idx == -1 ? envc++ : fta_idx] = fta_full;
    new_envp[dfp_idx == -1 ? envc++ : dfp_idx] = dfp_full;
    new_envp[envc] = 0;

    pthread_mutex_unlock(&_lock);
    if (pid == PSP_EXEC)
        return execve(wpath, argv, new_envp);
    else
        return posix_spawn(pid, wpath, facts, attrp, argv, new_envp);
}

int pspawn_parse_shebang(pid_t *pid, char const *spath, char const *shebang, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
    char my_path[PATH_MAX]; // This will be the path to our interpreter
    char my_args[PATH_MAX]; // This will be the following argument (if any)
                            // UNIX shebangs only permit a single argument
                            // before the actual file, which makes our job
                            // way easier.
    char my_spath[PATH_MAX];// Local copy of our script path
    strlcpy(my_spath, spath, PATH_MAX);

    int path_start = 2;
    int path_len = 0;       // Start and length of interpreter path
    int args_start = 0;
    int args_len = 0;       // Start and length of interpreter argument
    int our_argc = 0;       // Number of arguments in original argv

    // Strip leading spaces between shebang and interpreter
    for (; path_start < PATH_MAX; path_start++)
        if (shebang[path_start] != ' ')
            break;
    // Determine interpreter length at first space or newline
    for (; path_len < PATH_MAX; path_len++)
        if (shebang[path_start + path_len] == ' '
          || shebang[path_start + path_len] == '\n')
            break;

    // Determine start of argument at first non-space after interpreter
    for (args_start = path_start + path_len; args_start < PATH_MAX; args_start++)
        if (shebang[args_start] != ' ')
            break;

    // Set argument length to the end of the shebang line...
    for (; args_len < PATH_MAX; args_len++)
        if (shebang[args_start + args_len] == '\n')
            break;

    // then backtrack to strip trailing spaces from it.
    for (; args_len > 0; args_len--)
        if (shebang[args_start + args_len - 1] != ' ')
            break;

    // Finally, count arguments in original argv...
    for (; our_argc < ARG_MAX; our_argc++)
        if (argv[our_argc] == NULL)
            break;

    // ... so that we can stack-allocate our new one.
    char *new_argv[our_argc + 3];

    // Populate path and arg strings then formulate execve()
    strncpy(my_path, shebang + path_start, path_len);
    my_path[path_len] = 0;
    strncpy(my_args, shebang + args_start, args_len);
    my_args[args_len] = 0;

    DEBUG("Parsed interpreter '%s' with argument '%s'", my_path, my_args);
    new_argv[0] = my_path;
    if (args_len) {
        // With an argument
        new_argv[1] = my_args;
        for (int i = 0; argv[i]; i++)
            new_argv[i + 2] = argv[i];
        new_argv[2] = my_spath;
        new_argv[our_argc + 2] = 0;
    } else {
        // Without argument
        for (int i = 0; argv[i]; i++)
            new_argv[i + 1] = argv[i];
        new_argv[1] = my_spath;
        new_argv[our_argc + 1] = 0;
    }

    // Fun fact: shebangs are recursive! Scripts can be interpreters too!
    return my_posix_spawn(pid, my_path, facts, attrp, new_argv, envp);
}
