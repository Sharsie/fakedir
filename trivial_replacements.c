#include "common.h"
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

/**
 * @file        trivial_replacements.c
 * @author      Karim Vergnes <me@thesola.io>
 * @copyright   GPLv2
 * @brief       Set of trivial rewrites for system calls using paths.
 *
 * The following replacements are numerous and pretty much follow the same
 * pattern, so they have been grouped here for easier reading.
 */

int my_posix_spawn(pid_t *pid, char const *path, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[]);
void macho_add_dependencies(char const *path, void (*e)(char const *));
extern char **environ;

// PATH-searching front end for the p-variants of the exec family
// (cherry-picked from ToxicPine/fakedir ef647a7)
static int spawnp_resolved(pid_t *pid, char const *file, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
    if (strchr(file, '/'))
        return my_posix_spawn(pid, file, facts, attrp, argv, envp);

    char const *pathenv = getenv("PATH");
    if (!pathenv || !*pathenv)
        pathenv = "/bin:/usr/bin";

    char paths[ARG_MAX];
    strlcpy(paths, pathenv, sizeof paths);

    char *saveptr = NULL;
    for (char *dir = strtok_r(paths, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
        char candidate[PATH_MAX];
        if (!*dir)
            dir = ".";
        snprintf(candidate, sizeof candidate, "%s/%s", dir, file);
        if (!access(resolve_symlink(candidate), X_OK))
            return my_posix_spawn(pid, candidate, facts, attrp, argv, envp);
    }

    errno = ENOENT;
    return -1;
}

#define SUBST(T, n, p)  \
    T _my_##n p;                                         \
    __attribute__((used, section("__DATA,__interpose"))) \
        static void *_##n[] = { _my_##n , n };           \
    T _my_##n p {                                        \
        pthread_mutex_lock(&_lock);                      \
        DEBUG("Now serving %s", #n );                    \
        T _r = ({

#define ENDSUBST \
        });                                          \
        pthread_mutex_unlock(&_lock);                \
        return _r;                                   \
    }

#define RS_PARENT(p) resolve_symlink_parent(-1, p)

static char const *rs_at_flagged(int fd, char const *path, int flags)
{
    // AT_FDCWD is a special fd value (-2), not a bit in `flags`;
    // resolve_* helpers expect -1 for "relative to cwd"
    if (fd == AT_FDCWD)
        fd = -1;
    if (flags & AT_SYMLINK_NOFOLLOW)
        return resolve_symlink_parent(fd, path);
    else
        return resolve_symlink_at(fd, path);
}

void *my_dlopen(char const *path, int mode);

// Transitive dependency closure of a dlopen'd /nix library, collected so
// each dependency can be force-loaded (resolving @rpath/renamed refs the
// same way the spawn-time DYLD_INSERT_LIBRARIES closure does).
//
// The collection walks Mach-O load commands through macho_add_dependencies
// -> my_open, which requires _lock held (it only drops the lock across the
// blocking real open, then re-locks). But a real dlopen must NEVER run
// under _lock: dlopen executes the image's initializers, which re-enter
// this interposer -- nix's libtbb initializer dlopens tbbmalloc, whose
// initializer dlopens again, and holding _lock across the outer dlopen
// self-deadlocked the inner one. So we gather the resolved closure under
// the lock, release it, then dlopen every entry outside the lock.
#define DLCLOSURE_MAX 256
static char dlclosure[DLCLOSURE_MAX][PATH_MAX];
static int dlclosure_n;

static void dlclosure_collect(char const *lname)
{
    char realp[PATH_MAX];
    strlcpy(realp, resolve_symlink(lname), sizeof realp);
    // Dedup (nix's dylib graph is dense) and record BEFORE recursing, so a
    // dependency cycle terminates instead of recursing forever.
    for (int i = 0; i < dlclosure_n; i++)
        if (!strcmp(dlclosure[i], realp))
            return;
    if (dlclosure_n >= DLCLOSURE_MAX)
        return;
    strlcpy(dlclosure[dlclosure_n++], realp, PATH_MAX);
    macho_add_dependencies(realp, dlclosure_collect);
}

void *my_dlopen(char const *path, int mode)
{
    DEBUG("dlopen(%s) was called.", path);
    if (!path)
        return dlopen(path, mode);

    char realp[PATH_MAX];
    pthread_mutex_lock(&_lock);
    strlcpy(realp, resolve_symlink(path), sizeof realp);
    dlclosure_n = 0;
    macho_add_dependencies(realp, dlclosure_collect);
    // Copy the closure out while still locked (dlclosure is shared state),
    // so we can dlopen without the lock held.
    int n = dlclosure_n;
    char (*deps)[PATH_MAX] = n ? malloc((size_t)n * PATH_MAX) : NULL;
    if (deps)
        memcpy(deps, dlclosure, (size_t)n * PATH_MAX);
    else
        n = 0;
    pthread_mutex_unlock(&_lock);

    for (int i = 0; i < n; i++)
        dlopen(deps[i], RTLD_GLOBAL|RTLD_NOW);
    free(deps);
    return dlopen(realp, mode);
}

int my_open(char const *name, int flags, int mode)
{
    // Called with _lock held. Opening a fifo blocks until the peer opens
    // the other end - and the peer's own open can never resolve while we
    // sit on the global lock (node's http2 fifo tests deadlocked exactly
    // this way, reader and writer in one process). Resolve under the lock,
    // then release it across the real call.
    char const *n;
    char realp[PATH_MAX];
    if (flags & (O_SYMLINK|O_NOFOLLOW))
        n = RS_PARENT(name);
    else
        n = resolve_symlink(name);
    if (strlcpy(realp, n, sizeof realp) >= sizeof realp) {
        errno = ENAMETOOLONG;
        return -1;
    }
    pthread_mutex_unlock(&_lock);
    int fd = open(realp, flags, mode);
    pthread_mutex_lock(&_lock);
    return fd;
}

SUBST(int, execve, (char const *path, char *argv[], char *envp[]))
    my_posix_spawn(PSP_EXEC, path, NULL, NULL, argv, envp);
ENDSUBST

SUBST(int, execv, (char const *path, char *argv[]))
    my_posix_spawn(PSP_EXEC, path, NULL, NULL, argv, environ);
ENDSUBST

SUBST(int, execvp, (char const *path, char *argv[]))
    spawnp_resolved(PSP_EXEC, path, NULL, NULL, argv, environ);
ENDSUBST

SUBST(int, posix_spawn, (pid_t *pid, char const *path, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[]))
    my_posix_spawn(pid, path, facts, attrp, argv, envp);
ENDSUBST

SUBST(int, posix_spawnp, (pid_t *pid, char const *file, const posix_spawn_file_actions_t *facts, const posix_spawnattr_t *attrp, char *argv[], char *envp[]))
    spawnp_resolved(pid, file, facts, attrp, argv, envp);
ENDSUBST

// Paths stored inside posix_spawn file actions are consumed by the kernel
// at spawn time, after my_posix_spawn has run, so they must be rewritten
// when they are *added*. libuv implements spawn-with-cwd this way
// (posix_spawn_file_actions_addchdir_np), which is how every Node.js
// child_process call with a `cwd` option spawns - unrewritten, the chdir
// hit the real, nonexistent /nix and the spawn died with ENOENT.
SUBST(int, posix_spawn_file_actions_addchdir_np,
        (posix_spawn_file_actions_t *facts, char const *path))
    posix_spawn_file_actions_addchdir_np(facts, resolve_symlink(path));
ENDSUBST

SUBST(int, posix_spawn_file_actions_addopen,
        (posix_spawn_file_actions_t *facts, int fd, char const *path, int oflag, mode_t mode))
    posix_spawn_file_actions_addopen(facts, fd,
            (oflag & (O_SYMLINK|O_NOFOLLOW)) ? RS_PARENT(path)
                                             : resolve_symlink(path),
            oflag, mode);
ENDSUBST

// dlopen is not wrapped with SUBST: my_dlopen manages _lock itself (it
// must drop the lock before the real dlopen, whose initializers re-enter
// us), so the interposer must take no lock of its own.
void *_my_dlopen(char const *path, int mode);
__attribute__((used, section("__DATA,__interpose")))
    static void *_dlopen[] = { _my_dlopen, dlopen };
void *_my_dlopen(char const *path, int mode)
{
    return my_dlopen(path, mode);
}

// open() and openat() take `mode` as a *variadic* argument. On arm64 the
// Apple ABI passes variadic args on the stack but named args in registers,
// so declaring mode as a named parameter reads garbage. These two must be
// interposed with genuinely variadic signatures.
int _my_openat(int fd, char const *name, int flags, ...);
__attribute__((used, section("__DATA,__interpose")))
    static void *_openat[] = { _my_openat, openat };
int _my_openat(int fd, char const *name, int flags, ...)
{
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    pthread_mutex_lock(&_lock);
    DEBUG("Now serving %s", "openat");
    // `flags` here are O_* flags, not AT_* flags
    char const *n;
    char realp[PATH_MAX];
    int rfd = (fd == AT_FDCWD) ? -1 : fd;
    if (flags & (O_SYMLINK|O_NOFOLLOW))
        n = resolve_symlink_parent(rfd, name);
    else
        n = resolve_symlink_at(rfd, name);
    int _r;
    if (strlcpy(realp, n, sizeof realp) >= sizeof realp) {
        errno = ENAMETOOLONG;
        _r = -1;
    } else {
        // fifo opens block until the peer arrives; see my_open
        pthread_mutex_unlock(&_lock);
        _r = openat(fd, realp, flags, mode);
        pthread_mutex_lock(&_lock);
    }
    pthread_mutex_unlock(&_lock);
    return _r;
}

// Marks the shim symlinks planted by the AF_UNIX bind fallback further
// down; lstat reports them as the socket they lead to so callers cannot
// tell the shim from a socket bound in place.
#define SOCKSHIM_PREFIX "/tmp/.fakedir-sock-"

static void sockshim_untangle(char const *realp, struct stat *buf)
{
    if (!S_ISLNK(buf->st_mode))
        return;
    char tgt[PATH_MAX];
    ssize_t n = readlink(realp, tgt, sizeof tgt - 1);
    if (n <= 0)
        return;
    tgt[n] = 0;
    if (startswith(SOCKSHIM_PREFIX, tgt))
        lstat(tgt, buf);
}

SUBST(int, lstat, (char const *path, struct stat *buf))
    char const *rp = RS_PARENT(path);
    int _r = lstat(rp, buf);
    if (_r == 0)
        sockshim_untangle(rp, buf);
    _r;
ENDSUBST

SUBST(int, stat, (char const *path, struct stat *buf))
    stat(resolve_symlink(path), buf);
ENDSUBST

SUBST(int, fstatat, (int fd, char const *path, struct stat *buf, int flag))
    fstatat(fd, rs_at_flagged(fd, path, flag), buf, flag);
ENDSUBST

SUBST(int, access, (char const *path, int mode))
    access(resolve_symlink(path), mode);
ENDSUBST

SUBST(int, faccessat, (int fd, char const *path, int mode, int flag))
    faccessat(fd, rs_at_flagged(fd, path, flag), mode, flag);
ENDSUBST

SUBST(int, chflags, (char const *path, int flags))
    chflags(RS_PARENT(path), flags);
ENDSUBST

SUBST(int, mkfifo, (char const *path, mode_t mode))
    mkfifo(RS_PARENT(path), mode);
ENDSUBST

SUBST(int, chmod, (char const *path, mode_t mode))
    chmod(resolve_symlink(path), mode);
ENDSUBST

SUBST(int, fchmodat, (int fd, char const *path, mode_t mode, int flag))
    fchmodat(fd, rs_at_flagged(fd, path, flag), mode, flag);
ENDSUBST

SUBST(int, chown, (char const *path, uid_t owner, gid_t group))
    chown(resolve_symlink(path), owner, group);
ENDSUBST

SUBST(int, lchown, (char const *path, uid_t owner, gid_t group))
    lchown(RS_PARENT(path), owner, group);
ENDSUBST

SUBST(int, fchownat, (int fd, char const *path, uid_t owner, gid_t group, int flag))
    fchownat(fd, rs_at_flagged(fd, path, flag), owner, group, flag);
ENDSUBST

SUBST(int, link, (char const *path1, char const *path2))
    char newp1[PATH_MAX];
    strlcpy(newp1, RS_PARENT(path1), PATH_MAX);
    link(newp1, RS_PARENT(path2));
ENDSUBST

SUBST(int, linkat, 
        (int fd1, char const *path1, int fd2, char const *path2, int flag))
    const char *newp1 = (flag & AT_SYMLINK_FOLLOW) ? resolve_symlink_at(fd1, path1)
                                                   : resolve_symlink_parent(fd1, path1);
    linkat(fd1, newp1, fd2, resolve_symlink_parent(fd2, path2), flag);
ENDSUBST

SUBST(int, unlink, (char const *path))
    unlink(RS_PARENT(path));
ENDSUBST

SUBST(int, unlinkat, (int fd, char const *path, int flag))
    unlinkat(fd, resolve_symlink_parent(fd, path), flag);
ENDSUBST

SUBST(int, symlink, (char const *what, char const *path))
    symlink(what, RS_PARENT(path));
ENDSUBST

SUBST(int, symlinkat, (char const *what, int fd, char const *path))
    // never resolve the final component: we are creating it
    symlinkat(what, fd, rs_at_flagged(fd, path, AT_SYMLINK_NOFOLLOW));
ENDSUBST

SUBST(ssize_t, readlink, (char const *path, char *buf, size_t bsz))
    readlink(RS_PARENT(path), buf, bsz);
ENDSUBST

SUBST(ssize_t, readlinkat, (int fd, char const *path, char *buf, size_t bsz))
    // never resolve the final component: we are reading the link itself
    readlinkat(fd, rs_at_flagged(fd, path, AT_SYMLINK_NOFOLLOW), buf, bsz);
ENDSUBST

// fopen on a fifo blocks like open does; same unlock discipline (my_open)
SUBST(FILE *, fopen, (char const *path, char const *mode))
    char realp[PATH_MAX];
    FILE *f = NULL;
    if (strlcpy(realp, resolve_symlink(path), sizeof realp) >= sizeof realp) {
        errno = ENAMETOOLONG;
    } else {
        pthread_mutex_unlock(&_lock);
        f = fopen(realp, mode);
        pthread_mutex_lock(&_lock);
    }
    f;
ENDSUBST

SUBST(FILE *, freopen, (char const *path, char const *mode, FILE *orig))
    char realp[PATH_MAX];
    FILE *f = NULL;
    if (strlcpy(realp, resolve_symlink(path), sizeof realp) >= sizeof realp) {
        errno = ENAMETOOLONG;
    } else {
        pthread_mutex_unlock(&_lock);
        f = freopen(realp, mode, orig);
        pthread_mutex_lock(&_lock);
    }
    f;
ENDSUBST

// libc exports $DARWIN_EXTSN variants of some path-taking functions, and
// anything compiled with _DARWIN_C_SOURCE (e.g. all of nixpkgs) binds those
// symbols instead of the plain ones, sailing straight past the interposers
// above (CPython's `python script.py` failed on any /nix script this way
// while builtin open() worked). `$` cannot appear in a C identifier, so the
// real symbols are declared through __asm aliases and the interpose tuples
// are hand-rolled.
FILE *fopen_extsn(char const *path, char const *mode)
    __asm("_fopen$DARWIN_EXTSN");
char *realpath_extsn(char const *path, char *resolved)
    __asm("_realpath$DARWIN_EXTSN");

FILE *_my_fopen_extsn(char const *path, char const *mode);
__attribute__((used, section("__DATA,__interpose")))
    static void *_fopen_extsn[] = { _my_fopen_extsn, fopen_extsn };
FILE *_my_fopen_extsn(char const *path, char const *mode)
{
    pthread_mutex_lock(&_lock);
    DEBUG("Now serving %s", "fopen$DARWIN_EXTSN");
    char realp[PATH_MAX];
    FILE *_r = NULL;
    if (strlcpy(realp, resolve_symlink(path), sizeof realp) >= sizeof realp) {
        errno = ENAMETOOLONG;
    } else {
        // fifo opens block until the peer arrives; see my_open
        pthread_mutex_unlock(&_lock);
        _r = fopen_extsn(realp, mode);
        pthread_mutex_lock(&_lock);
    }
    pthread_mutex_unlock(&_lock);
    return _r;
}

// Both realpath variants share one body: rewrite the input to its real
// location, let the real realpath canonicalize it, then map the result back
// into the fake tree so callers keep seeing logical /nix paths (getcwd
// makes the same real->logical translation). The real realpath re-enters
// our stat/readlink/getattrlist interposers, so the lock must not be held
// across the call.
static char *realpath_common(char const *path, char *resolved,
                             char *(*real_fn)(char const *, char *),
                             char const *name)
{
    if (path == NULL)
        return real_fn(path, resolved);

    char realin[PATH_MAX];
    char realout[PATH_MAX];
    pthread_mutex_lock(&_lock);
    DEBUG("Now serving %s", name);
    size_t inlen = strlcpy(realin, resolve_symlink(path), sizeof realin);
    pthread_mutex_unlock(&_lock);
    if (inlen >= sizeof realin) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    if (real_fn(realin, realout) == NULL)
        return NULL;

    pthread_mutex_lock(&_lock);
    char const *logical = rewrite_path_rev(realout);
    // realpath contract: resolved == NULL means "malloc the result"
    // (mirrors the strdup already done by the getcwd interposer)
    char *_r = resolved ? strlcpy(resolved, logical, PATH_MAX), resolved
                        : strdup(logical);
    pthread_mutex_unlock(&_lock);
    return _r;
}

char *_my_realpath(char const *path, char *resolved);
__attribute__((used, section("__DATA,__interpose")))
    static void *_realpath[] = { _my_realpath, realpath };
char *_my_realpath(char const *path, char *resolved)
{
    return realpath_common(path, resolved, realpath, "realpath");
}

char *_my_realpath_extsn(char const *path, char *resolved);
__attribute__((used, section("__DATA,__interpose")))
    static void *_realpath_extsn[] = { _my_realpath_extsn, realpath_extsn };
char *_my_realpath_extsn(char const *path, char *resolved)
{
    return realpath_common(path, resolved, realpath_extsn,
                           "realpath$DARWIN_EXTSN");
}

// AF_UNIX socket paths travel inside struct sockaddr_un, which none of the
// path interposers above ever see (nix's gc-socket under /nix/var/nix
// failed to bind this way). Hand-rolled rather than SUBST: the real bind()
// and especially connect() can block, and SUBST would hold the global
// mutex across the real call, stalling every interposed syscall in the
// process. Anything that isn't an AF_UNIX address under FAKEDIR_PATTERN
// passes straight through without touching the lock.
static int sockcall_resolved(int fd, const struct sockaddr *addr,
                             socklen_t len,
                             int (*real_fn)(int, const struct sockaddr *,
                                            socklen_t),
                             bool resolve_parent_only, char const *name)
{
    if (addr == NULL || addr->sa_family != AF_UNIX
            || len <= offsetof(struct sockaddr_un, sun_path))
        return real_fn(fd, addr, len);

    // sun_path need not be NUL-terminated within len; bound and terminate
    char inpath[sizeof ((struct sockaddr_un *)0)->sun_path + 1];
    size_t inlen = len - offsetof(struct sockaddr_un, sun_path);
    if (inlen > sizeof inpath - 1)
        inlen = sizeof inpath - 1;
    memcpy(inpath, ((const struct sockaddr_un *)addr)->sun_path, inlen);
    inpath[inlen] = '\0';

    if (!startswith(pattern, inpath))
        return real_fn(fd, addr, len);

    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    char realp[PATH_MAX];
    pthread_mutex_lock(&_lock);
    DEBUG("Now serving %s", name);
    size_t outlen = strlcpy(realp,
            resolve_parent_only ? resolve_symlink_parent(-1, inpath)
                                : resolve_symlink(inpath),
            sizeof realp);
    pthread_mutex_unlock(&_lock);
    if (outlen >= sizeof realp) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (outlen >= sizeof sun.sun_path) {
        // The real prefix often pushes a logical path that would be a legal
        // sun_path (104 bytes) over the limit - a rooted install would have
        // bound it fine. For bind, place the socket at a short /tmp name
        // and plant a symlink at the requested location; connect resolves
        // through that symlink (resolve_symlink above already followed it,
        // so reaching this point on connect means no such shim exists).
        if (!resolve_parent_only) {
            // connect: the target is not one of our bound sockets (those
            // resolve through their planted shim to a short /tmp path and
            // never reach here). A rooted install would have connect()ed
            // the short logical path and let the kernel report the true
            // error - ENOTSOCK for a regular file, ENOENT for a missing
            // one, ECONNREFUSED for an unlistened socket. Reach realp
            // through a short, temporary /tmp symlink so the kernel still
            // follows it to that verdict instead of us short-circuiting
            // with ENAMETOOLONG.
            static int cshimctr;
            pthread_mutex_lock(&_lock);
            int ctr = cshimctr++;
            pthread_mutex_unlock(&_lock);
            char tmplink[sizeof sun.sun_path];
            snprintf(tmplink, sizeof tmplink, SOCKSHIM_PREFIX "c%d-%d",
                     getpid(), ctr);
            unlink(tmplink);
            if (symlink(realp, tmplink) != 0) {
                errno = ENAMETOOLONG;
                return -1;
            }
            strlcpy(sun.sun_path, tmplink, sizeof sun.sun_path);
            sun.sun_len = SUN_LEN(&sun);
            int r = real_fn(fd, (const struct sockaddr *)&sun,
                            SUN_LEN(&sun) + 1);
            int saved = errno;
            unlink(tmplink);
            errno = saved;
            return r;
        }
        struct stat st;
        if (lstat(realp, &st) == 0) {
            errno = EADDRINUSE;
            return -1;
        }
        static int shimctr;
        pthread_mutex_lock(&_lock);
        int ctr = shimctr++;
        pthread_mutex_unlock(&_lock);
        snprintf(sun.sun_path, sizeof sun.sun_path, SOCKSHIM_PREFIX "%d-%d",
                 getpid(), ctr);
        sun.sun_len = SUN_LEN(&sun);
        int r = real_fn(fd, (const struct sockaddr *)&sun, SUN_LEN(&sun) + 1);
        if (r == 0 && symlink(sun.sun_path, realp) != 0) {
            int saved = errno;
            unlink(sun.sun_path);
            errno = saved;
            return -1;
        }
        // the shim socket in /tmp outlives an unlink of the symlink; small,
        // uniquely named, and cleaned with /tmp
        return r;
    }

    memcpy(sun.sun_path, realp, outlen + 1);
    sun.sun_len = SUN_LEN(&sun);
    return real_fn(fd, (const struct sockaddr *)&sun, SUN_LEN(&sun) + 1);
}

// dladdr reports image paths as dyld loaded them - real store locations.
// Callers compare those against logical paths (node asserts its backtrace
// frames contain process.execPath, which realpath gave back in logical
// form), so dli_fname is reverse-mapped. The struct field must outlive the
// call: rewritten names are interned in a small permanent table (a process
// maps few distinct images; on overflow the real name passes through).
static char const *dladdr_intern(char const *logical)
{
    static char *interned[64];
    static int ninterned;
    for (int i = 0; i < ninterned; i++)
        if (!strcmp(interned[i], logical))
            return interned[i];
    if (ninterned >= 64)
        return NULL;
    char *dup = strdup(logical);
    if (dup)
        interned[ninterned++] = dup;
    return dup;
}

int _my_dladdr(const void *addr, Dl_info *info);
__attribute__((used, section("__DATA,__interpose")))
    static void *_dladdr[] = { _my_dladdr, dladdr };
int _my_dladdr(const void *addr, Dl_info *info)
{
    int r = dladdr(addr, info);
    if (r && info->dli_fname) {
        // dladdr is the one interposer that runs UNDER the dyld lock
        // (image initializers inside dlopen call it), while any thread
        // holding our lock may block on the dyld lock through a lazy
        // symbol bind - taking _lock here unconditionally deadlocked a
        // 10-hour build (ABBA). The rewrite is cosmetic: when the lock is
        // contended, return the real path rather than gamble.
        if (pthread_mutex_trylock(&_lock) == 0) {
            char const *logical = rewrite_path_rev(info->dli_fname);
            if (strcmp(logical, info->dli_fname)) {
                char const *stable = dladdr_intern(logical);
                if (stable)
                    info->dli_fname = stable;
            }
            pthread_mutex_unlock(&_lock);
        }
    }
    return r;
}

int _my_bind(int fd, const struct sockaddr *addr, socklen_t len);
__attribute__((used, section("__DATA,__interpose")))
    static void *_bind[] = { _my_bind, bind };
int _my_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    // parent-only resolve: the socket file itself is being created
    return sockcall_resolved(fd, addr, len, bind, true, "bind");
}

int _my_connect(int fd, const struct sockaddr *addr, socklen_t len);
__attribute__((used, section("__DATA,__interpose")))
    static void *_connect[] = { _my_connect, connect };
int _my_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    return sockcall_resolved(fd, addr, len, connect, false, "connect");
}

int _my_open2(char const *name, int flags, ...);
__attribute__((used, section("__DATA,__interpose")))
    static void *_open[] = { _my_open2, open };
int _my_open2(char const *name, int flags, ...)
{
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    pthread_mutex_lock(&_lock);
    DEBUG("Now serving %s", "open");
    int _r = my_open(name, flags, mode);
    pthread_mutex_unlock(&_lock);
    return _r;
}

SUBST(int, clonefile, (char const *path1, char const *path2, int flags))
    clonefile( (flags & CLONE_NOFOLLOW) ? RS_PARENT(path1)
                                        : resolve_symlink(path1)
             , RS_PARENT(path2), flags);
ENDSUBST

SUBST(int, clonefileat, 
        (int fd1, char const *path1, int fd2, char const *path2, int flags))
    clonefileat( fd1
               , (flags & CLONE_NOFOLLOW) ? resolve_symlink_parent(fd1, path1)
                                          : resolve_symlink_at(fd1, path1)
                , fd2
                , resolve_symlink_parent(fd2, path2)
                , flags);
ENDSUBST

SUBST(int, fclonefileat, (int src, int fd, char const *path, int flags))
    fclonefileat(src, fd, resolve_symlink_parent(fd, path), flags);
ENDSUBST

SUBST(int, exchangedata, (char const *path1, char const *path2, int options))
    exchangedata((options & FSOPT_NOFOLLOW) ? RS_PARENT(path1)
                                            : resolve_symlink(path1)
                , RS_PARENT(path2)
                , options);
ENDSUBST

SUBST(int, truncate, (char const *path, off_t length))
    truncate(resolve_symlink(path), length);
ENDSUBST

SUBST(int, utimes, (char const *path, struct timeval times[2]))
    utimes(resolve_symlink(path), times);
ENDSUBST

SUBST(int, lutimes, (char const *path, struct timeval times[2]))
    lutimes(RS_PARENT(path), times);
ENDSUBST

SUBST(int, utimensat, (int fd, char const *path, const struct timespec times[2], int flag))
    utimensat(fd, rs_at_flagged(fd, path, flag), times, flag);
ENDSUBST

SUBST(int, rename, (char const *from, char const *to))
    char newp1[PATH_MAX];
    strlcpy(newp1, RS_PARENT(from), PATH_MAX);
    rename(newp1, RS_PARENT(to));
ENDSUBST

SUBST(int, renameat, (int fd1, char const *from, int fd2, char const *to))
    char newp1[PATH_MAX];
    strlcpy(newp1, resolve_symlink_parent(fd1, from), PATH_MAX);
    renameat(fd1, newp1, fd2, resolve_symlink_parent(fd2, to));
ENDSUBST

SUBST(int, renamex_np, (char const *from, char const *to, int flags))
    char newp1[PATH_MAX];
    strlcpy(newp1, RS_PARENT(from), PATH_MAX);
    renamex_np(newp1, RS_PARENT(to), flags);
ENDSUBST

SUBST(int, renameatx_np,
        (int fd1, char const *from, int fd2, char const *to, int flags))
    char newp1[PATH_MAX];
    strlcpy(newp1, resolve_symlink_parent(fd1, from), PATH_MAX);
    renameatx_np(fd1, newp1, fd2, resolve_symlink_parent(fd2, to), flags);
ENDSUBST

SUBST(int, undelete, (char const *path))
    undelete(resolve_symlink(path));
ENDSUBST

SUBST(int, mkdir, (char const *path, mode_t mode))
    mkdir(RS_PARENT(path), mode);
ENDSUBST

SUBST(int, mkdirat, (int fd, char const *path, mode_t mode))
    mkdirat(fd, resolve_symlink_parent(fd, path), mode);
ENDSUBST

SUBST(int, rmdir, (char const *path))
    rmdir(RS_PARENT(path));
ENDSUBST

SUBST(int, chdir, (char const *path))
    chdir(resolve_symlink(path));
ENDSUBST

SUBST(int, statfs, (char const *path, struct statfs *buf))
    statfs(resolve_symlink(path), buf);
ENDSUBST

SUBST(ssize_t, listxattr, 
        (char const *path, char *buf, size_t size, int options))
    listxattr(RS_PARENT(path), buf, size, options);
ENDSUBST

SUBST(int, removexattr, 
        (char const *path, char const *name, int options))
    removexattr(RS_PARENT(path), name, options);
ENDSUBST

SUBST(int, setxattr, 
        (char const *path, char const *name, void *value, size_t size, u_int32_t position, int options))
    setxattr(RS_PARENT(path), name, value, size, position, options);
ENDSUBST

// pathconf returns long, and POSIX says it follows symlinks. It was
// declared int here: a real -1 (e.g. dangling link) came back to 64-bit
// callers as 4294967295 - libuv sizes its readlink buffer with it, and the
// kernel then rejected readlink(..., 4294967295) with EINVAL, breaking
// every fs.readlink/fs.symlink consumer in Node. RS_PARENT compounded it:
// the final component must be resolved (followed), or an all-logical
// symlink looks dangling to the real pathconf.
SUBST(long, pathconf, (char const *path, int name))
    pathconf(resolve_symlink(path), name);
ENDSUBST

SUBST(int, setattrlist, 
        (char const *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options))
    setattrlist(RS_PARENT(path), attrList, attrBuf, attrBufSize, options);
ENDSUBST

SUBST(int, getattrlist, 
        (char const *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options))
    getattrlist(RS_PARENT(path), attrList, attrBuf, attrBufSize, options);
ENDSUBST

SUBST(int, getattrlistat, 
        (int fd, char const *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned long options))
    getattrlistat(fd, resolve_symlink_parent(fd, path), attrList, attrBuf, attrBufSize, options);
ENDSUBST

SUBST(char const *, getcwd, (char *buf, size_t size))
    // libSystem getcwd() calls upon our other functions
    pthread_mutex_unlock(&_lock);
    char const *cwd = getcwd(buf, size);
    pthread_mutex_lock(&_lock);
    char const *nbuf;
    if (cwd == NULL) {
        nbuf = NULL;
    } else if (buf == NULL) {
        // getcwd(NULL, size) contract: return a malloc'd buffer the caller
        // frees. size may be 0 here, so the rewrite cannot go through
        // strlcpy(..., size) - it would copy nothing and hand the caller
        // the real path (bash's startup PWD came out un-rewritten this way).
        nbuf = strdup(rewrite_path_rev(cwd));
        free((void *)cwd);
    } else {
        // real -> logical strictly shrinks (pattern is shorter than
        // target), so rewriting in place never overflows the caller's size
        strlcpy(buf, rewrite_path_rev(buf), size);
        nbuf = buf;
    }
    nbuf;
ENDSUBST

SUBST(DIR *, opendir, (char const *path))
    opendir(resolve_symlink(path));
ENDSUBST

// scandir opens the directory through libc-internal calls that never hit
// the opendir interposer above; Node.js fs.readdir / fs.rm -r go through
// libuv's uv_fs_scandir -> scandir(3) and got ENOENT on every /nix path
// (about 150 of nodejs' checkPhase failures shared this one root cause).
// Like getcwd, the real call re-enters our interposers (its opendir binds
// through the interpose table), so the lock cannot be held across it.
SUBST(int, scandir,
        (char const *path, struct dirent ***namelist,
         int (*select)(const struct dirent *),
         int (*compar)(const struct dirent **, const struct dirent **)))
    char realp[PATH_MAX];
    int n;
    if (strlcpy(realp, resolve_symlink(path), sizeof realp) >= sizeof realp) {
        // oversize inputs pass through resolution verbatim; never operate
        // on a truncated copy (its prefix could name a real directory)
        errno = ENAMETOOLONG;
        n = -1;
    } else {
        pthread_mutex_unlock(&_lock);
        n = scandir(realp, namelist, select, compar);
        pthread_mutex_lock(&_lock);
    }
    n;
ENDSUBST

// The mkstemp family mutates its template argument in place, so the
// rewritten-and-filled real result must be mapped back into the caller's
// buffer (logical form is never longer than the input template unless
// parent-dir symlink resolution grew the prefix; in that unlikely case the
// created entry is removed and the call fails rather than overflowing the
// caller's buffer). Node's compile cache creates files via libuv's
// uv_fs_mkstemp -> mkostemp(3).
static int tmpl_writeback(char *template, char *realt)
{
    char const *logical = rewrite_path_rev(realt);
    if (strlen(logical) > strlen(template))
        return -1;
    strcpy(template, logical);
    return 0;
}

// A template outside the pattern needs no rewriting, and must not be
// resolved: resolve_symlink_parent would follow non-/nix symlinks (macOS
// /tmp -> /private/tmp) and lengthen the path past the caller's template
// buffer, so tmpl_writeback then fails a perfectly good call with
// ENAMETOOLONG (nix develop creates /tmp/nix-shell.XXXXXX this way). Pass
// such templates straight to the real call, unchanged.
SUBST(int, mkstemp, (char *template))
    char realt[PATH_MAX];
    int fd = -1;
    if (!startswith(pattern, template)) {
        pthread_mutex_unlock(&_lock);
        fd = mkstemp(template);
        pthread_mutex_lock(&_lock);
    } else if (strlcpy(realt, resolve_symlink_parent(-1, template),
                sizeof realt) >= sizeof realt) {
        errno = ENAMETOOLONG;
    } else {
        pthread_mutex_unlock(&_lock);
        fd = mkstemp(realt);
        pthread_mutex_lock(&_lock);
        if (fd >= 0 && tmpl_writeback(template, realt) < 0) {
            unlink(realt);
            close(fd);
            errno = ENAMETOOLONG;
            fd = -1;
        }
    }
    fd;
ENDSUBST

SUBST(int, mkostemp, (char *template, int oflags))
    char realt[PATH_MAX];
    int fd = -1;
    if (!startswith(pattern, template)) {
        pthread_mutex_unlock(&_lock);
        fd = mkostemp(template, oflags);
        pthread_mutex_lock(&_lock);
    } else if (strlcpy(realt, resolve_symlink_parent(-1, template),
                sizeof realt) >= sizeof realt) {
        errno = ENAMETOOLONG;
    } else {
        pthread_mutex_unlock(&_lock);
        fd = mkostemp(realt, oflags);
        pthread_mutex_lock(&_lock);
        if (fd >= 0 && tmpl_writeback(template, realt) < 0) {
            unlink(realt);
            close(fd);
            errno = ENAMETOOLONG;
            fd = -1;
        }
    }
    fd;
ENDSUBST

SUBST(char *, mkdtemp, (char *template))
    char realt[PATH_MAX];
    char *r = NULL;
    if (!startswith(pattern, template)) {
        pthread_mutex_unlock(&_lock);
        r = mkdtemp(template);
        pthread_mutex_lock(&_lock);
    } else if (strlcpy(realt, resolve_symlink_parent(-1, template),
                sizeof realt) >= sizeof realt) {
        errno = ENAMETOOLONG;
    } else {
        pthread_mutex_unlock(&_lock);
        r = mkdtemp(realt);
        pthread_mutex_lock(&_lock);
        if (r != NULL && tmpl_writeback(template, realt) < 0) {
            rmdir(realt);
            errno = ENAMETOOLONG;
            r = NULL;
        }
    }
    r ? template : NULL;
ENDSUBST

// vim: ft=c.doxygen
