#include "common.h"
#include <string.h>
#include <stdarg.h>

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

void _my_dlopen_inner(char const *path)
{
    DEBUG("recursing through dlopen '%s'", path);
    my_dlopen(path, RTLD_GLOBAL|RTLD_NOW);
}

void *my_dlopen(char const *path, int mode)
{
    DEBUG("dlopen(%s) was called.", path);
    if (path) {
        char realp[PATH_MAX];
        pthread_mutex_lock(&_lock);
        strlcpy(realp, resolve_symlink(path), PATH_MAX);
        pthread_mutex_unlock(&_lock);
        macho_add_dependencies(realp, _my_dlopen_inner);
        return dlopen(realp, mode);
    } else {
        return dlopen(path, mode);
    }
}

int my_open(char const *name, int flags, int mode)
{
    char const *n;
    if (flags & (O_SYMLINK|O_NOFOLLOW))
        n = RS_PARENT(name);
    else
        n = resolve_symlink(name);
    return open(n, flags, mode);
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

SUBST(void *, dlopen, (char const *path, int mode))
    // unlock due to recursive function, see above
    pthread_mutex_unlock(&_lock);
    my_dlopen(path, mode);
ENDSUBST

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
    int rfd = (fd == AT_FDCWD) ? -1 : fd;
    if (flags & (O_SYMLINK|O_NOFOLLOW))
        n = resolve_symlink_parent(rfd, name);
    else
        n = resolve_symlink_at(rfd, name);
    int _r = openat(fd, n, flags, mode);
    pthread_mutex_unlock(&_lock);
    return _r;
}

SUBST(int, lstat, (char const *path, struct stat *buf))
    lstat(RS_PARENT(path), buf);
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

SUBST(FILE *, fopen, (char const *path, char const *mode))
    fopen(resolve_symlink(path), mode);
ENDSUBST

SUBST(FILE *, freopen, (char const *path, char const *mode, FILE *orig))
    freopen(resolve_symlink(path), mode, orig);
ENDSUBST

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

SUBST(int, pathconf, (char const *path, int name))
    pathconf(RS_PARENT(path), name);
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
    char *nbuf;
    if (buf == NULL) {
        nbuf = strdup(cwd);
    } else {
        nbuf = buf;
    }
    strlcpy(nbuf, rewrite_path_rev(nbuf), size);
    nbuf;
ENDSUBST

SUBST(DIR *, opendir, (char const *path))
    opendir(resolve_symlink(path));
ENDSUBST

// vim: ft=c.doxygen
