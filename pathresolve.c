#include "common.h"

/**
 * @file        pathresolve.c
 * @author      Karim Vergnes <me@thesola.io>
 * @copyright   GPLv2
 * @brief       Pure path rewriting and symlink resolution logic.
 *
 * Split out of fakedir.c so it can be compiled and unit-tested on any POSIX
 * host (`make check`): everything here only depends on readlinkat() and
 * string handling, no Mach-O or interposition machinery.
 *
 * Due to the sensitive nature of the calling system calls, heap memory
 * allocation is strictly forbidden. All code below must use memory allocated
 * on the stack or static buffers (callers serialize on the global lock).
 */

static char pathbuf[FAKEDIR_BUFSZ];
static char rpathbuf[FAKEDIR_BUFSZ];
static char dedupbuf[FAKEDIR_BUFSZ];

/*
 * Inputs already at or over PATH_MAX are returned verbatim instead: the
 * kernel refuses the string with ENAMETOOLONG before looking at the
 * filesystem, which is exactly what a rooted install would report (and
 * what e.g. nodejs' filename-too-long tests assert). The marker below is
 * only for the remaining edge - an input short enough to be legal whose
 * *rewritten* form no longer fits PATH_MAX (or our buffers). It contains a
 * control character, so it cannot name an existing file: the calling
 * syscall fails with a clean ENOENT instead of operating on a silently
 * truncated - and possibly existing - path. It is also short, so callers
 * copying results into PATH_MAX buffers cannot re-truncate it into
 * something meaningful.
 */
static const char overflow_marker[] = "/\1fakedir-name-too-long";

void rewrite_init(void)
{
    strlcpy(pathbuf, target, sizeof pathbuf);
    strlcpy(rpathbuf, pattern, sizeof rpathbuf);
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
    // strip a redundant leading "/." only when followed by another
    // component ("/./nix/..." -> "/nix/..."); a bare startswith("/.")
    // check would also mangle real dotfiles like "/.vol/..."
    if (startswith("/./", path))
        path += 2;
    if (strlen(path) >= PATH_MAX) {
        DEBUG("rewrite_path: input exceeds PATH_MAX, passing through");
        return path;
    }
    if (pattern && startswith(pattern, path)) {
        size_t target_len = strlen(target);
        if (strlcpy(pathbuf + target_len, path + strlen(pattern),
                    sizeof pathbuf - target_len) >= sizeof pathbuf - target_len
                || strlen(pathbuf) >= PATH_MAX) {
            DEBUG("rewrite_path: rewritten path exceeds PATH_MAX, failing '%s'", path);
            return overflow_marker;
        }
        return pathbuf;
    } else {
        if (path != dedupbuf)
            strlcpy(dedupbuf, path, sizeof dedupbuf);
        return dedupbuf;
    }
}

char const *rewrite_path_rev(char const *path)
{
    if (startswith("/./", path))
        path += 2;
    if (strlen(path) >= PATH_MAX) {
        DEBUG("rewrite_path_rev: input exceeds PATH_MAX, passing through");
        return path;
    }
    if (target && startswith(target, path)) {
        size_t pattern_len = strlen(pattern);
        if (strlcpy(rpathbuf + pattern_len, path + strlen(target),
                    sizeof rpathbuf - pattern_len) >= sizeof rpathbuf - pattern_len) {
            DEBUG("rewrite_path_rev: rewritten path overflows, failing '%s'", path);
            return overflow_marker;
        }
        return rpathbuf;
    } else {
        if (path != dedupbuf)
            strlcpy(dedupbuf, path, sizeof dedupbuf);
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
static char resbufs[2][FAKEDIR_BUFSZ];
static int resbuf_idx = 0;

static char const *resolve_path_common(int fd, char const *path, bool keep_last)
{
    char rest[FAKEDIR_BUFSZ];   // unprocessed components, '/'-separated
    char out[FAKEDIR_BUFSZ];    // logical resolved-so-far
    char comp[FAKEDIR_BUFSZ];
    char lbuf[FAKEDIR_BUFSZ];
    char probe[FAKEDIR_BUFSZ];
    char tmp[FAKEDIR_BUFSZ];
    int nlinks = 0;
    char *res = resbufs[resbuf_idx];
    resbuf_idx = (resbuf_idx + 1) % 2;

    if (!path || !path[0]) {
        // preserve syscall semantics for the empty path (ENOENT)
        strlcpy(res, path ? path : "", FAKEDIR_BUFSZ);
        return res;
    }

    if (strlen(path) >= PATH_MAX) {
        // no resolution attempted: the kernel rejects the string with
        // ENAMETOOLONG before path lookup, same as a rooted install
        DEBUG("resolve: input exceeds PATH_MAX, passing through");
        return path;
    }

    bool is_abs = (path[0] == '/');
    if (fd == AT_FDCWD)
        fd = -1;

    strlcpy(rest, is_abs ? path + 1 : path, FAKEDIR_BUFSZ);
    out[0] = 0;

    while (rest[0]) {
        char *slash = strchr(rest, '/');
        if (slash) {
            size_t clen = slash - rest;
            memcpy(comp, rest, clen);
            comp[clen] = 0;
            memmove(rest, slash + 1, strlen(slash + 1) + 1);
        } else {
            strlcpy(comp, rest, FAKEDIR_BUFSZ);
            rest[0] = 0;
        }
        if (!comp[0] || !strcmp(comp, "."))
            continue;
        if (!strcmp(comp, "..")) {
            // Pop the last component - but only if there is one to pop.
            // For *relative* paths a leading ".." refers to the parent of
            // the fd/cwd, which we cannot resolve lexically, so it must be
            // kept verbatim (same when `out` is already all ".."s). Eating
            // it would turn openat(fd, "..") into openat(fd, ".") and
            // chdir("..") into a no-op: tools walking directory trees
            // (gnulib fts: chmod -R, cp, find, ...) then either abort with
            // ENOENT ("disinformation" dev/ino check) or silently mis-nest
            // every subsequent sibling one level deeper.
            // For absolute paths, "/.." is "/" (POSIX), so popping from an
            // empty `out` correctly stays at the root.
            char *ls = strrchr(out, '/');
            char const *lastc = ls ? ls + 1 : out;
            if (!is_abs && (!out[0] || !strcmp(lastc, ".."))) {
                if (out[0])
                    strlcat(out, "/", FAKEDIR_BUFSZ);
                strlcat(out, "..", FAKEDIR_BUFSZ);
            } else if (ls) {
                *ls = 0;
            } else {
                out[0] = 0;
            }
            continue;
        }
        strlcpy(probe, out, FAKEDIR_BUFSZ);
        if (is_abs || out[0])
            strlcat(probe, "/", FAKEDIR_BUFSZ);
        strlcat(probe, comp, FAKEDIR_BUFSZ);

        if (keep_last && !rest[0]) {
            // final component belongs to the caller (create/readlink/etc.)
            strlcpy(out, probe, FAKEDIR_BUFSZ);
            break;
        }

        ssize_t ll = readlinkat(fd == -1 ? AT_FDCWD : fd,
                                rewrite_path(probe), lbuf, FAKEDIR_BUFSZ - 1);
        if (ll < 0 || ++nlinks > 40) {
            // not a symlink (or ELOOP guard): keep component as-is
            strlcpy(out, probe, FAKEDIR_BUFSZ);
            continue;
        }
        lbuf[ll] = 0;
        if (lbuf[0] == '/') {
            out[0] = 0;
            is_abs = true;
            strlcpy(tmp, lbuf + 1, FAKEDIR_BUFSZ);
        } else {
            strlcpy(tmp, lbuf, FAKEDIR_BUFSZ);
        }
        if (rest[0]) {
            strlcat(tmp, "/", FAKEDIR_BUFSZ);
            strlcat(tmp, rest, FAKEDIR_BUFSZ);
        }
        strlcpy(rest, tmp, FAKEDIR_BUFSZ);
    }

    if (!out[0])
        strlcpy(out, is_abs ? "/" : ".", FAKEDIR_BUFSZ);
    strlcpy(res, rewrite_path(out), FAKEDIR_BUFSZ);
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

// vim: ft=c.doxygen
