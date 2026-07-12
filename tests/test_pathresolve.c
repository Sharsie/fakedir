#include "common.h"

/*
 * Unit tests for pathresolve.c. Compiles and runs on any POSIX host:
 *   make check
 *
 * Builds a sandbox that mimics a rootless nix store layout
 * (pattern "/fnix" mapped onto a real directory) including the
 * profile-style symlink chains that broke resolution historically,
 * then asserts on rewrite_path/resolve_symlink_* behavior.
 */

// Globals normally defined by fakedir.c (not linked here).
bool isdebug = false;
int debugfd = 2;
const char *pattern;
const char *target;

static int failures = 0;
static int checks = 0;

static void expect_str(const char *name, const char *got, const char *want)
{
    checks++;
    if (!got || strcmp(got, want)) {
        failures++;
        printf("FAIL %-42s got '%s'\n     %-42s want '%s'\n", name, got ? got : "(null)", "", want);
    } else {
        printf("ok   %-42s '%s'\n", name, got);
    }
}

static void expect_true(const char *name, bool cond)
{
    checks++;
    if (!cond) {
        failures++;
        printf("FAIL %s\n", name);
    } else {
        printf("ok   %s\n", name);
    }
}

static void xmkdir(const char *path)
{
    if (mkdir(path, 0755) && errno != EEXIST) {
        perror(path);
        exit(1);
    }
}

static void xsymlink(const char *tgt, const char *path)
{
    if (symlink(tgt, path)) {
        perror(path);
        exit(1);
    }
}

static char sb[FAKEDIR_BUFSZ];      // sandbox root
static char tgt[FAKEDIR_BUFSZ];     // FAKEDIR_TARGET = $sb/real

static char pb[8][FAKEDIR_BUFSZ];   // scratch for building paths
static int pbi = 0;

static const char *sbpath(const char *rel)
{
    char *b = pb[pbi];
    pbi = (pbi + 1) % 8;
    snprintf(b, FAKEDIR_BUFSZ, "%s/%s", sb, rel);
    return b;
}

static const char *tpath(const char *rel)
{
    char *b = pb[pbi];
    pbi = (pbi + 1) % 8;
    snprintf(b, FAKEDIR_BUFSZ, "%s%s", tgt, rel);
    return b;
}

int main(void)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(sb, sizeof sb, "%s/fakedir-test.XXXXXX", tmp);
    if (!mkdtemp(sb)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(tgt, sizeof tgt, "%s/real", sb);

    pattern = "/fnix";
    target = tgt;
    rewrite_init();

    // sandbox layout
    xmkdir(tpath(""));
    xmkdir(tpath("/store"));
    xmkdir(tpath("/store/aaa-hello"));
    xmkdir(tpath("/store/aaa-hello/bin"));
    xmkdir(tpath("/store/bbb-env"));
    xmkdir(tpath("/store/bbb-env/bin"));
    xmkdir(sbpath("home"));
    xmkdir(sbpath("work"));
    xmkdir(sbpath("work/sub"));
    xmkdir(sbpath("work/sub/a"));
    xmkdir(sbpath("work/other"));

    FILE *f = fopen(tpath("/store/aaa-hello/bin/hello"), "w");
    fputs("hi", f);
    fclose(f);

    // profile-style chain: absolute logical target
    xsymlink("/fnix/store/aaa-hello/bin/hello", tpath("/store/bbb-env/bin/hello"));
    // relative target with leading ".."s
    xsymlink("../../aaa-hello/bin/hello", tpath("/store/bbb-env/bin/hello2"));
    // profile generation link + ~/.nix-profile
    xsymlink("/fnix/store/bbb-env", tpath("/profile-1"));
    xsymlink(tpath("/profile-1"), sbpath("home/.nix-profile"));
    // symlink loop
    xsymlink("loop", tpath("/loop"));

    // --- rewrite_path ---------------------------------------------------
    expect_str("rewrite basic", rewrite_path("/fnix/store/x"), tpath("/store/x"));
    expect_str("rewrite non-matching", rewrite_path("/elsewhere/y"), "/elsewhere/y");
    expect_str("rewrite '/./' prefix", rewrite_path("/./fnix/store/x"), tpath("/store/x"));
    expect_str("rewrite keeps root dotfiles", rewrite_path("/.hidden"), "/.hidden");
    expect_str("rewrite_rev basic", rewrite_path_rev(tpath("/store/x")), "/fnix/store/x");

    // --- absolute resolution through symlink chains ----------------------
    expect_str("abs: logical-target link",
               resolve_symlink_at(-1, "/fnix/store/bbb-env/bin/hello"),
               tpath("/store/aaa-hello/bin/hello"));
    expect_str("abs: profile chain splice",
               resolve_symlink_at(-1, sbpath("home/.nix-profile/bin/hello")),
               tpath("/store/aaa-hello/bin/hello"));
    expect_str("abs: relative-'..'-target link",
               resolve_symlink_at(-1, "/fnix/store/bbb-env/bin/hello2"),
               tpath("/store/aaa-hello/bin/hello"));
    expect_str("abs: keep_last leaves leaf link",
               resolve_symlink_parent(-1, "/fnix/store/bbb-env/bin/hello"),
               tpath("/store/bbb-env/bin/hello"));
    expect_str("abs: '/fnix/store/..' pops to target root",
               resolve_symlink_at(-1, "/fnix/store/.."), tgt);
    expect_str("abs: '/..' stays at root", resolve_symlink_at(-1, "/.."), "/");
    expect_str("abs: symlink loop terminates",
               resolve_symlink_at(-1, "/fnix/loop"), tpath("/loop"));
    expect_str("empty path preserved", resolve_symlink_at(-1, ""), "");

    // --- relative paths with leading ".." (the fts/chdir bug) -----------
    int wsfd = open(sbpath("work/sub"), O_RDONLY | O_DIRECTORY);
    expect_true("open work/sub dirfd", wsfd >= 0);

    expect_str("rel: '..' kept", resolve_symlink_at(wsfd, ".."), "..");
    expect_str("rel: '../other' kept", resolve_symlink_at(wsfd, "../other"), "../other");
    expect_str("rel: '../..' kept", resolve_symlink_at(wsfd, "../.."), "../..");
    expect_str("rel: '../../work/sub' kept",
               resolve_symlink_at(wsfd, "../../work/sub"), "../../work/sub");
    expect_str("rel: 'a/..' collapses to '.'", resolve_symlink_at(wsfd, "a/.."), ".");
    expect_str("rel: keep_last '..'", resolve_symlink_parent(wsfd, ".."), "..");

    // the actual fts ascent scenario: openat(fd, "..") must open the parent
    struct stat st_parent, st_via;
    stat(sbpath("work"), &st_parent);
    int upfd = openat(wsfd, resolve_symlink_at(wsfd, ".."), O_RDONLY | O_DIRECTORY);
    expect_true("openat(fd, resolve('..')) opens parent",
                upfd >= 0 && !fstat(upfd, &st_via)
                && st_via.st_dev == st_parent.st_dev
                && st_via.st_ino == st_parent.st_ino);
    if (upfd >= 0)
        close(upfd);

    // fd-relative name whose symlink target starts with ".."
    int binfd = open(tpath("/store/bbb-env/bin"), O_RDONLY | O_DIRECTORY);
    expect_true("open bbb-env/bin dirfd", binfd >= 0);
    expect_str("rel: link target with leading '..'",
               resolve_symlink_at(binfd, "hello2"), "../../aaa-hello/bin/hello");
    char rbuf[4];
    int hfd = openat(binfd, resolve_symlink_at(binfd, "hello2"), O_RDONLY);
    expect_true("openat resolved '..'-target reads file",
                hfd >= 0 && read(hfd, rbuf, 2) == 2 && !strncmp(rbuf, "hi", 2));
    if (hfd >= 0)
        close(hfd);

    // --- oversize handling ------------------------------------------------
    {
        // long but valid: must come back complete, never truncated.
        // Sized so the rewritten path stays under PATH_MAX even on macOS
        // (1024 there, 4096 on Linux) - anything longer passes through
        // unrewritten, which the next case covers.
        char longp[2048];
        int n = snprintf(longp, sizeof longp, "/fnix/store/");
        size_t fill = PATH_MAX - 1 - strlen(tgt) - (n - strlen("/fnix"));
        memset(longp + n, 'a', fill);
        longp[n + fill] = 0;
        const char *r = resolve_symlink_at(-1, longp);
        checks++;
        if (strlen(r) != strlen(longp) - strlen("/fnix") + strlen(tgt)
            || !startswith(tgt, r) || !endswith("aaa", r)) {
            failures++;
            printf("FAIL long path resolved without truncation (len %zu)\n", strlen(r));
        } else {
            printf("ok   long path resolved without truncation (len %zu)\n", strlen(r));
        }

        // at/over PATH_MAX: passed through verbatim so the kernel reports
        // ENAMETOOLONG, exactly as it would on a rooted install (nodejs'
        // filename-too-long tests assert that errno). Never truncated.
        static char huge[FAKEDIR_BUFSZ + 100];
        huge[0] = '/';
        memset(huge + 1, 'b', sizeof huge - 2);
        huge[sizeof huge - 1] = 0;
        const char *m = resolve_symlink_at(-1, huge);
        expect_true("oversize input passes through verbatim", m == huge);
        expect_true("oversize open fails ENAMETOOLONG",
                    open(m, O_RDONLY) == -1 && errno == ENAMETOOLONG);

        // input legal, rewritten form too long: the unresolvable marker
        // (clean ENOENT, cannot name a real file, cannot be re-truncated
        // into one)
        char edge[PATH_MAX];
        int en = snprintf(edge, sizeof edge, "/fnix/store/");
        memset(edge + en, 'c', PATH_MAX - 1 - en);
        edge[PATH_MAX - 1] = 0;
        const char *e = resolve_symlink_at(-1, edge);
        expect_true("rewrite overflow yields unresolvable marker",
                    e && e[0] == '/' && e[1] == '\1');
    }

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
