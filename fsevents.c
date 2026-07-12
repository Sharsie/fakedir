#include "common.h"

/**
 * @file        fsevents.c
 * @author      Karim Vergnes <me@thesola.io>
 * @copyright   GPLv2
 * @brief       FSEvents path rewriting via dlsym interception.
 *
 * Directory watching on macOS goes through FSEventStreamCreate, which takes
 * a CFArray of path strings - none of the POSIX interposers ever see them.
 * Worse, libuv (Node.js fs.watch on directories) does not even link
 * CoreServices: it dlopens the framework and calls FSEventStreamCreate
 * through a dlsym'd pointer, which DYLD interposition cannot rebind. So
 * dlsym itself is interposed: a lookup of FSEventStreamCreate returns a
 * shim that rewrites the watched paths into the real tree, and wraps the
 * event callback so delivered event paths are mapped back to the logical
 * prefix before the caller sees them (callers filter events by comparing
 * against the logical path they asked to watch).
 *
 * Everything CoreFoundation is resolved lazily through the real dlsym at
 * shim-call time: by definition the caller has CoreFoundation loaded, and
 * fakedir must not link it - that would drag CF initializers into every
 * injected process (and CF is not fork-safe).
 *
 * Unlike the syscall interposers, this path allocates: FSEvents callbacks
 * run on a runloop thread, well outside any syscall, and the CF API forces
 * allocation anyway (CFStringCreate/CFArrayCreate).
 */

// --- minimal CF/FSEvents declarations (no framework headers) --------------
typedef void *CFAllocatorRef;
typedef void *CFArrayRef;
typedef void *CFStringRef;
typedef void *FSEventStreamRef;
typedef long CFIndex;
typedef double CFTimeInterval;
typedef unsigned char Boolean;
typedef unsigned int CFStringEncoding;
typedef unsigned int FSEventStreamCreateFlags;
typedef unsigned int FSEventStreamEventFlags;
typedef unsigned long long FSEventStreamEventId;

#define kCFStringEncodingUTF8 0x08000100
#define kFSEventStreamCreateFlagUseCFTypes 0x00000001

typedef struct {
    CFIndex version;
    void *info;
    const void *(*retain)(const void *);
    void (*release)(const void *);
    CFStringRef (*copyDescription)(const void *);
} FSEventStreamContext;

typedef void (*FSEventStreamCallback)(FSEventStreamRef stream, void *info,
        size_t numEvents, void *eventPaths,
        const FSEventStreamEventFlags *eventFlags,
        const FSEventStreamEventId *eventIds);

typedef FSEventStreamRef (*FSEventStreamCreate_t)(CFAllocatorRef,
        FSEventStreamCallback, FSEventStreamContext *, CFArrayRef,
        FSEventStreamEventId, CFTimeInterval, FSEventStreamCreateFlags);

static FSEventStreamCreate_t real_FSEventStreamCreate;

static CFIndex (*pCFArrayGetCount)(CFArrayRef);
static const void *(*pCFArrayGetValueAtIndex)(CFArrayRef, CFIndex);
static Boolean (*pCFStringGetCString)(CFStringRef, char *, CFIndex,
        CFStringEncoding);
static CFStringRef (*pCFStringCreateWithCString)(CFAllocatorRef,
        const char *, CFStringEncoding);
static CFArrayRef (*pCFArrayCreate)(CFAllocatorRef, const void **, CFIndex,
        const void *);
static void (*pCFRelease)(const void *);
static void *pkCFTypeArrayCallBacks;

static bool cf_resolve(void)
{
    if (pCFRelease)
        return true;
#   define R(n) (p##n = dlsym(RTLD_DEFAULT, #n))
    if (!R(CFArrayGetCount) || !R(CFArrayGetValueAtIndex)
            || !R(CFStringGetCString) || !R(CFStringCreateWithCString)
            || !R(CFArrayCreate) || !(pkCFTypeArrayCallBacks =
                    dlsym(RTLD_DEFAULT, "kCFTypeArrayCallBacks")))
        return false;
    return R(CFRelease) != NULL;
#   undef R
}

// Original callback + info, carried through the stream's context. Lives as
// long as the stream; FSEventStreamRelease gives us no hook, so one small
// allocation per created stream is deliberately leaked.
struct fse_trampoline {
    FSEventStreamCallback cb;
    void *info;
};

static void fse_event_shim(FSEventStreamRef stream, void *info,
        size_t numEvents, void *eventPaths,
        const FSEventStreamEventFlags *eventFlags,
        const FSEventStreamEventId *eventIds)
{
    struct fse_trampoline *t = info;
    char **in = eventPaths;
    char **out = calloc(numEvents, sizeof (char *));

    if (out) {
        for (size_t i = 0; i < numEvents; i++) {
            pthread_mutex_lock(&_lock);
            out[i] = strdup(rewrite_path_rev(in[i]));
            pthread_mutex_unlock(&_lock);
            if (!out[i])
                goto passthrough;
        }
        t->cb(stream, t->info, numEvents, out, eventFlags, eventIds);
        for (size_t i = 0; i < numEvents; i++)
            free(out[i]);
        free(out);
        return;
    }

passthrough:
    // allocation failure: better real paths than dropped events
    if (out) {
        for (size_t i = 0; i < numEvents; i++)
            free(out[i]);
        free(out);
    }
    t->cb(stream, t->info, numEvents, eventPaths, eventFlags, eventIds);
}

static FSEventStreamRef my_FSEventStreamCreate(CFAllocatorRef allocator,
        FSEventStreamCallback callback, FSEventStreamContext *context,
        CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen,
        CFTimeInterval latency, FSEventStreamCreateFlags flags)
{
    DEBUG("Now serving %s", "FSEventStreamCreate");

    if (!cf_resolve())
        return real_FSEventStreamCreate(allocator, callback, context,
                pathsToWatch, sinceWhen, latency, flags);

    CFIndex count = pCFArrayGetCount(pathsToWatch);
    CFStringRef strs[count > 0 ? count : 1];
    const void *values[count > 0 ? count : 1];

    for (CFIndex i = 0; i < count; i++) {
        char buf[FAKEDIR_BUFSZ];
        CFStringRef s = (CFStringRef) pCFArrayGetValueAtIndex(pathsToWatch, i);
        if (pCFStringGetCString(s, buf, sizeof buf, kCFStringEncodingUTF8)) {
            pthread_mutex_lock(&_lock);
            strs[i] = pCFStringCreateWithCString(NULL, resolve_symlink(buf),
                    kCFStringEncodingUTF8);
            pthread_mutex_unlock(&_lock);
        } else {
            strs[i] = NULL;
        }
        values[i] = strs[i] ? strs[i] : pCFArrayGetValueAtIndex(pathsToWatch, i);
    }
    CFArrayRef rewritten = pCFArrayCreate(NULL, values, count,
            pkCFTypeArrayCallBacks);

    FSEventStreamRef ref;
    if (flags & kFSEventStreamCreateFlagUseCFTypes) {
        // event paths would arrive as CFStrings we do not rewrite; keep the
        // caller's callback untouched rather than half-translate (libuv and
        // friends use plain C-string events, so this path is theoretical)
        ref = real_FSEventStreamCreate(allocator, callback, context,
                rewritten ? rewritten : pathsToWatch, sinceWhen, latency,
                flags);
    } else {
        struct fse_trampoline *t = malloc(sizeof *t);
        FSEventStreamContext ctx = { 0 };
        if (context)
            ctx = *context;
        if (t) {
            t->cb = callback;
            t->info = context ? context->info : NULL;
            ctx.info = t;
            // the caller's retain/release manage their info pointer, which
            // now lives inside the trampoline instead of the context
            ctx.retain = NULL;
            ctx.release = NULL;
            ctx.copyDescription = NULL;
        }
        ref = real_FSEventStreamCreate(allocator,
                t ? fse_event_shim : callback, t ? &ctx : context,
                rewritten ? rewritten : pathsToWatch, sinceWhen, latency,
                flags);
    }

    for (CFIndex i = 0; i < count; i++)
        if (strs[i])
            pCFRelease(strs[i]);
    if (rewritten)
        pCFRelease(rewritten);
    return ref;
}

// --- dlsym interception ----------------------------------------------------
// DYLD interposition rewrites symbol bindings, not function pointers, so
// anything obtained through dlsym escapes every interposer above. That is
// exactly how libuv calls FSEvents. Interpose dlsym itself and swap the one
// symbol that matters.
void *_my_dlsym(void *handle, const char *name);
__attribute__((used, section("__DATA,__interpose")))
    static void *_dlsym[] = { _my_dlsym, dlsym };
void *_my_dlsym(void *handle, const char *name)
{
    void *real = dlsym(handle, name);
    if (real && name && !strcmp(name, "FSEventStreamCreate")) {
        DEBUG("dlsym(%s) intercepted", name);
        real_FSEventStreamCreate = (FSEventStreamCreate_t) real;
        return (void *) my_FSEventStreamCreate;
    }
    return real;
}

// vim: ft=c.doxygen
