#pragma once
#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#define _DARWIN_C_SOURCE

//#define PROFILING

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/cdefs.h>
#ifdef PROFILING
#include <time.h>
#endif

#define swap32 __builtin_bswap32
#define SWAP32(x) ((typeof(x)) swap32((uint32_t) (x)))

// this function gets rid of compiler warnings about "comparison always true" - if that is true (because size_t is 64-bit on this architecture), great, don't bother me about it
__attribute__((always_inline)) static inline size_t _id(size_t x) { return x; }
#define MAX_ARRAY(typ) _id(~(size_t)0 / sizeof(typ))


static inline void _free_cleanup(void *pp) {
    void *p = *((void **) pp);
    if(p) free(p);
}
#define autofree __attribute__((cleanup(_free_cleanup)))

__unused static const char *const _arg = (char *) MAP_FAILED;

#define die(fmt, args...) ((_arg == MAP_FAILED) ? \
    _die("%s: " fmt "\n", __func__, ##args) : \
    _die("%s: %s: " fmt "\n", __func__, _arg, ##args))

#define edie(fmt, args...) die(fmt ": %s", ##args, strerror(errno))

struct binary;
#define ADDR64 1
#if ADDR64
typedef uint64_t addr_t;
#else
typedef uint32_t addr_t;
#endif
typedef struct { const struct binary *binary; addr_t start; size_t size; } range_t;
typedef struct { addr_t start; size_t size; } arange_t;
typedef struct { void *start; size_t size; } prange_t;

__BEGIN_DECLS

prange_t pdup(prange_t range, size_t newsize, size_t offset);

bool is_valid_range(prange_t range);

prange_t parse_hex_string(const char *string);

prange_t load_file(const char *filename, bool rw, mode_t *mode);
prange_t load_fd(int fd, bool rw);

void store_file(prange_t range, const char *filename, mode_t mode);

addr_t parse_hex_addr(const char *string);

__attribute__((noreturn, format(printf, 1, 2)))
void _die(const char *fmt, ...);

#if defined(__APPLE__) && __DARWIN_C_LEVEL < 200809L
static inline size_t strnlen(const char *s, size_t n) {
  const char *p = (const char *) memchr(s, 0, n);
  return p ? (size_t) (p-s) : n;
}
#endif

__END_DECLS
