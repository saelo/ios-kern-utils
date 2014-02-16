#include "common.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdarg.h>
#ifdef __APPLE__
#include <mach/mach.h>
#endif

prange_t pdup(prange_t range, size_t newsize, size_t offset) {
    if(newsize < offset + range.size) {
        die("pdup: newsize=%zu < offset=%zu + range.size=%zu", newsize, offset, range.size);
    }
    void *buf = mmap(NULL, newsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if(buf == MAP_FAILED) {
        edie("pdup: could not mmap");
    }
#ifdef __APPLE__
    munmap(buf + offset, range.size);
    vm_prot_t cur, max;
    vm_address_t addr = (vm_address_t) (buf + offset);
    kern_return_t kr = vm_remap(mach_task_self(), &addr, range.size, 0xfff, 0, mach_task_self(), (vm_address_t) range.start, true, &cur, &max, VM_INHERIT_NONE);
    if(kr) {
        die("pdup: kr = %d", (int) kr);
    }
#else
    memcpy(buf + offset, range.start, range.size);
#endif
    return (prange_t) {buf, newsize};
}

bool is_valid_range(prange_t range) {
    char c;
    return !mincore(range.start, range.size, (void *) &c);
}

static inline uint8_t parse_hex_digit(char digit, const char *string) {
    switch(digit) {
    case '0' ... '9':
        return (uint8_t) (digit - '0');
    case 'a' ... 'f':
        return (uint8_t) (10 + (digit - 'a'));
    default:
        die("bad hex string %s", string);
    }
}

prange_t parse_hex_string(const char *string) {
    if(string[0] == '0' && string[1] == 'x') {
        string += 2;
    }
    const char *in = string;
    size_t len = strlen(string);
    size_t out_len = (len + 1)/2;
    uint8_t *out = malloc(out_len);
    prange_t result = (prange_t) {out, out_len};
    if(len % 2) {
        *out++ = parse_hex_digit(*in++, string);
    }
    while(out_len--) {
        uint8_t a = parse_hex_digit(*in++, string);
        uint8_t b = parse_hex_digit(*in++, string);
        *out++ = (uint8_t) ((a * 0x10) + b);
    }
    return result;
}

addr_t parse_hex_addr(const char *string) {
    char *end;
    addr_t result = (addr_t) strtoll(string, &end, 16);
    if(!*string || *end) {
        die("invalid hex value %s", string);
    }
    return result;
}

prange_t load_file(const char *filename, bool rw, mode_t *mode) {
#define _arg filename
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        edie("could not open");
    }
    if(mode) {
        struct stat st;
        if(fstat(fd, &st)) {
            edie("could not lstat");
        }
        *mode = st.st_mode;
    }
    prange_t ret = load_fd(fd, rw);
    close(fd);
    return ret;
#undef _arg
}

prange_t load_fd(int fd, bool rw) {
    off_t end = lseek(fd, 0, SEEK_END);
    if(end == 0) {
        fprintf(stderr, "load_fd: warning: mapping an empty file\n");
    }
    if(sizeof(off_t) > sizeof(size_t) && end > (off_t) SIZE_MAX) {
        die("too big: %lld", (long long) end);
    }
    void *buf = mmap(NULL, (size_t) end, PROT_READ | (rw ? PROT_WRITE : 0), MAP_PRIVATE, fd, 0);
    if(buf == MAP_FAILED) {
        edie("could not mmap buf (end=%zu)", (size_t) end);
    }
    return (prange_t) {buf, (size_t) end};
}

void store_file(prange_t range, const char *filename, mode_t mode) {
#define _arg filename
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if(fd == -1) {
        edie("could not open");
    }
    if(write(fd, range.start, range.size) != (ssize_t) range.size) {
        edie("could not write data");
    }
    close(fd);
#undef _arg
}

#if defined(__GNUC__) && !defined(__clang__) && !defined(__arm__)
#define EXCEPTION_SUPPORT 1
#endif

// Basically, ctypes/libffi is very fancy but does not support using setjmp() as an exception mechanism.  Running setjmp() directly from Python is... not effective, as you might expect.  So here's an unnecessarily portable hack.

#ifdef EXCEPTION_SUPPORT
#include <setjmp.h>
#include <pthread.h>

static bool call_going;
static void *call_func;
static jmp_buf call_jmp;
static char call_error[256];

void data_call_init(void *func) {
    call_func = func;
    call_going = true;
    call_error[0] = 0;
}

void data_call(__unused int whatever, ...) {
    if(!setjmp(call_jmp)) {
        __builtin_return(__builtin_apply(call_func, __builtin_apply_args(), 32));
    }
}

char *data_call_fini() {
    call_going = false;
    return call_error;
}

void _die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    if(call_going) {
        vsnprintf(call_error, sizeof(call_error), fmt, ap);
        longjmp(call_jmp, -1);
    } else {
        vfprintf(stderr, fmt, ap);
        abort();
    }

    va_end(ap);
}

#else
void _die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    abort();
    va_end(ap);
}
#endif

