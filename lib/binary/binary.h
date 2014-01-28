#pragma once
#include "common.h"
#include "headers/machine.h"

// options
#define MUST_FIND 1
// for sym
#define TO_EXECUTE 2
#define PRIVATE_SYM 4
#define IMPORTED_SYM 8
// for rangeconv
#define EXTEND_RANGE 16
// for find_string
#define PRECEDING_ZERO 32
#define TRAILING_ZERO 64

struct dyld_cache_header;
struct shared_file_mapping_np;
struct mach_header;
struct dysymtab_command;

struct data_segment {
    range_t file_range;
    range_t vm_range;
    void *native_segment;
};

struct data_sym {
    const char *name;
    addr_t address;
};

struct binary {
    bool valid;
    
    struct data_segment *segments;
    uint32_t nsegments; 

    cpu_type_t cpusubtype;
    cpu_type_t cputype;
    uint8_t pointer_size;

    prange_t valid_range;
    size_t header_offset;

    uint32_t reserved[8];

    uint32_t last_seg;
    
    struct binary *reexports;
    unsigned int nreexports;

    struct mach_binary *mach;
    struct dyldcache_binary *dyld;

    addr_t (*_sym)(const struct binary *binary, const char *name, int options);
    void (*_copy_syms)(const struct binary *binary, struct data_sym **syms, uint32_t *nsyms, int options);
};

__BEGIN_DECLS

static inline bool prange_check(const struct binary *binary, prange_t range) {
    return binary->valid_range.start <= range.start && range.size <= (size_t) ((char *) binary->valid_range.start + binary->valid_range.size - (char *) range.start);
}

__attribute__((pure)) prange_t rangeconv(range_t range, int flags);
__attribute__((pure)) prange_t rangeconv_off(range_t range, int flags);
__attribute__((pure)) range_t range_to_off_range(range_t range, int flags);
__attribute__((pure)) range_t off_range_to_range(range_t range, int flags);

void b_init(struct binary *binary);

// return value is |1 if to_execute is set and it is a thumb symbol
addr_t b_sym(const struct binary *binary, const char *name, int options);
void b_copy_syms(const struct binary *binary, struct data_sym **syms, uint32_t *nsyms, int options);

void b_store(struct binary *binary, const char *path);
#define b_macho_store b_store

static inline uint8_t b_pointer_size(const struct binary *binary) {
    return sizeof(addr_t) == 4 ? 4 : binary->pointer_size;
}

__attribute__((const))
static inline addr_t read_pointer(const void *ptr, int pointer_size) {
    if(pointer_size == 4) {
        return *((uint32_t *) ptr);
    } else {
        return *((uint64_t *) ptr);
    }
}

static inline void write_pointer(void *ptr, addr_t value, int pointer_size) {
    if(pointer_size == 4) {
        *((uint32_t *) ptr) = value;
    } else {
        *((uint64_t *) ptr) = value;
    }
}

__END_DECLS

// b_read32, etc.
#define r(sz) \
static inline uint##sz##_t b_read##sz(const struct binary *binary, addr_t addr) { \
    return *(uint##sz##_t *)(rangeconv((range_t) {binary, addr, sz/8}, MUST_FIND).start); \
}

r(8)
r(16)
r(32)
r(64)

