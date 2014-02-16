#include "common.h"
#include "binary.h"
#include "find.h"
#include <stddef.h>

static inline bool prange_check(const struct binary *binary, prange_t range);

void b_init(struct binary *binary) {
    memset(binary, 0, sizeof(*binary));
}

static inline bool rangeconv_stuff(const struct binary *binary, addr_t addr, bool is_off, addr_t *out_address, addr_t *out_offset, size_t *out_size) {
    uint32_t ls = binary->last_seg, ns = binary->nsegments, i = ls;
    #define STUFF \
        const struct data_segment *seg = &binary->segments[i]; \
        addr_t diff = addr - (is_off ? seg->file_range : seg->vm_range).start; \
        if(diff < seg->file_range.size) { \
            ((struct binary *) binary)->last_seg = i; \
            *out_address = seg->vm_range.start + diff; \
            *out_offset = seg->file_range.start + diff; \
            *out_size = seg->file_range.size - diff; \
            return true; \
        }
    STUFF
    for(i = 0; i < ns; i++) {
        STUFF
    }
    return false;
}

inline prange_t rangeconv(range_t range, int flags) {
    addr_t address; addr_t offset; size_t size;
    if(rangeconv_stuff(range.binary, range.start, false, &address, &offset, &size)) {
        if(__builtin_expect(flags & EXTEND_RANGE, 0)) {
            range.size = size;
            flags &= ~EXTEND_RANGE;
        }
        return rangeconv_off((range_t) {range.binary, offset, range.size}, flags);
    } else if(flags & MUST_FIND) {
        die("range (%08llx, %zx) not valid", (uint64_t) range.start, range.size);
    } else {
        return (prange_t) {NULL, 0};
    }
}

inline prange_t rangeconv_off(range_t range, int flags) {
    prange_t pr;
    if(range.start == 0 && range.binary->header_offset) {
        // dyld caches are weird.
        range.start = range.binary->header_offset;
    }
    pr.start = (char *) range.binary->valid_range.start + range.start;
    pr.size = range.size;
    if(!prange_check(range.binary, pr)) {
        if(flags & MUST_FIND) {
            die("offset range (%08llx, %zx) not valid", (uint64_t) range.start, range.size);
        } else {
            return (prange_t) {NULL, 0};
        }
    }
    if(__builtin_expect(flags & EXTEND_RANGE, 0)) {
        pr.size = ((char *) range.binary->valid_range.start + range.binary->valid_range.size - (char *) pr.start); 
    }
    return pr;
}

range_t range_to_off_range(range_t range, int flags) {
    addr_t address; addr_t offset; size_t size;
    if(rangeconv_stuff(range.binary, range.start, false, &address, &offset, &size) && range.size <= size) {
        return (range_t) {range.binary, offset, range.size};
    }
    if(flags & MUST_FIND) {
        die("range (%08llx, %zx) not valid", (uint64_t) range.start, range.size);
    } else {
        return (range_t) {NULL, 0, 0};
    }
}

range_t off_range_to_range(range_t range, int flags) {
    addr_t address; addr_t offset; size_t size;
    if(rangeconv_stuff(range.binary, range.start, true, &address, &offset, &size) && range.size <= size) {
        return (range_t) {range.binary, address, range.size};
    }
    if(flags & MUST_FIND) {
        die("offset range (%08llx, %zx) not valid", (uint64_t) range.start, range.size);
    } else {
        return (range_t) {NULL, 0, 0};
    }
}

addr_t b_sym(const struct binary *binary, const char *name, int options) {
    addr_t result = binary->_sym ? binary->_sym(binary, name, options) : 0;
    if(!result && (options & MUST_FIND)) {
        die("symbol %s not found", name);
    }
    return result;
}

void b_copy_syms(const struct binary *binary, struct data_sym **syms, uint32_t *nsyms, int options) {
    if(!binary->_copy_syms) {
        *syms = NULL;
        *nsyms = 0;
        return;
    }
    binary->_copy_syms(binary, syms, nsyms, options);
}

void b_store(struct binary *binary, const char *path) {
    store_file(binary->valid_range, path, 0755);
}

