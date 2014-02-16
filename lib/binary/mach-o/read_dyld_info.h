#pragma once
#include <stdint.h>
// ld64
static addr_t read_xleb128(void **ptr, void *end, bool is_signed) {
    addr_t result = 0;
    uint8_t *p = *ptr;
    uint8_t bit;
    unsigned int shift = 0;
    do {
        if(p >= (uint8_t *) end) die("uleb128 overrun");
        bit = *p++;
        addr_t k = bit & 0x7f;
        // 0x0051 BIND_OPCODE_ADD_ADDR_ULEB(0xFFFFFFF8)
        // the argument is a lie, it's actually 64 bits of fff, which overflows here
        // it should just be sleb, but ...
        //if(shift >= 8*sizeof(addr_t) || ((k << shift) >> shift) != k) die("uleb128 too big");
        if(shift < sizeof(addr_t) * 8) {
            result |= k << shift;
        }
        shift += 7;
    } while(bit & 0x80);
    if(is_signed && (bit & 0x40)) {
        result |= ~(((addr_t) 0) << shift);
    }
    *ptr = p;
    return result;
}

static addr_t read_uleb128(void **ptr, void *end) {
    return read_xleb128(ptr, end, false);
}

__attribute__((unused)) static addr_t read_sleb128(void **ptr, void *end) {
    return read_xleb128(ptr, end, true);
}

static inline void *read_bytes(void **ptr, void *end, size_t size) {
    char *p = *ptr;
    if((size_t) ((char *) end - p) < size) die("too big");
    *ptr = p + size;
    return p;
}

#define read_int(ptr, end, typ) *((typ *) read_bytes(ptr, end, sizeof(typ)))

static inline char *read_cstring(void **ptr, void *end) {
    // could use strnlen...
    char *start = *ptr, *strend = start;
    while(strend != end) {
        if(!*strend++) {
            *ptr = strend;
            return start;
        }
    }
    die("c string overflow");
}
