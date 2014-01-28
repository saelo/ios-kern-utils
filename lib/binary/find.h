#pragma once
#include "common.h"
struct binary;
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

__BEGIN_DECLS

// Specify align as 0 if you only expect to find it at one place.
addr_t find_data(range_t range, const char *to_find, int align, int options);
addr_t find_string(range_t range, const char *string, int align, int options);
addr_t find_bytes(range_t range, const char *bytes, size_t len, int align, int options);
addr_t find_int32(range_t range, uint32_t number, int options);

// helper functions
addr_t find_bof(range_t range, addr_t eof, int is_thumb);
uint32_t resolve_ldr(const struct binary *binary, addr_t addr);

addr_t find_bl(range_t *range);

#define b_find_anywhere b_find_data_anywhere
addr_t b_find_data_anywhere(const struct binary *binary, const char *to_find, int align, int options);
addr_t b_find_string_anywhere(const struct binary *binary, const char *string, int align, int options);
addr_t b_find_bytes_anywhere(const struct binary *binary, const char *bytes, size_t len, int align, int options);
addr_t b_find_int32_anywhere(const struct binary *binary, uint32_t number, int options);

struct findmany *findmany_init(range_t range);
void findmany_add(addr_t *result, struct findmany *fm, const char *to_find);
void findmany_go(struct findmany *fm);

__END_DECLS
