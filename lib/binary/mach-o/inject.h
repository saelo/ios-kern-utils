#pragma once
#include "binary.h"

addr_t b_allocate_vmaddr(const struct binary *binary);

// these two functions will modify binary->valid_range and trash everything else.
uint32_t b_macho_extend_cmds(struct binary *binary, size_t space);
// this function works for both the kernel and uselrand binaries.  for userland, pass NULL for find_hack_func.
void b_inject_macho_binary(struct binary *target, const struct binary *inject, addr_t (*find_hack_func)(const struct binary *binary), bool userland);

