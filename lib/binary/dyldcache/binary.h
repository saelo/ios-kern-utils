#pragma once
#include "../binary.h"
#include "../mach-o/binary.h"

struct dyldcache_binary {
    struct dyld_cache_header *hdr;
    struct shared_file_mapping_np *mappings;
    uint32_t nmappings;
    struct shared_file_mapping_np *last_sfm;
};

__BEGIN_DECLS

void b_prange_load_dyldcache(struct binary *binary, prange_t range, const char *name);
void b_dyldcache_load_macho(const struct binary *binary, const char *filename, struct binary *out);

void b_load_dyldcache(struct binary *binary, const char *filename);


__END_DECLS
