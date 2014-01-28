#include "binary.h"
#include "../mach-o/headers/loader.h"
#include "headers/dyld_cache_format.h"

#define downcast(val, typ) ({ typeof(val) v = (val); typ t = (typ) v; if(t != v) die("out of range %s", #val); t; })

void b_prange_load_dyldcache(struct binary *binary, prange_t pr, const char *name) {
#define _arg name

    binary->valid = true;
    binary->pointer_size = 4;
    binary->dyld = calloc(1, sizeof(*binary->dyld));
    binary->valid_range = pr;

    if(pr.size < sizeof(*binary->dyld->hdr)) {
        die("truncated (no room for dyld cache header)");
    }
    binary->dyld->hdr = pr.start;

    if(memcmp(binary->dyld->hdr->magic, "dyld_", 5)) {
        die("not a dyld cache");
    }
    char *thing = binary->dyld->hdr->magic + sizeof(binary->dyld->hdr->magic) - 7;
    if(!memcmp(thing, " armv7", 7)) {
        binary->cputype = CPU_TYPE_ARM;
        binary->cpusubtype = CPU_SUBTYPE_ARM_V7;
    } else if(!memcmp(thing, " armv6", 7)) {
        binary->cputype = CPU_TYPE_ARM;
        binary->cpusubtype = CPU_SUBTYPE_ARM_V6;
    } else {
        die("unknown processor in magic: %.6s", thing);
    }

    if(binary->dyld->hdr->mappingCount > 1000) {
        die("insane mapping count: %u", binary->dyld->hdr->mappingCount);
    }
    binary->nsegments = binary->dyld->hdr->mappingCount;
    binary->segments = malloc(sizeof(*binary->segments) * binary->nsegments);
    struct shared_file_mapping_np *mappings = rangeconv_off((range_t) {binary, binary->dyld->hdr->mappingOffset, binary->dyld->hdr->mappingCount * sizeof(struct shared_file_mapping_np)}, MUST_FIND).start;
    for(uint32_t i = 0; i < binary->dyld->hdr->mappingCount; i++) {
        struct data_segment *seg = &binary->segments[i];
        seg->vm_range.binary = seg->file_range.binary = binary;
        seg->native_segment = &mappings[i];
        seg->vm_range.start = downcast(mappings[i].sfm_address, addr_t);
        seg->file_range.start = downcast(mappings[i].sfm_file_offset, addr_t);
        seg->file_range.size = seg->vm_range.size = downcast(mappings[i].sfm_size, size_t);
    }

    
    for(unsigned int i = 0; i < binary->dyld->nmappings; i++) {
        struct shared_file_mapping_np *mapping = &binary->dyld->mappings[i];
        if(mapping->sfm_file_offset >= pr.size || mapping->sfm_size > pr.size - mapping->sfm_file_offset) {
            die("truncated (no room for dyld cache mapping %d)", i);
        }
    }
#undef _arg
}

void b_dyldcache_load_macho(const struct binary *binary, const char *filename, struct binary *out) {
    if(binary == out) {
        die("uck");
    }

    if(binary->dyld->hdr->imagesCount > 1000) {
        die("insane images count");
    }

    struct dyld_cache_image_info *info = rangeconv_off((range_t) {binary, binary->dyld->hdr->imagesOffset, binary->dyld->hdr->imagesCount * sizeof(*info)}, MUST_FIND).start;
    for(unsigned int i = 0; i < binary->dyld->hdr->imagesCount; i++) {
        char *name = rangeconv_off((range_t) {binary, info[i].pathFileOffset, 128}, MUST_FIND).start;

        if(strncmp(name, filename, 128)) {
            continue;
        }
        // we found it
        b_prange_load_macho(out, binary->valid_range,range_to_off_range((range_t) {binary, (uint32_t) info[i].address, 0}, MUST_FIND).start, filename);
        
        // look for reexports (maybe blowing the stack)
        int count = 0;
        CMD_ITERATE(b_mach_hdr(out), cmd) {
            if(cmd->cmd == LC_REEXPORT_DYLIB) count++;
        }
        if(count > 0 && count < 1000) {
            out->nreexports = (unsigned int) count;
            struct binary *p = out->reexports = malloc(out->nreexports * sizeof(struct binary));
            CMD_ITERATE(b_mach_hdr(out), cmd) {
                if(cmd->cmd == LC_REEXPORT_DYLIB) {
                    const char *name = convert_lc_str(cmd, ((struct dylib_command *) cmd)->dylib.name.offset);
                    b_dyldcache_load_macho(binary, name, p);
                    p++;
                }
            }
        }

        return;
    }
    die("couldn't find %s in dyld cache", filename);
}

void b_load_dyldcache(struct binary *binary, const char *filename) {
    return b_prange_load_dyldcache(binary, load_file(filename, true, NULL), filename);
}
