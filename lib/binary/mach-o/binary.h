#pragma once
#include "../binary.h"
#include "headers/loader.h"

#define CMD_ITERATE(hdr, cmd) \
    for(struct load_command *cmd = \
        (struct load_command *) ((uint32_t *) ((hdr) + 1) + (ADDR64 ? ((hdr)->magic & 1) : 0)), \
        *end = (struct load_command *) ((char *) cmd + (hdr)->sizeofcmds); \
        cmd < end; \
        cmd = (struct load_command *) ((char *) cmd + cmd->cmdsize))

#define LC_SEGMENT_X sizeof(_spec_LC_SEGMENT_X)
#define pointer_size_x sizeof(_spec_pointer_size_x)

#define _MACHO_SPECIALIZE(_LC_SEGMENT_X, _segment_command_x, _section_x, _nlist_x, _pointer_size_x, text...) { \
    typedef struct _segment_command_x segment_command_x; \
    typedef struct _section_x section_x; \
    typedef struct _nlist_x nlist_x; \
    typedef char _spec_LC_SEGMENT_X[_LC_SEGMENT_X]; \
    typedef char _spec_pointer_size_x[_pointer_size_x]; \
    text \
}
#define _MACHO_SPECIALIZE_64(text...) _MACHO_SPECIALIZE(LC_SEGMENT_64, segment_command_64, section_64, nlist_64, 8, text)
#define _MACHO_SPECIALIZE_32(text...) _MACHO_SPECIALIZE(LC_SEGMENT, segment_command, section, nlist, 4, text)
#if ADDR64
#define MACHO_SPECIALIZE(text...) _MACHO_SPECIALIZE_64(text) _MACHO_SPECIALIZE_32(text)
#define MACHO_SPECIALIZE_POINTER_SIZE(binary, text...) \
    if(b_pointer_size(binary) == 8) _MACHO_SPECIALIZE_64(text) else _MACHO_SPECIALIZE_32(text)
#else
#define MACHO_SPECIALIZE(text...) _MACHO_SPECIALIZE_32(text)
#define MACHO_SPECIALIZE_POINTER_SIZE(binary, text...) _MACHO_SPECIALIZE_32(text)
#endif

struct mach_binary {
    // this is unnecessary, don't use it
    struct mach_header *hdr;

    // this stuff is _all_ symbols...
    void *symtab; // either nlist or nlist_64
    uint32_t nsyms;

    // for b_sym (external stuff)
    struct nlist *ext_symtab, *imp_symtab;
    uint32_t ext_nsyms, imp_nsyms;

    // alternatively
    struct dyld_info_command *dyld_info;
    prange_t export_trie;
    addr_t export_baseaddr;

    char *strtab;
    uint32_t strsize;
    const struct dysymtab_command *dysymtab;
};

__BEGIN_DECLS

static inline struct mach_header *b_mach_hdr(const struct binary *binary) {
    return (struct mach_header *) ((char *) binary->valid_range.start + binary->header_offset);
}

__attribute__((pure)) range_t b_macho_segrange(const struct binary *binary, const char *segname);
__attribute__((pure)) range_t b_macho_sectrange(const struct binary *binary, const char *segname, const char *sectname);

void b_prange_load_macho(struct binary *binary, prange_t range, size_t offset, const char *name);
void b_prange_load_macho_nosyms(struct binary *binary, prange_t range, size_t offset, const char *name);

void b_load_macho(struct binary *binary, const char *filename);

void *b_macho_nth_symbol(const struct binary *binary, uint32_t n);

addr_t b_macho_reloc_base(const struct binary *binary);

const char *convert_lc_str(const struct load_command *cmd, uint32_t offset);

__END_DECLS
