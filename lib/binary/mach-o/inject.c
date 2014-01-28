#include "inject.h"
#include "read_dyld_info.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/reloc.h"
#include <stddef.h>

addr_t b_allocate_vmaddr(const struct binary *binary) {
    addr_t max = 0;

    for(uint32_t i = 0; i < binary->nsegments; i++) {
        const range_t *range = &binary->segments[i].vm_range;
        addr_t newmax = range->start + range->size;
        if(newmax > max) max = newmax;
    }

    return (max + 0xfff) & ~0xfffu;
}

// this function is used by both b_macho_extend_cmds and b_inject_macho_binary
static void handle_retarded_dyld_info(void *ptr, uint32_t size, int num_segments, bool kill_dylibs, bool kill_dones) {
    // seriously, take a look at dyldinfo.cpp from ld64, especially, in this case, the separate handing of different LC_DYLD_INFO sections and the different meaning of BIND_OPCODE_DONE in lazy bind vs the other binds
    // not to mention the impossibility of reading this data without knowing every single opcode
    // and the lack of nop
    uint8_t flat_lookup = BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | (((uint8_t) BIND_SPECIAL_DYLIB_FLAT_LOOKUP) & ~BIND_OPCODE_MASK);
    void *end = ptr + size;
    while(ptr != end) { 
        uint8_t byte = read_int(&ptr, end, uint8_t);
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        switch(opcode){
        // things we actually care about:
        case BIND_OPCODE_DONE:
            if(kill_dones) {
                *((uint8_t *) ptr - 1) = BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER;
            }
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
            // update the segment number
            uint8_t *p = ptr - 1;
            //printf("incr'ing %u by %u\n", (unsigned int) immediate, (unsigned int) num_segments);
            *p = (*p & BIND_OPCODE_MASK) | (immediate + num_segments);
            read_uleb128(&ptr, end);
            break;
        }
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            if(kill_dylibs) {
                *((uint8_t *) ptr - 1) = flat_lookup;
            }
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
            void *start = ptr - 1;
            read_uleb128(&ptr, end);
            if(kill_dylibs) {
                memset(start, flat_lookup, ptr - start);
            }
            break;
        }
        // things we have to get through
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            ptr += strnlen(ptr, end - ptr);
            if(ptr == end) 
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB: // actually sleb (and I like how read_uleb128 and read_sleb128 in dyldinfo.cpp are completely separate functions), but read_uleb128 should work
        case BIND_OPCODE_ADD_ADDR_ULEB:
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            read_uleb128(&ptr, end);
            break;

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            read_uleb128(&ptr, end);
            read_uleb128(&ptr, end);
            break;
        }
    }
}


uint32_t b_macho_extend_cmds(struct binary *binary, size_t space) {
    size_t old_size = b_mach_hdr(binary)->sizeofcmds;
    size_t new_size = old_size + space;
    if((new_size >> 12) == (old_size >> 12)) {
        // good enough, it'll fit
        return (new_size + 0xfff) & ~0xfff;
    }

    // looks like we need to make a duplicate header and do ugly stuff
    size_t stuff_size = (sizeof(struct mach_header) + sizeof(struct segment_command) + sizeof(struct section) + new_size + 0xfff) & ~0xfff;

    #define X(a) if(a) a += stuff_size;
    CMD_ITERATE(b_mach_hdr(binary), cmd) {
        switch(cmd->cmd) {
        case LC_SEGMENT: {
            struct segment_command *seg = (void *) cmd;
            seg->fileoff += stuff_size;
            struct section *sect = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++, sect++) {
                sect->offset += stuff_size;
                X(sect->reloff)
            }
            break;
        }
        case LC_SYMTAB: {
            struct symtab_command *sym = (void *) cmd;
            X(sym->symoff)
            X(sym->stroff)
            break;
        }
        case LC_DYSYMTAB: {
            struct dysymtab_command *dys = (void *) cmd;
            X(dys->tocoff)
            X(dys->modtaboff)
            X(dys->extrefsymoff)
            X(dys->indirectsymoff)
            X(dys->extreloff)
            X(dys->locreloff)
            break;
        }
        case LC_TWOLEVEL_HINTS: {
            struct twolevel_hints_command *two = (void *) cmd;
            X(two->offset)
            break;
        }
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
        case 38 /*LC_FUNCTION_STARTS*/: {
            // this is sort of a best (but rather bad) guess - all three commands will probably be screwed up by being moved like this
            struct linkedit_data_command *dat = (void *) cmd;
            X(dat->dataoff)
            break;
        }
        case LC_ENCRYPTION_INFO: {
            struct encryption_info_command *enc = (void *) cmd;
            X(enc->cryptoff)
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            struct dyld_info_command *dyl = (void *) cmd;
            X(dyl->rebase_off)
            X(dyl->export_off)
            #define Y(a) if(dyl->a##_off) { \
                prange_t pr = rangeconv_off((range_t) {binary, dyl->a##_off, dyl->a##_size}, MUST_FIND); \
                handle_retarded_dyld_info(pr.start, pr.size, 1, false, false); \
                dyl->a##_off += stuff_size; \
            }
            Y(bind)
            Y(weak_bind)
            Y(lazy_bind)
            #undef Y
            break;
        }
        }
    }
    #undef X

    binary->valid_range = pdup(binary->valid_range, ((binary->valid_range.size + 0xfff) & ~0xfff) + stuff_size, stuff_size);
    struct mach_header *hdr = binary->valid_range.start;
    struct segment_command *seg = (void *) (hdr + 1);
    struct section *sect = (void *) (seg + 1);
    memcpy(hdr, binary->valid_range.start + stuff_size, sizeof(*hdr));
    memcpy(sect + 1, binary->valid_range.start + stuff_size + sizeof(struct mach_header), hdr->sizeofcmds);

    hdr->ncmds++;
    hdr->sizeofcmds += sizeof(*seg) + sizeof(*sect);

    seg->cmd = LC_SEGMENT;
    seg->cmdsize = sizeof(*seg) + sizeof(*sect);
    // yes, it MUST be called __TEXT.
    static const char segname[16] = "__TEXT";
    memcpy(seg->segname, segname, 16);
    seg->vmaddr = b_allocate_vmaddr(binary);
    seg->vmsize = stuff_size;
    seg->fileoff = 0;
    seg->filesize = stuff_size;
    seg->maxprot = seg->initprot = PROT_READ | PROT_EXEC;
    seg->nsects = 1;
    seg->flags = 0;

    // we need a section to make codesign_allocate happy
    static const char sectname[16] = "__useless";
    memcpy(sect->sectname, sectname, 16);
    memcpy(sect->segname, segname, 16);
    sect->addr = seg->vmaddr + stuff_size;
    sect->size = 0;
    sect->offset = stuff_size;
    sect->align = 0;
    sect->reloff = 0;
    sect->nreloc = 0;
    sect->flags = 0;
    sect->reserved1 = 0;
    sect->reserved2 = 0;

    return stuff_size - sizeof(struct mach_header);
}


// cctool's checkout.c insists on this exact order
enum {
    MM_BIND, MM_WEAK_BIND, MM_LAZY_BIND,
    MM_LOCREL,
    MM_SYMTAB,
    MM_LOCALSYM, MM_EXTDEFSYM, MM_UNDEFSYM,
    MM_EXTREL,
    MM_INDIRECT,
    MM_STRTAB,
    NMOVEME
};

struct linkedit_info {
    arange_t linkedit_range;
    void *linkedit_ptr;

    // things we need to move:
    // 0. string table
    // 1-3. {local, extdef, undef}sym
    // 4-5. {locrel, extrel}
    // 6. indirect syms
    // 7-9. dyld info {, weak_, lazy_}bind
    // [hey, I will just assume that nobody has any section relocations because it makes things simpler!]
    // things we need to update:
    // - symbols reference string table
    // - relocations reference symbols
    // - indirect syms reference symbols
    // - (section data references indirect syms)
    struct moveme {
        uint32_t *off, *size;
        uint32_t element_size;
        
        int off_base;

        void *copied_to;
        void *copied_from;
        uint32_t copied_size;
    } moveme[NMOVEME];

    struct symtab_command *symtab;
    struct dysymtab_command *dysymtab;
    struct dyld_info_command *dyld_info;
};

static const struct moveref {
    int target;
    ptrdiff_t offset;
} moveref[NMOVEME] = {
    [MM_LOCALSYM]  = {MM_STRTAB, offsetof(struct nlist, n_un.n_strx)},
    [MM_EXTDEFSYM] = {MM_STRTAB, offsetof(struct nlist, n_un.n_strx)},
    [MM_UNDEFSYM]  = {MM_STRTAB, offsetof(struct nlist, n_un.n_strx)},

              // hooray for little endian
    [MM_LOCREL]    = {MM_UNDEFSYM, 4},
    [MM_EXTREL]    = {MM_UNDEFSYM, 4},
              // the whole thing is a symbol number
    [MM_INDIRECT]  = {MM_UNDEFSYM, 0}
};

static bool catch_linkedit(struct mach_header *hdr, struct linkedit_info *li, bool patch) {
    memset(li, 0, sizeof(*li));
    bool ret = false;
    CMD_ITERATE(hdr, cmd) {
        restart:
        switch(cmd->cmd) {
        case LC_SEGMENT: {
            struct segment_command *seg = (void *) cmd;
            if(!strcmp(seg->segname, "__LINKEDIT")) {
                li->linkedit_range.start = seg->fileoff;
                li->linkedit_range.size = seg->filesize;
                ret = true;
                goto patchout;
                break;
            }

            break;
        }
        case LC_SYMTAB: {
            struct symtab_command *symtab = (void *) cmd;
            li->symtab = symtab;

            li->moveme[MM_STRTAB].off = &symtab->stroff;
            li->moveme[MM_STRTAB].size = &symtab->strsize;
            li->moveme[MM_STRTAB].element_size = 1;
            
            li->moveme[MM_SYMTAB].off = &symtab->symoff;
            li->moveme[MM_SYMTAB].size = &symtab->nsyms;
            li->moveme[MM_SYMTAB].element_size = sizeof(struct nlist);
            li->moveme[MM_SYMTAB].off_base = -1;

            break;
        }
        case LC_DYSYMTAB: {
            struct dysymtab_command *dys = (void *) cmd;
            li->dysymtab = dys;

            li->moveme[MM_LOCALSYM].off = &dys->ilocalsym;
            li->moveme[MM_LOCALSYM].size = &dys->nlocalsym;
            li->moveme[MM_LOCALSYM].element_size = sizeof(struct nlist);
            li->moveme[MM_LOCALSYM].off_base = MM_SYMTAB;

            li->moveme[MM_EXTDEFSYM].off = &dys->iextdefsym;
            li->moveme[MM_EXTDEFSYM].size = &dys->nextdefsym;
            li->moveme[MM_EXTDEFSYM].element_size = sizeof(struct nlist);
            li->moveme[MM_EXTDEFSYM].off_base = MM_SYMTAB;

            li->moveme[MM_UNDEFSYM].off = &dys->iundefsym;
            li->moveme[MM_UNDEFSYM].size = &dys->nundefsym;
            li->moveme[MM_UNDEFSYM].element_size = sizeof(struct nlist);
            li->moveme[MM_UNDEFSYM].off_base = MM_SYMTAB;

            li->moveme[MM_LOCREL].off = &dys->locreloff;
            li->moveme[MM_LOCREL].size = &dys->nlocrel;
            li->moveme[MM_LOCREL].element_size = sizeof(struct relocation_info);

            li->moveme[MM_EXTREL].off = &dys->extreloff;
            li->moveme[MM_EXTREL].size = &dys->nextrel;
            li->moveme[MM_EXTREL].element_size = sizeof(struct relocation_info);

            li->moveme[MM_INDIRECT].off = &dys->indirectsymoff;
            li->moveme[MM_INDIRECT].size = &dys->nindirectsyms;
            li->moveme[MM_INDIRECT].element_size = 4;

            break;
        }
        case LC_DYLD_INFO_ONLY:
        case LC_DYLD_INFO: {
            struct dyld_info_command *di = (void *) cmd;
            li->dyld_info = di;

            if(patch) {
                di->rebase_off = 0;
                di->rebase_size = 0;
                di->export_off = 0;
                di->export_size = 0;
            }

            li->moveme[MM_BIND].off = &di->bind_off;
            li->moveme[MM_BIND].size = &di->bind_size;
            li->moveme[MM_BIND].element_size = 1;

            li->moveme[MM_WEAK_BIND].off = &di->weak_bind_off;
            li->moveme[MM_WEAK_BIND].size = &di->weak_bind_size;
            li->moveme[MM_WEAK_BIND].element_size = 1;

            li->moveme[MM_LAZY_BIND].off = &di->lazy_bind_off;
            li->moveme[MM_LAZY_BIND].size = &di->lazy_bind_size;
            li->moveme[MM_LAZY_BIND].element_size = 1;
            break;
        }
        patchout:
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
        case 38 /*LC_FUNCTION_STARTS*/:
            // hope you didn't need that stuff <3
            if(patch) {
                hdr->sizeofcmds -= cmd->cmdsize;
                size_t copysize = hdr->sizeofcmds - ((char *) cmd - (char *) (hdr + 1));
                hdr->ncmds--;
                memcpy(cmd, (char *) cmd + cmd->cmdsize, copysize);
                // update this thing from the CMD_ITERATE macro
                end = (void *) (hdr + 1) + hdr->sizeofcmds;
                // don't run off the end
                if(!copysize) goto end;
                goto restart;
            }
            break;
        }
    }
    end:
    // we want both binaries to have a symtab and dysymtab, makes things easier
    if(!li->symtab || !li->dysymtab) die("symtab/dysymtab missing");
    return ret;
}

static void fixup_stub_helpers(int cputype, void *base, size_t size, uint32_t incr) {
    if(!size) return;
    size_t skip_begin, skip_end, offset, stride;
    switch(cputype) {
    case CPU_TYPE_ARM:
        skip_begin = 0x24;
        skip_end = 0;
        offset = 8;
        stride = 0xc;
        break;
    case CPU_TYPE_X86:
        skip_begin = 0;
        skip_end = 0xa;
        offset = 1;
        stride = 0xa;
        break;
    default:
        die("stub_helpers, but unknown cpu type");
    }
    if(size < (skip_begin + skip_end)) {
        die("unknown stub_helpers format (too small)");
    }
    base += skip_begin; size -= skip_begin;
    while(size >= skip_end + stride) {   
        *((uint32_t *) (base + offset)) += incr;
        base += stride; size -= stride;
    }
}

void b_inject_macho_binary(struct binary *target, const struct binary *binary, addr_t (*find_hack_func)(const struct binary *binary), bool userland) {
#define ADD_COMMAND(size) ({ \
        void *ret = (char *) hdr + sizeof(struct mach_header) + hdr->sizeofcmds; \
        uint32_t newsize = hdr->sizeofcmds + size; \
        if(newsize > sizeofcmds_limit) { \
            die("not enough space for commands"); \
        } \
        hdr->ncmds++; \
        hdr->sizeofcmds += (uint32_t) (size); \
        ret; \
    })

#define ADD_SEGMENT(size) ({ \
        uint32_t ret = (seg_off + 0xfff) & ~0xfff; \
        seg_off = ret + (size); \
        ret; \
    })

#define ADD_SEGMENT_ADDR(size) ({ \
        uint32_t ret = (seg_addr + 0xfff) & ~0xfff; \
        seg_addr = ret + (size); \
        ret; \
    })
        
    // the 0x100 is arbitrary, but intended to please codesign_allocate
    uint32_t sizeofcmds_limit = b_macho_extend_cmds(target, b_mach_hdr(binary)->sizeofcmds + 0x100);

    size_t seg_off = target->valid_range.size;
    addr_t seg_addr = 0;

    struct mach_header *hdr = b_mach_hdr(target);
    hdr->flags &= ~MH_PIE;

    const struct binary *binaries[] = {binary, target};
    
    // in userland mode, we cut off the LINKEDIT segment  (for target, only if it's at the end of the binary)
    struct linkedit_info li[2];
    if(userland) {
        for(int i = 0; i < 2; i++) { 
            if(catch_linkedit(b_mach_hdr(binaries[i]), &li[i], i == 1)) {
                li[i].linkedit_ptr = rangeconv_off((range_t) {binaries[i], li[i].linkedit_range.start, li[i].linkedit_range.size}, MUST_FIND).start;
            }
        }
        if((size_t) (li[1].linkedit_range.start + li[1].linkedit_range.size) == seg_off) {
            target->valid_range.size = seg_off = li[1].linkedit_range.start;
        }
        if((li[0].dyld_info != 0) != (li[1].dyld_info != 0)) {
            die("LC_DYLD_INFO(_ONLY) should be in both or neither");
        }
    }

    uint32_t init_ptrs[100];
    unsigned num_init_ptrs = 0;
    uint32_t *reserved1s[100];
    unsigned num_reserved1s = 0;
    struct copy { ptrdiff_t off; void *start; size_t size; } copies[100];
    unsigned num_copies = 0;

    unsigned num_segments = 0;
    if(userland) {
        CMD_ITERATE(hdr, cmd) {
            if(cmd->cmd == LC_SEGMENT) {
                num_segments++;
                struct segment_command *seg = (void *) cmd;
                struct section *sections = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++) {
                    struct section *sect = &sections[i];
                    switch(sect->flags & SECTION_TYPE) {
                    case S_NON_LAZY_SYMBOL_POINTERS:
                    case S_LAZY_SYMBOL_POINTERS:
                    case S_SYMBOL_STUBS:
                        if(num_reserved1s < 100) reserved1s[num_reserved1s++] = &sect->reserved1;
                        break;
                    }

                    if(li[0].dyld_info && !strcmp(sect->sectname, "__stub_helper")) {
                        void *segdata = rangeconv_off((range_t) {target, seg->fileoff, seg->filesize}, MUST_FIND).start;
                        fixup_stub_helpers(hdr->cputype, segdata + sect->offset - seg->fileoff, sect->size, *li[0].moveme[MM_LAZY_BIND].size);
                    }
                }
            }
        }
    }

    CMD_ITERATE(b_mach_hdr(binary), cmd) {
        switch(cmd->cmd) {
        case LC_SEGMENT: {
            struct segment_command *seg = (void *) cmd;

            if(userland && !strcmp(seg->segname, "__LINKEDIT")) continue;

            size_t size = sizeof(struct segment_command) + seg->nsects * sizeof(struct section);

            // make seg_addr useful
            addr_t new_addr = seg->vmaddr + seg->vmsize;
            if(new_addr > seg_addr) seg_addr = new_addr;

            struct segment_command *newseg = ADD_COMMAND(size);
            memcpy(newseg, seg, size);
            prange_t pr = rangeconv_off((range_t) {binary, seg->fileoff, seg->filesize}, MUST_FIND);

            newseg->fileoff = (uint32_t) ADD_SEGMENT(pr.size);
            //printf("setting fileoff to %u\n", newseg->fileoff);
            if(num_copies < 100) copies[num_copies++] = (struct copy) {newseg->fileoff, pr.start, pr.size};
            
            struct section *sections = (void *) (newseg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                sect->offset = newseg->fileoff + sect->addr - newseg->vmaddr;
                // ZEROFILL is okay because iBoot always zeroes vmsize - filesize
                if(!userland && (sect->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS) {
                    uint32_t *p = rangeconv_off((range_t) {binary, sect->offset, sect->size}, MUST_FIND).start;
                    size_t num = sect->size / 4;
                    while(num--) {
                        if(num_init_ptrs < 100) init_ptrs[num_init_ptrs++] = *p++;
                    }
                }
            }
            break;
        }
        case LC_LOAD_DYLIB:
            if(userland) {
                void *newcmd = ADD_COMMAND(cmd->cmdsize);
                memcpy(newcmd, cmd, cmd->cmdsize);
            }
            break;
        }
    }


    // now deal with the init pointers (if not userland)
    // this code is really gross
    if(num_init_ptrs > 0) {
        if(num_init_ptrs == 1) { // hey, correct plurals are nice
            fprintf(stderr, "note: 1 constructor function is present; using the hack_func\n");
        } else {
            fprintf(stderr, "note: %d constructor functions are present; using the hack_func\n", num_init_ptrs);
        }

        if(!find_hack_func) {
            die("...but there was no find_hack_func");
        }
        
        // ldr pc, [pc]
        uint16_t part0[] = {0xf8df, 0xf000};

        // push {r0-r3, lr}; adr lr, f+1; ldr pc, a; f: b next; a: .long 0; next:
        // (the address of the init func)
        // 
        uint16_t part1[] = {0xb50f, 0xf20f, 0x0e07, 0xf8df, 0xf004, 0xe001};
        // (bytes_to_move bytes of stuff)
        // pop {r0-r3, lr}
        static const uint16_t part2[] = {0xe8bd, 0x400f};
        // ldr pc, [pc]
        static const uint16_t part3[] = {0xf8df, 0xf000};

        uint32_t bytes_to_move = 12; // don't cut the MRC in two!

        addr_t hack_func = find_hack_func(target);
        fprintf(stderr, "hack_func = %08llx\n", (long long) hack_func);
        prange_t hack_func_pr = rangeconv((range_t) {target, hack_func & ~1, bytes_to_move}, MUST_FIND);

        // allocate a new segment for the stub

        uint32_t stub_size = (uint32_t) ((sizeof(part1) + 4) * num_init_ptrs + sizeof(part2) + bytes_to_move + sizeof(part3) + 4);

        if(!(hack_func & 1)) {
            die("hack func 0x%llx is not thumb", (uint64_t) hack_func);
        }

        struct segment_command *newseg = ADD_COMMAND(sizeof(struct segment_command));
        
        newseg->cmd = LC_SEGMENT;
        newseg->cmdsize = sizeof(struct segment_command);
        memset(newseg->segname, 0, 16);
        strcpy(newseg->segname, "__CRAP");
        newseg->vmaddr = ADD_SEGMENT_ADDR(stub_size);
        newseg->vmsize = stub_size;
        newseg->fileoff = ADD_SEGMENT(stub_size);
        newseg->filesize = stub_size;
        newseg->maxprot = newseg->initprot = PROT_READ | PROT_EXEC;
        newseg->nsects = 0;
        newseg->flags = 0;

        void *ptr = malloc(stub_size);
        for(unsigned i = 0; i < num_init_ptrs; i++) {
            memcpy(ptr, part1, sizeof(part1));
            ptr += sizeof(part1);
            memcpy(ptr, &init_ptrs[i], 4);
            ptr += 4;
            part1[0] = 0x46c0;
        }

        memcpy(ptr, part2, sizeof(part2));
        ptr += sizeof(part2);

        memcpy(ptr, hack_func_pr.start, bytes_to_move);
        ptr += bytes_to_move;
        
        memcpy(ptr, part3, sizeof(part3));
        ptr += sizeof(part3);

        uint32_t new_addr = hack_func + bytes_to_move;
        memcpy(ptr, &new_addr, 4);
        ptr += 4;
        
        new_addr = newseg->vmaddr | 1;
        memcpy(hack_func_pr.start, part0, sizeof(part0));
        memcpy(hack_func_pr.start + sizeof(part0), &new_addr, 4);

        if(num_copies < 100) copies[num_copies++] = (struct copy) {newseg->fileoff, ptr, stub_size};
    }

    autofree char *linkedit = NULL;

    if(userland) {
        // build the new LINKEDIT
        uint32_t newsize = 0;
        for(int i = 0; i < NMOVEME; i++) {
            for(int l = 0; l < 2; l++) {
                struct moveme *m = &li[l].moveme[i];
                if(!m->size) {
                    static uint32_t zero = 0;
                    m->size = m->off = &zero;
                    m->element_size = 1;
                }
                if(m->off_base != -1) {
                    newsize += *m->size * m->element_size;
                }
            }
        }

        if(newsize != 0) {
            uint32_t linkedit_off = ADD_SEGMENT(newsize);
            linkedit = malloc(newsize);
            uint32_t off = 0;
            
            for(int i = 0; i < NMOVEME; i++) {
                uint32_t s = 0;
                for(int l = 0; l < 2; l++) {
                    struct moveme *m = &li[l].moveme[i];
                    m->copied_size = *m->size * m->element_size;
                    m->copied_to = linkedit + off + s;
                    if(m->off_base > 0) {
                        // the value is an index into a table represented by another moveme (i.e. the symtab)
                        m->copied_from = li[l].moveme[m->off_base].copied_from + *m->off * m->element_size;
                    } else {
                        // the value is a file offset
                        // if 0, just plain copy; if -1, the references will handle copying
                        m->copied_from = li[l].linkedit_ptr - li[l].linkedit_range.start + *m->off;
                    }
                    if(m->off_base != -1) {
                        memcpy(m->copied_to, m->copied_from, m->copied_size);
                    }
                    s += m->copied_size;
                }
                //printf("i=%d s=%u off=%u\n", i, s, off);
                // update the one to load
                struct moveme *m = &li[1].moveme[i];
                *m->off = linkedit_off + off;
                if(m->off_base > 0) {
                    *m->off = (*m->off - *li[1].moveme[m->off_base].off) / m->element_size;
                }
                *m->size = s / m->element_size;

                if(m->off_base != -1) {
                    off += s;
                }
            }

            // update struct references (which are out of order, yay)
            off = 0;
            for(int i = 0; i < 2; i++) {
                for(int j = MM_LOCREL; j <= MM_INDIRECT; j++) {
                    int k = moveref[j].target;
                    if(!k) continue;

                    struct moveme *m = &li[i].moveme[j];
                    for(void *ptr = m->copied_to; ptr < m->copied_to + m->copied_size; ptr += m->element_size) {
                        uint32_t diff = 0;
                        int b = li[i].moveme[k].off_base;
                        if(b > 0) {
                            //    A1 A2 B1 B2 C1 C2
                            // 0: <--------->
                            // 1: <------------>
                            int orig_off = (li[i].moveme[k].copied_from - li[i].moveme[b].copied_from) / li[i].moveme[k].element_size;
                            int new_off = (li[i].moveme[k].copied_to - li[0].moveme[b].copied_to) / li[i].moveme[k].element_size;
                            diff = new_off - orig_off;
                        } else {
                            //    A   B
                            // 0: 
                            // 1: <->
                            if(i == 1) {
                                diff = li[0].moveme[k].copied_size / li[0].moveme[k].element_size;
                            }
                        }

                        uint32_t *p = ptr + moveref[j].offset;
                        if(*p < 0x10000000) *p += diff;
                    }
                }
            }
            
            // update library numbers in symbol table
            {
                struct moveme *restrict m = &li[0].moveme[MM_UNDEFSYM];
                for(struct nlist *nl = m->copied_to; (void *) (nl + 1) <= (m->copied_to + m->copied_size); nl++) {
                    unsigned lib = GET_LIBRARY_ORDINAL(nl->n_desc);
                    if(lib != SELF_LIBRARY_ORDINAL && lib <= MAX_LIBRARY_ORDINAL) {

                        SET_LIBRARY_ORDINAL(nl->n_desc, DYNAMIC_LOOKUP_ORDINAL);
                    }
                }
            }

            // ... and update section references
            for(unsigned i = 0; i < num_reserved1s; i++) {
                *reserved1s[i] += *li[0].moveme[MM_INDIRECT].size;
            }

            // ... and dyld info
            if(li->dyld_info) {
                for(int i = MM_BIND; i <= MM_LAZY_BIND; i++) {
                    if(*li[1].moveme[i].off) {
                        handle_retarded_dyld_info(linkedit - linkedit_off + *li[1].moveme[i].off, *li[0].moveme[i].size, num_segments, true, i != MM_LAZY_BIND);
                    }
                }
            }

            struct segment_command *newseg = ADD_COMMAND(sizeof(struct segment_command));
            newseg->cmd = LC_SEGMENT;
            newseg->cmdsize = sizeof(struct segment_command);
            memset(newseg->segname, 0, 16);
            strcpy(newseg->segname, "__LINKEDIT");
            newseg->vmaddr = ADD_SEGMENT_ADDR(newsize);
            newseg->vmsize = (newsize + 0xfff) & ~0xfff;
            newseg->fileoff = linkedit_off;
            newseg->filesize = newsize;
            newseg->maxprot = newseg->initprot = PROT_READ | PROT_WRITE;
            newseg->nsects = 0;
            newseg->flags = 0;

            //printf("off=%d newsize=%d\n", linkedit_off, newsize);
            if(num_copies < 100) copies[num_copies++] = (struct copy) {linkedit_off, linkedit, newsize};
        }
        
    }

    // finally, expand the binary in memory and actually copy in the new stuff
    target->valid_range = pdup(target->valid_range, seg_off, 0);
    for(unsigned i = 0; i < num_copies; i++) {
        memcpy(target->valid_range.start + copies[i].off, copies[i].start, copies[i].size);
    }
}

