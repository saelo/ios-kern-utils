#include "link.h"
#include "headers/loader.h"
#include "headers/nlist.h"
#include "headers/reloc.h"
#include "headers/arm_reloc.h"
#include <ctype.h>
#include "read_dyld_info.h"

static addr_t lookup_symbol_or_do_stuff(lookupsym_t lookup_sym, void *context, const char *name, bool weak, bool userland) {
    addr_t sym = lookup_sym(context, name);
    if(!sym) {
        if(userland) {
            // let it pass
        } else if(!strcmp(name, "dyld_stub_binder")) {
            sym = 0xdeadbeef;
        } else if(weak) {
            fprintf(stderr, "lookup_nth_symbol: warning: couldn't find weak symbol %s\n", name);
        } else {
            die("couldn't find symbol %s\n", name);
        }
    }
    return sym;
}

static addr_t lookup_nth_symbol(const struct binary *load, uint32_t symbolnum, lookupsym_t lookup_sym, void *context, bool userland) {
    struct nlist *nl = b_macho_nth_symbol(load, symbolnum);
    bool weak = nl->n_desc & N_WEAK_REF;
    const char *name = load->mach->strtab + nl->n_un.n_strx;
    return lookup_symbol_or_do_stuff(lookup_sym, context, name, weak, userland);
}

static void relocate_area(struct binary *load, uint32_t reloff, uint32_t nreloc, enum reloc_mode mode, lookupsym_t lookup_sym, void *context, addr_t slide) {
    struct relocation_info *things = rangeconv_off((range_t) {load, reloff, nreloc * sizeof(struct relocation_info)}, MUST_FIND).start;
    for(uint32_t i = 0; i < nreloc; i++) {
        if(things[i].r_length != 2) {
            die("bad relocation length");
        }
        addr_t address = things[i].r_address;
        if(address == 0 || things[i].r_symbolnum == R_ABS) continue;
        address += b_macho_reloc_base(load);
        uint32_t *p = rangeconv((range_t) {load, address, 4}, MUST_FIND).start;

        addr_t value;
        if(things[i].r_extern) {
            if(mode == RELOC_LOCAL_ONLY) continue;
            value = lookup_nth_symbol(load, things[i].r_symbolnum, lookup_sym, context, mode == RELOC_USERLAND);
            if(value == 0 && mode == RELOC_USERLAND) continue;
        } else {
            if(mode == RELOC_EXTERN_ONLY || mode == RELOC_USERLAND) continue;
            // *shrug*
            value = slide;
        }

        things[i].r_address = 0;
        things[i].r_symbolnum = R_ABS;

        if(mode == RELOC_EXTERN_ONLY && things[i].r_type != ARM_RELOC_VANILLA) {
            die("non-VANILLA relocation but we are relocating without knowing the slide; use __attribute__((long_call)) to get rid of these");
        }
        switch(things[i].r_type) {
        case ARM_RELOC_VANILLA:
            //printf("%x, %x += %x\n", address, *p, value); 
            if(rangeconv((range_t) {load, *p, 0}, 0).start) {
                // when dyld_stub_binding_helper (which would just crash, btw) is present, entries in the indirect section point to it; usually this increments to point to the right dyld_stub_binding_helper, then that's clobbered by the indirect code.  when we do prelinking, the indirect code runs first and we would be relocating the already-correctly-located importee symbol, so we add this check (easier than actually checking that it's not in the indirect section) to make sure we're not relocating nonsense.
                *p += value;
            }
            //else printf("skipping %x\n", *p);
            break;
        case ARM_RELOC_BR24: {
            if(!things[i].r_pcrel) die("weird relocation");
            uint32_t ins = *p;
            uint32_t off = ins & 0x00ffffff;
            if(ins & 0x00800000) off |= 0xff000000;
            off <<= 2;
            off += (value - slide);
            if((off & 0xfc000000) != 0 &&
               (off & 0xfc000000) != 0xfc000000) {
                die("BR24 relocation out of range");
            }
            uint32_t cond = ins >> 28;
            if(value & 1) {
                if(cond != 0xe && cond != 0xf) die("can't convert BL with condition to BLX (which must be unconditional)");
                ins = (ins & 0x0effffff) | 0xf0000000 | ((off & 2) << 24);
            } else if(cond == 0xf) {
                ins = (ins & 0x0fffffff) | 0xe0000000;
            }

            ins = (ins & 0xff000000) | ((off >> 2) & 0x00ffffff);
            *p = ins;
            break;
        }
        default:
            die("unknown relocation type %d", things[i].r_type);
        }

    }
}

static void go_indirect(struct binary *load, uint32_t offset, uint32_t size, uint32_t flags, uint32_t reserved1, uint32_t reserved2, enum reloc_mode mode, lookupsym_t lookup_sym, void *context, addr_t slide) {
    uint8_t type = flags & SECTION_TYPE;
    uint8_t pointer_size = b_pointer_size(load);
    switch(type) {
    case S_NON_LAZY_SYMBOL_POINTERS:
    case S_LAZY_SYMBOL_POINTERS: {
        uint32_t indirect_table_offset = reserved1;
        const struct dysymtab_command *dysymtab = load->mach->dysymtab;
        

        uint32_t stride = type == S_SYMBOL_STUBS ? reserved2 : pointer_size;
        uint32_t num_syms = size / stride;

        if(stride < pointer_size ||
           num_syms * stride != size ||
           dysymtab->nindirectsyms > ((addr_t) -(dysymtab->indirectsymoff - 1)) / sizeof(uint32_t) ||
           indirect_table_offset > dysymtab->nindirectsyms ||
           num_syms > dysymtab->nindirectsyms - indirect_table_offset) {
           die("bad indirect section");
        }
        
        uint32_t *indirect_syms = rangeconv_off((range_t) {load, (addr_t) dysymtab->indirectsymoff + indirect_table_offset * sizeof(uint32_t), num_syms * sizeof(uint32_t)}, MUST_FIND).start;
        void *addrs = rangeconv_off((range_t) {load, offset, size}, MUST_FIND).start;
        for(uint32_t i = 0; i < num_syms; i++, indirect_syms++, addrs += stride) {
            addr_t addr, found_addr;

            switch(*indirect_syms) {
            case INDIRECT_SYMBOL_LOCAL:
                if(mode == RELOC_EXTERN_ONLY || mode == RELOC_USERLAND) continue;
                addr = read_pointer(addrs, pointer_size) + slide;
                break;
            case INDIRECT_SYMBOL_ABS:
                continue;
            default:
                if(mode == RELOC_LOCAL_ONLY) continue;
                found_addr = lookup_nth_symbol(load, *indirect_syms, lookup_sym, context, mode == RELOC_USERLAND);
                if(!found_addr && mode == RELOC_USERLAND) {
                    // don't set to ABS! 
                    continue;
                }

                addr = found_addr;
                break;
            }

            write_pointer(addrs, addr, pointer_size);
            *indirect_syms = INDIRECT_SYMBOL_ABS;
        }
        break;
    }
    case S_ZEROFILL:
    case S_MOD_INIT_FUNC_POINTERS:
    case S_MOD_TERM_FUNC_POINTERS:
    case S_REGULAR:
    case S_CSTRING_LITERALS:
    case S_4BYTE_LITERALS:
    case S_8BYTE_LITERALS:
    case S_16BYTE_LITERALS:
        break;
    default:
        if(mode != RELOC_USERLAND) {
            die("unrecognized section type %02x", type);
        }
    }
    
}

static void relocate_with_symtab(struct binary *load, enum reloc_mode mode, lookupsym_t lookup_sym, void *context, addr_t slide) {
    if(mode != RELOC_EXTERN_ONLY && mode != RELOC_USERLAND) {
        relocate_area(load, load->mach->dysymtab->locreloff, load->mach->dysymtab->nlocrel, mode, lookup_sym, context, slide);
    }
    if(mode != RELOC_LOCAL_ONLY) {
        relocate_area(load, load->mach->dysymtab->extreloff, load->mach->dysymtab->nextrel, mode, lookup_sym, context, slide);
    }

    CMD_ITERATE(b_mach_hdr(load), cmd) {
        MACHO_SPECIALIZE(
            if(cmd->cmd == LC_SEGMENT_X) {
                segment_command_x *seg = (void *) cmd;
                //printf("%.16s %08x\n", seg->segname, seg->vmaddr);
                section_x *sect = (void *) (seg + 1);
                for(uint32_t i = 0; i < seg->nsects; i++, sect++) {
                    //printf("   %.16s\n", sect->sectname);
                    go_indirect(load, sect->offset, sect->size, sect->flags, sect->reserved1, sect->reserved2, mode, lookup_sym, context, slide);
                    relocate_area(load, sect->reloff, sect->nreloc, mode, lookup_sym, context, slide);
                }
            }
        )
    }

}

static void do_bind_section(prange_t opcodes, struct binary *load, bool weak, bool userland, lookupsym_t lookup_sym, void *context) {
    uint8_t pointer_size = b_pointer_size(load);

    uint8_t symbol_flags;
    char *sym = NULL;
    uint8_t type = BIND_TYPE_POINTER;
    addr_t addend = 0;
    prange_t segment = {NULL, 0};
    addr_t segaddr = 0;
    addr_t offset = 0;

    void *ptr = opcodes.start, *end = ptr + opcodes.size;
    while(ptr != end) {
        void *orig_ptr = ptr;
        uint8_t byte = read_int(&ptr, end, uint8_t);
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        uint8_t opcode = byte & BIND_OPCODE_MASK;

        addr_t count, stride;

        switch(opcode) {
        case BIND_OPCODE_DONE:
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            // do nothing
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&ptr, end);
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym = read_cstring(&ptr, end);
            symbol_flags = immediate;
            break;
        case BIND_OPCODE_SET_TYPE_IMM:
            type = immediate;
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(&ptr, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            if(immediate >= load->nsegments) {
                die("segment too high");
            }
            segment = rangeconv_off(load->segments[immediate].file_range, MUST_FIND);
            segaddr = load->segments[immediate].vm_range.start;
            offset = read_uleb128(&ptr, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            {
            addr_t o = read_uleb128(&ptr, end);
            offset += o;
            }
            break;
        case BIND_OPCODE_DO_BIND:
            count = 1;
            stride = pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            count = 1;
            stride = read_uleb128(&ptr, end) + pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            count = 1;
            stride = immediate * pointer_size + pointer_size;
            goto bind;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = read_uleb128(&ptr, end);
            stride = read_uleb128(&ptr, end) + pointer_size;
            goto bind;
        bind: {
            if(!sym || !segment.start) die("improper bind");
            bool _64b;
            addr_t value;


            value = lookup_symbol_or_do_stuff(lookup_sym, context, sym, weak, userland);
            if(!value) {
                offset += stride * count;
                break;
            }
            value += addend;
            switch(type) {
            case BIND_TYPE_POINTER:
                _64b = pointer_size == 8;
                break;
            case BIND_TYPE_TEXT_ABSOLUTE32:
                _64b = false;
                break;
            case BIND_TYPE_TEXT_PCREL32:
                _64b = false;
                value = -value + (segaddr + offset + 4);
                break;
            default:
                die("bad bind type %d", (int) type);
            }
            
            if(offset >= segment.size ||
               stride < (_64b ? sizeof(uint64_t) : sizeof(uint32_t)) ||
               (segment.size - offset) / stride < count) {
               die("bad address while binding");
            }

            while(count--) {
                if(_64b) {
                    *((uint64_t *) (segment.start + offset)) = value;
                } else {
                    *((uint32_t *) (segment.start + offset)) = value;
                }

                offset += stride;
                if(type == BIND_TYPE_TEXT_PCREL32) value += stride;
            }

            memset(orig_ptr, BIND_OPCODE_SET_TYPE_IMM, ptr - orig_ptr);
            type = BIND_TYPE_POINTER;
            break;    
        }
        default:
            die("unknown bind opcode 0x%x", (int) opcode);
        }
    }
}

static void do_rebase(struct binary *load, prange_t opcodes, addr_t slide) {
    uint8_t pointer_size = b_pointer_size(load);
    uint8_t type = REBASE_TYPE_POINTER;
    addr_t offset = 0;
    prange_t segment = {NULL, 0};

    void *ptr = opcodes.start, *end = ptr + opcodes.size;
    while(ptr != end) {
        uint8_t byte = read_int(&ptr, end, uint8_t);
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;
        uint8_t opcode = byte & BIND_OPCODE_MASK;

        addr_t count, stride;

        switch(opcode) {
        // this code is very similar to do_bind_section
        case REBASE_OPCODE_DONE:
            return;
        case REBASE_OPCODE_SET_TYPE_IMM:
            type = immediate;
            break;
        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            if(immediate >= load->nsegments) {
                die("segment too high");
            }
            segment = rangeconv_off(load->segments[immediate].file_range, MUST_FIND);
            offset = read_uleb128(&ptr, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_ULEB:
            offset += read_uleb128(&ptr, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            offset += immediate * pointer_size;
            break;
        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            count = immediate;
            stride = pointer_size;
            goto rebase;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
            count = read_uleb128(&ptr, end);
            stride = pointer_size;
            goto rebase;
        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            count = 1;
            stride = read_uleb128(&ptr, end) + pointer_size;
            goto rebase;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
            count = read_uleb128(&ptr, end);
            stride = read_uleb128(&ptr, end) + pointer_size;
            goto rebase;
        rebase: {
            bool _64b;
            switch(type) {
            case REBASE_TYPE_POINTER:
                _64b = pointer_size == 8;
                break;
            case REBASE_TYPE_TEXT_ABSOLUTE32:
            case REBASE_TYPE_TEXT_PCREL32:
                _64b = false;
                break;
            default:
                die("bad rebase type %d", (int) type);
            }

            if(offset >= segment.size || (segment.size - offset) / stride < count) {
               die("bad address while rebasing");
            }

            while(count--) {
                if(_64b) {
                    *((uint64_t *) (segment.start + offset)) += slide;
                } else {
                    uint32_t *ptr = segment.start + offset;
                    *ptr += slide;
                    if(type == REBASE_TYPE_TEXT_PCREL32) {
                        // WTF!?  This is actually what dyld does.
                        *ptr = -*ptr;
                    }
                }

                offset += stride;
            }
            break;
        }
        default:
            die("unknown rebase opcode 0x%x", (int) opcode);
        }
    }
}

static void relocate_with_dyld_info(struct binary *load, enum reloc_mode mode, lookupsym_t lookup_sym, void *context, addr_t slide) {
    // It gets more complicated
    struct dyld_info_command *dyld_info = load->mach->dyld_info;
    #define fetch(type) prange_t type = dyld_info->type##_off ? rangeconv_off((range_t) {load, dyld_info->type##_off, dyld_info->type##_size}, MUST_FIND) : (prange_t) {NULL, 0};

    if(mode != RELOC_EXTERN_ONLY && slide != 0) {
        fetch(rebase)
        do_rebase(load, rebase, slide);
        dyld_info->rebase_size = 0;
    }

    if(mode != RELOC_LOCAL_ONLY) {
        fetch(bind)
        fetch(weak_bind)
        fetch(lazy_bind)
        bool userland = mode == RELOC_USERLAND;
        do_bind_section(bind, load, userland, userland, lookup_sym, context);
        do_bind_section(weak_bind, load, true, userland, lookup_sym, context);
        do_bind_section(lazy_bind, load, userland, userland, lookup_sym, context);
    }
}

void b_relocate(struct binary *load, const struct binary *target, enum reloc_mode mode, lookupsym_t lookup_sym, void *context, addr_t slide) {
    if(mode == RELOC_USERLAND && slide != 0) {
        die("sliding is not supported in userland mode");
    }

    if(!load->mach->symtab || !load->mach->dysymtab) {
        die("no LC_SYMTAB/LC_DYSYMTAB");
    }

    // check for overlap
    if(target) {
        for(uint32_t i = 0; i < load->nsegments; i++) {
            struct data_segment *a = &load->segments[i];
            for(uint32_t j = 0; j < target->nsegments; j++) {
                struct data_segment *b = &target->segments[j];
                addr_t diff = b->vm_range.start - (a->vm_range.start + slide);
                if(diff < a->vm_range.size || -diff < b->vm_range.size) {
                    die("segments of load and target overlap; load:%llx+%zu target:%llx+%zu", (uint64_t) a->vm_range.start, a->vm_range.size, (uint64_t) b->vm_range.start, b->vm_range.size);
                }
            }
        }
    }
    
    (load->mach->dyld_info ? relocate_with_dyld_info : relocate_with_symtab)(load, mode, lookup_sym, context, slide);
    
    if(mode != RELOC_EXTERN_ONLY && slide != 0) {
        CMD_ITERATE(b_mach_hdr(load), cmd) {
            MACHO_SPECIALIZE(
                if(cmd->cmd == LC_SEGMENT_X) {
                    segment_command_x *seg = (void *) cmd;
                    section_x *sect = (void *) (seg + 1);
                    seg->vmaddr += slide;
                    for(uint32_t i = 0; i < seg->nsects; i++, sect++) {
                        sect->addr += slide;
                    }
                }
            )
        }
    }
}

