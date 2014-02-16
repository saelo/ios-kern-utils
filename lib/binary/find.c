#include "find.h"
#include "binary.h"

// Various links:
// http://ridiculousfish.com/blog/archives/2006/05/30/old-age-and-treachery/
// http://www-igm.univ-mlv.fr/~lecroq/string/tunedbm.html#SECTION00195
// http://www-igm.univ-mlv.fr/~lecroq/string/node19.html#SECTION00190 (was using this)

static addr_t find_data_raw(range_t range, int16_t *buf, ssize_t pattern_size, size_t offset, int align, int options, const char *name) {
    int8_t ps = (int8_t) pattern_size;
    if(ps != pattern_size) {
        die("pattern too long");
    }
    // the problem with this is that it is faster to search for everything at once

    // reduce inefficiency
    for(int pos = pattern_size - 1; pos >= 0; pos--) {
        if(buf[pos] == -1) {
            pattern_size--;
        } else {
            break;
        }
    }
    int8_t table[256];
    for(int c = 0; c < 256; c++) {
        table[c] = ps;
    }
    for(int8_t pos = 0; pos < ps - 1; pos++) {
        if(buf[pos] == -1) {
            // Unfortunately, we can't put any character past being in this position...
            for(int i = 0; i < 256; i++) {
                table[i] = ps - pos - 1;
            }
        } else {
            table[buf[pos]] = ps - pos - 1;
        }
    }

    // this can't be -1 due to above
    int8_t shift = table[buf[pattern_size - 1]];
    table[buf[pattern_size - 1]] = 0;

    // now, for each c, let x be the last position in the string, other than the final position, where c might appear, or -1 if it doesn't appear anywhere; table[i] is size - x - 1.
    // so if we got c but no match, we can skip ahead by table[i]
    // updated
    buf += pattern_size - 1;
    addr_t foundit = 0;
    prange_t pr = rangeconv(range, MUST_FIND);
    uint8_t *start = pr.start + pattern_size - 1;
    uint8_t *end = pr.start + pr.size;
    uint8_t *cutoff = end - 400; // arbitrary
    uint8_t *cursor = start;

#define GUTS(keep_going) \
        { \
            for(int i = 0; i >= (-pattern_size + 1); i--) { \
                if(buf[i] != -1 && cursor[i] != buf[i]) { \
                    /* Not a match */ \
                    goto keep_going; \
                } \
            } \
            /* Whoa, we found it */ \
            addr_t new_match = cursor - start + range.start; \
            if(align && (new_match & (align - 1))) { \
                /* Just kidding. */ \
                goto keep_going; \
            } \
            if(foundit) { \
                die("found [%s] multiple times in range: first at %08llx then at %08llx", name, (uint64_t) foundit, (uint64_t) new_match); \
            } \
            foundit = new_match; \
            if(align) { \
                goto done; \
            } \
        } \
        /* otherwise, keep searching to make sure we won't find it again */ \
        keep_going: \
        cursor += shift;

    uint8_t jump;

    while(1) {
        if(cursor >= cutoff) break;
        do {
            jump = table[*cursor];
            cursor += jump;
            jump = table[*cursor];
            cursor += jump;
            jump = table[*cursor];
            cursor += jump;
            if(cursor >= end) goto done;
        } while(jump);
        GUTS(lbl1)
    }
    if(cursor >= end) goto done;
    while(1) {
        do {
            jump = table[*cursor];
            cursor += jump;
            if(cursor >= end) goto done;
        } while(jump);
        GUTS(lbl2)
    }
    done:
    if(foundit) {
        return foundit + offset;
    } else if(options & MUST_FIND) {
        die("didn't find [%s] in range (%08llx, %zx)", name, (uint64_t) range.start, range.size);
    } else {
        return 0;
    }
}

static void parse_pattern(const char *to_find, int16_t buf[128], ssize_t *pattern_size, ssize_t *offset) {
    *pattern_size = 0;
    *offset = 0;
    autofree char *to_find_ = strdup(to_find);
    while(to_find_) {
        char *bit = strsep(&to_find_, " ");
        if(!strcmp(bit, "-")) {
            *offset = *pattern_size;
            continue;
        } else if(!strcmp(bit, "+")) {
            *offset = *pattern_size + 1;
            continue;
        } else if(!strcmp(bit, "..")) {
            buf[*pattern_size] = -1;
        } else {
            char *endptr;
            buf[*pattern_size] = (int16_t) (strtol(bit, &endptr, 16) & 0xff);
            if(*endptr) {
                die("invalid bit %s in [%s]", bit, to_find);
            }
        }
        if(++*pattern_size >= 128) {
            die("pattern [%s] too big", to_find);
        }
    }
}

addr_t find_data(range_t range, const char *to_find, int align, int options) {
    int16_t buf[128];
    ssize_t pattern_size, offset;
    parse_pattern(to_find, buf, &pattern_size, &offset);
    return find_data_raw(range, buf, pattern_size, offset, align, options, to_find);
}

addr_t find_string(range_t range, const char *string, int align, int options) {
    size_t len = strlen(string);
    autofree int16_t *buf = malloc(sizeof(int16_t) * (len + 2));
    buf[0] = buf[len + 1] = 0;
    for(unsigned int i = 0; i < len; i++) {
        buf[i+1] = (uint8_t) string[i];
    }
    bool pz = options & PRECEDING_ZERO;
    bool tz = options & TRAILING_ZERO;
    addr_t result = find_data_raw(range, pz ? buf : buf + 1, len + tz + pz, pz ? 1 : 0, align, options, string);
    return result;
}

addr_t find_bytes(range_t range, const char *bytes, size_t len, int align, int options) {
    autofree int16_t *buf = malloc(sizeof(int16_t) * (len + 2));
    for(unsigned int i = 0; i < len; i++) {
        buf[i] = (uint8_t) bytes[i];
    }
    addr_t result = find_data_raw(range, buf, len, 0, align, options, "bytes");
    return result;
}
addr_t find_int32(range_t range, uint32_t number, int options) {
    prange_t pr = rangeconv(range, MUST_FIND);
    char *start = pr.start;
    char *end = pr.start + pr.size;
    for(char *p = start; p + 4 <= end; p++) {
        if(*((uint32_t *)p) == number) {
            return p - start + range.start;
        }
    }
    if(options & MUST_FIND) {
        die("didn't find %08x in range", number);
    } else {
        return 0;
    }
}

// search for push {..., lr}; add r7, sp, ...
// if is_thumb = 2, then search for both thumb and arm variants
addr_t find_bof(range_t range, addr_t eof, int is_thumb) {
    addr_t start = eof & ~1;
    if(start - range.start >= range.size) {
        die("out of range: %llx", (uint64_t) eof);
    }

    uint8_t *p = rangeconv(range, MUST_FIND).start + (start - range.start);
    addr_t addr = start;
    if(addr & 1) { p--; addr--; }
    for(p -= 8, addr -= 8; addr >= start - 0x1000 && addr >= range.start; p -= 2, addr -= 2) {
        if(p[1] == 0xb5 && p[3] == 0xaf && is_thumb != 0) {
            return addr | 1;
        } else if(p[2] == 0x2d && p[3] == 0xe9 &&
                  p[6] == 0x8d && p[7] == 0xe2 &&
                  is_thumb != 1 && !(addr & 2)) {
            return addr;
        }

    }
    die("couldn't find the beginning of %08llx", (uint64_t) eof);
}

uint32_t resolve_ldr(const struct binary *binary, addr_t addr) {
    uint32_t val = b_read32(binary, addr & ~1);
    addr_t target;
    if(addr & 1) {
        addr_t base = ((addr + 3) & ~3);
        if((val & 0xf800) == 0x4800) { // thumb
            target = base + ((val & 0xff) * 4);
        } else if((val & 0xffff) == 0xf8df) { // thumb-2
            target = base + ((val & 0x0fff0000) >> 16);
        } else {
            die("weird thumb instruction %08x at %08llx", val, (uint64_t) addr);
        }
    } else {
        addr_t base = addr + 8;
        if((val & 0x0fff0000) == 0x59f0000) { // arm
            target = base + (val & 0xfff);
        } else {
            die("weird ARM instruction %08x at %08llx", val, (uint64_t) addr);
        }
    }
    return b_read32(binary, target);
}

addr_t find_bl(range_t *range) {
    bool thumb = range->start & 1;
    range->start &= ~1;
    prange_t pr = rangeconv(*range, MUST_FIND);
    uint32_t diff;
    void *base;
    if(thumb) {
        uint16_t *p = pr.start;
        while((uintptr_t)(p + 2) <= (uintptr_t)pr.start + pr.size) {
            base = p;
            uint16_t val = *p++;
            if((val & 0xf800) == 0xf000) {
                uint32_t imm10 = val & 0x3ff;
                uint32_t S = ((val & 0x400) >> 10);
                uint16_t val2 = *p++;

                uint32_t J1 = ((val2 & 0x2000) >> 13);
                uint32_t J2 = ((val2 & 0x800) >> 11);
                uint32_t I1 = ~(J1 ^ S) & 1, I2 = ~(J2 ^ S) & 1;
                uint32_t imm11 = val2 & 0x7ff;
                diff = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);

                if((val2 & 0xd000) == 0xd000) {
                    // BL
                    diff |= 1;
                    goto ok;
                } else if((val2 & 0xd000) == 0xc000) {
                    // BLX
                    goto ok;
                }
            }
        }
    } else {
        uint32_t *p = pr.start;
        while((uintptr_t)(p + 1) <= (uintptr_t)pr.start + pr.size) {
            base = p;
            uint32_t val = *p++;
            if((val & 0xfe000000) == 0xfa000000) {
                // BL
                diff = ((val & 0xffffff) << 2);
                goto ok;
            } else if((val & 0x0f000000) == 0x0b000000) {
                // BLX
                diff = ((val & 0x1000000) >> 23) | ((val & 0xffffff) << 2) | 1;
                goto ok;
            }
        }
    }
    return 0;
    ok:;
    addr_t baseaddr = ((char *) base) - ((char *) pr.start) + range->start + 4;
    range->start = baseaddr + thumb;
    if(diff & 0x800000) diff |= 0xff000000;
    return baseaddr + diff;
}

#define unparen(args...) args
#define find_anywhere_func(name, args1, args2) \
addr_t b_find_##name##_anywhere(const struct binary *binary, unparen args1, int options) { \
    uint32_t end = binary->nsegments - 1; \
    for(uint32_t i = 0; i <= end; i++) { \
        range_t range = binary->segments[i].vm_range; \
        addr_t result = find_##name(range, unparen args2, i == end ? options : options & ~MUST_FIND); \
        if(result) return result; \
    } \
    return 0; /* won't reach */ \
}

find_anywhere_func(data, (const char *to_find, int align), (to_find, align))
find_anywhere_func(string, (const char *string, int align), (string, align))
find_anywhere_func(bytes, (const char *bytes, size_t len, int align), (bytes, len, align))
find_anywhere_func(int32, (uint32_t number), (number))

struct pattern {
    int16_t buf[128];
    ssize_t pattern_size, offset;
    const char *name;
    addr_t *result;
};

struct findmany {
    range_t range;
    int num_patterns;
    struct pattern *patterns;
};

struct findmany *findmany_init(range_t range) {
    struct findmany *fm = malloc(sizeof(*fm));
    fm->range = range;
    fm->num_patterns = 0;
    fm->patterns = NULL;
    return fm;
}

void findmany_add(addr_t *result, struct findmany *fm, const char *to_find) {
    if(fm->num_patterns >= 32) {
        die("too many patterns");
    }
    fm->num_patterns++;
    fm->patterns = realloc(fm->patterns, sizeof(struct pattern) * fm->num_patterns);
    struct pattern *pat = &fm->patterns[fm->num_patterns - 1];

    parse_pattern(to_find, pat->buf, &pat->pattern_size, &pat->offset);
    pat->name = to_find;
    pat->result = result;
    *result = 0;
}

struct node {
    uint16_t next[16];
    uint32_t terminates;
};

struct node2 {
    uint16_t next[16];
};

struct findmany2 {
    struct node *nodes;
    uint8_t *index_paths;
    uint16_t node_count;
    struct node2 *nodes2;
    uint16_t node2_count;
};

static inline int find_or_create(void **restrict array, void *restrict cmp, uint16_t *restrict num_items, int item_size, uint16_t *restrict node) {
    char *p = *array;
    for(int j = 0; j < *num_items; j++) {
        if(!memcmp(p, cmp, item_size)) {
            *node = j;
            return false;
        }
        p += item_size;
    }
    if(*num_items == 65535) {
        die("welp");
    }
    *node = *num_items;
    *array = realloc(*array, ++*num_items * item_size);
    memcpy(*array + *node * item_size, cmp, item_size);
    return true;
}

static uint16_t findmany_recurse(const struct findmany *restrict fm, struct findmany2 *restrict fm2, uint8_t *restrict cur_index_path) {
    // this part is inefficient
    uint16_t node;
    if(!find_or_create((void **) &fm2->index_paths, cur_index_path, &fm2->node_count, fm->num_patterns, &node)) {
        // it found an existing node
        return node;
    }
    /*
    printf("findmany_recurse: created node %d with cur_index_path = ", node);
    for(int p = 0; p < fm->num_patterns; p++) {
        printf(" %d", (int) cur_index_path[p]);
    }
    printf("\n");
    */
    memcpy(fm2->index_paths + node * fm->num_patterns, cur_index_path, fm->num_patterns);

    fm2->nodes = realloc(fm2->nodes, fm2->node_count * sizeof(struct node));
    struct node *nodep = &fm2->nodes[node];

    nodep->terminates = 0;
    for(int p = 0; p < fm->num_patterns; p++) {
        if(cur_index_path[p] == fm->patterns[p].pattern_size) {
            nodep->terminates |= (1 << p);
            cur_index_path[p] = 0;
        }
    }

    autofree uint8_t *new_index_path = malloc(fm->num_patterns);
    for(uint8_t hi = 0; hi < 16; hi++) {
        struct node2 n2;
        for(uint8_t lo = 0; lo < 16; lo++) {
            uint8_t chr = hi * 16 + lo;

            uint8_t orr = 0; // hack - a lot will point to 0

            for(int p = 0; p < fm->num_patterns; p++) {
                uint8_t idx = cur_index_path[p];
                int16_t comp = fm->patterns[p].buf[idx];
                if(comp == -1 || comp == chr) {
                    idx++;
                } else {
                    idx = 0;
                }
                new_index_path[p] = idx;
                orr |= idx;
            }

            n2.next[lo] = orr ? findmany_recurse(fm, fm2, new_index_path) : 0;
        }
        nodep = &fm2->nodes[node];
        find_or_create((void **) &fm2->nodes2, &n2, &fm2->node2_count, sizeof(struct node2), &nodep->next[hi]);
    }

    //printf("returning node %d\n", node);
    return node;
}

void findmany_go(struct findmany *fm) {
    struct findmany2 fm2;
    memset(&fm2, 0, sizeof(fm2));
    autofree uint8_t *cur_index_path = calloc(1, fm->num_patterns);
#ifdef PROFILING
    clock_t a = clock();
#endif
    findmany_recurse(fm, &fm2, cur_index_path);
#ifdef PROFILING
    clock_t b = clock();
    printf("it took %d clocks to prepare the DFA\n", (int) (b - a));
#endif

    prange_t pr = rangeconv(fm->range, MUST_FIND);
    uint8_t *start = pr.start;
    struct node *cur = &fm2.nodes[0];
    for(uint8_t *ptr = start; ptr < start + pr.size; ptr++) {
        uint8_t chr = *ptr;

        cur = &fm2.nodes[fm2.nodes2[cur->next[chr / 16]].next[chr % 16]];
        if(cur->terminates) {
            for(int p = 0, bit = 1; p < fm->num_patterns; p++, bit <<= 1) {
                if(cur->terminates & bit) {
                    struct pattern *pat = &fm->patterns[p];
                    addr_t result = ptr - pat->pattern_size - start + fm->range.start + 1;
                    if(*pat->result) {
                        die("found [%s] multiple times in range: first at %08llx then at %08llx", pat->name, (uint64_t) *pat->result, (uint64_t) result);
                    }
                    *pat->result = result + pat->offset;
                }

            }
        }
    }

    free(fm2.index_paths); // could be done earlier
    free(fm2.nodes);
    free(fm2.nodes2);

    for(int p = 0; p < fm->num_patterns; p++) {
        struct pattern *pat = &fm->patterns[p];
        if(!*pat->result) {
            die("didn't find [%s] in range(%llx, %zx)", pat->name, (uint64_t) fm->range.start, fm->range.size);
        }
    }

    free(fm->patterns);
    free(fm);
}
