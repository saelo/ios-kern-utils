/*
 * kdump.c - Kernel dumper code
 *
 * Copyright (c) 2014 Samuel Groß
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach_init.h>
#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include <libkern.h>
#include <mach-o/binary.h>

#define KERNEL_SIZE 0x1800000
#define HEADER_SIZE 0x1000

#define max(a, b) (a) > (b) ? (a) : (b)

int main()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_address_t kbase;
    unsigned char buf[HEADER_SIZE];      // will hold the original mach-o header and load commands
    unsigned char header[HEADER_SIZE];   // header for the new mach-o file
    unsigned char* binary;               // mach-o will be reconstructed in here
    FILE* f;
    size_t filesize = 0;
#if __LP64__
    struct segment_command_64* seg;
    struct mach_header_64* orig_hdr = (struct mach_header_64*)buf;
    struct mach_header_64* hdr = (struct mach_header_64*)header;
#else
    struct segment_command* seg;
    struct mach_header* orig_hdr = (struct mach_header*)buf;
    struct mach_header* hdr = (struct mach_header*)header;
#endif

    memset(header, 0, HEADER_SIZE);

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS) {
        printf("[!] failed to get access to the kernel task");
        return -1;
    }

    if ((kbase = get_kernel_base()) == 0) {
        printf("[!] could not find kernel base address\n");
        return -1;
    }
    printf("[*] found kernel base at address 0x" ADDR "\n", kbase);

    f = fopen("kernel.bin", "wb");
    binary = calloc(1, KERNEL_SIZE);            // too large for the stack

    printf("[*] reading kernel header...\n");
    read_kernel(kbase, HEADER_SIZE, buf);
    memcpy(hdr, orig_hdr, sizeof(*hdr));
    hdr->ncmds = 0;
    hdr->sizeofcmds = 0;

    /*
     * We now have the mach-o header with the LC_SEGMENT
     * load commands in it.
     * Next we are going to redo the loading process,
     * parse each load command and read the data from
     * vmaddr into fileoff.
     * Some parts of the mach-o can not be restored (e.g. LC_SYMTAB).
     * The load commands for these parts will be removed from the final
     * executable.
     */
    printf("[*] restoring segments...\n");
    CMD_ITERATE(orig_hdr, cmd) {
        switch(cmd->cmd) {
        case LC_SEGMENT:
        case LC_SEGMENT_64: {
            #if __LP64__
            seg = (struct segment_command_64*)cmd;
            #else
            seg = (struct segment_command*)cmd;
            #endif
            printf("[+] found segment %s\n", seg->segname);
            read_kernel(seg->vmaddr, seg->filesize, binary + seg->fileoff);
            filesize = max(filesize, seg->fileoff + seg->filesize);
        }
        case LC_UUID:
        case LC_UNIXTHREAD:
        case 0x25:
        case 0x2a:
        case 0x26:
            memcpy(header + sizeof(*hdr) + hdr->sizeofcmds, cmd, cmd->cmdsize);
            hdr->sizeofcmds += cmd->cmdsize;
            hdr->ncmds++;
            break;
        }
    }

    // now replace the old header with the new one ...
    memcpy(binary, header, sizeof(*hdr) + orig_hdr->sizeofcmds);

    // ... and write the final binary to file
    fwrite(binary, filesize, 1, f);

    printf("[*] done, wrote 0x%lx bytes\n", filesize);
    fclose(f);
    free(binary);
    return 0;
}
