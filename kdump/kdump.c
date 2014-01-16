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

// just dump 20MB for now
#define DUMP_SIZE 0x1400000

int main()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_address_t kbase;
    unsigned char* buf = malloc(DUMP_SIZE);     // buffer is too big for the stack...

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

    FILE *f = fopen("kernel.bin", "wb");

    printf("[*] now dumping the kernel image...\n");
    size_t size = read_kernel(kbase, DUMP_SIZE, buf);
    fwrite(buf, 1, size, f);

    printf("[*] done, read 0x%lx bytes\n", size);
    fclose(f);
    free(buf);
    return 0;
}
