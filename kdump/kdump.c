/*
 * kdump.c - Kernel dumper code
 *
 * (c) 2014 Samuel Groß
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include <arch.h>

task_t kernel_task;

#define CHUNK_SIZE 0x500


vm_address_t get_kernel_base()
{
    kern_return_t ret;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned long depth = 0;
    vm_address_t addr = 0xffffff81200000;         // lowest possible kernel base address
                        

    printf("[*] retrieving kernel memory mappings...\n");
    while (1) {
        // get next memory region
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);

        if (ret != KERN_SUCCESS)
            break;

        // the kernel maps more than a GB of RAM at the address where it maps
        // itself so we use that to detect it's position

        if (size > 1024*1024*1024)
            return addr + 0x1000;       // kernel image is mapped at offset 0x1000


        addr += size;
    }

    return 0;
}

int main()
{
    kern_return_t ret;
    vm_address_t kbase;

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

    vm_size_t size;
    vm_address_t va;
    unsigned char buf[CHUNK_SIZE];

    FILE *f = fopen("kernel.bin", "wb");

    printf("[*] now dumping the kernel image...\n");
    for (va = kbase; va <= kbase + 0x1400000; va += CHUNK_SIZE) {
        // we just dump 20MB here
        size = CHUNK_SIZE;
        ret = vm_read_overwrite(kernel_task, va, size, (vm_address_t)buf, &size);
        if (ret != KERN_SUCCESS) {
            printf("[!] failed to read memory, dump may be incomplete...\n");
            break;
        }
        fwrite(buf, 1, size, f);
    }

    printf("[*] done\n");
    fclose(f);
    return 0;
}
