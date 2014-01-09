/*
 * kmap.c - Display a listing of the kernel memory mappings.
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

int main()
{
    kern_return_t ret;
    task_t kernel_task;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS) {
        printf("[!] failed to get access to the kernel task");
        return -1;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x80000000;
    size_t displaysize;
    char scale;
    char curR, curW, curX, maxR, maxW, maxX;

    while (1) {
        // get next memory region
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        if (ret != KERN_SUCCESS) {
            break;
        }

        // size
        scale = 'K';
        displaysize = size / 1024;
        if (displaysize > 99999) {
            scale = 'M';
            displaysize /= 1024;
        }

        // protection
        curR = (info.protection) & VM_PROT_READ ? 'r' : '-';
        curW = (info.protection) & VM_PROT_WRITE ? 'w' : '-';
        curX = (info.protection) & VM_PROT_EXECUTE ? 'x' : '-';
        maxR = (info.max_protection) & VM_PROT_READ ? 'r' : '-';
        maxW = (info.max_protection) & VM_PROT_WRITE ? 'w' : '-';
        maxX = (info.max_protection) & VM_PROT_EXECUTE ? 'x' : '-';

        printf("%08x-%08x [%5zu%c] %c%c%c/%c%c%c\n", 
               addr, addr+size, displaysize, scale, 
               curR, curW, curX, maxR, maxW, maxX); 
        
        addr += size;
    }

    return 0;
}
