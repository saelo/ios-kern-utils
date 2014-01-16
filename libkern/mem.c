/*
 * mem.c - Kernel memory related functions.
 *
 * Copyright (c) 2014 Samuel Groß
 */

#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include "libkern.h"

#define MAX_CHUNK_SIZE 0x500

vm_size_t read_kernel(vm_address_t addr, vm_size_t size, unsigned char* buf)
{
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size;
    vm_size_t bytes_read = 0;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS)
        return -1;

    vm_address_t end = addr + size;

    // reading memory in big chunks seems to cause problems, so
    // we are splitting it up into multiple smaller chunks here
    while (addr < end) {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;

        ret = vm_read_overwrite(kernel_task, addr, size, (vm_address_t)(buf + bytes_read), &size);
        if (ret != KERN_SUCCESS || size == 0)
            break;

        bytes_read += size;
        addr += size;
        remainder -= size;
    }

    return bytes_read;
}

vm_size_t write_kernel(vm_address_t addr, unsigned char* buf, vm_size_t size)
{
    kern_return_t ret;
    task_t kernel_task;
    vm_size_t remainder = size;
    vm_size_t bytes_written = 0;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS)
        return -1;

    vm_address_t end = addr + size;

    while (addr < end) {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;

        ret = vm_write(kernel_task, addr, (vm_offset_t)(buf + bytes_written), size);
        if (ret != KERN_SUCCESS)
            break;

        bytes_written += size;
        addr += size;
        remainder -= size;
    }

    return bytes_written;
}
