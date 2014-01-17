/*
 * kpatch.c - Apply patches to a running kenel.
 *
 * Copyright (c) 2014 Samuel Groß
 */

#include <stdio.h>
#include <string.h>

#include <libkern.h>

// address UUID string on iPhone 4 7.0.4
#define KERN_UUID 0x345170


int main()
{
    vm_address_t kbase;

    char* data = "writing kernel memory is fun :)";

    if((kbase = get_kernel_base()) == 0) {
        printf("[!] failed to get the kernel base address");
        return -1;
    }

    write_kernel(kbase + KERN_UUID, (unsigned char*)data, strlen(data)+1);

    // now do a "sysctl kern.uuid"

    return 0;
}
