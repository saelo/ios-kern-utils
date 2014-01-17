/*
 * kpatch.c - Apply patches to a running kenel.
 *
 * Copyright (c) 2014 Samuel Groß
 */

#include <stdio.h>
#include <string.h>

#include <sys/sysctl.h>     // sysctlbyname

#include <libkern.h>


int main(int argc, char** argv)
{
    vm_address_t kbase;

    if (argc < 2) {
        printf("Usage: kpatch new-uuid\n");
        return -1;
    }

    char uuid[0x50];
    size_t size = 0x50;
    memset(uuid, 0, size);
    int ret = sysctlbyname("kern.uuid", uuid, &size, NULL, 0);
    printf("[*] uuid: %s\n", uuid);

    if((kbase = get_kernel_base()) == 0) {
        printf("[!] failed to get the kernel base address");
        return -1;
    }

    vm_address_t uuid_addr = find_bytes(kbase, kbase + 0x1000000, (unsigned char*)uuid, strlen(uuid));
    if (uuid_addr == 0) {
        printf("[!] failed to find the uuid in kernel memory\n");
        return -1;
    }
    printf("[*] found uuid at 0x" ADDR "\n", uuid_addr);

    write_kernel(uuid_addr, (unsigned char*)argv[1], strlen(argv[1])+1);

    printf("[*] done, check \"sysctl kern.uuid\"\n");

    return 0;
}
