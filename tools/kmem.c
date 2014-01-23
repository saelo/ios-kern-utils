/*
 * kmem.c - Read kernel memory and dump it to the console.
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

void hexdump(unsigned char *data, size_t size)
{
    int i;
    char cs[17];
    memset(cs, 0, 17);

    for (i = 0; i < size; i++) {
        if (i != 0 && i % 0x10 == 0) {
            printf(" |%s|\n", cs);
            memset(cs, 0, 17);
        } else if (i != 0 && i % 0x8 == 0) {
            printf(" ");
        }

        printf("%02X ", data[i]);
        cs[(i % 0x10)] = (data[i] >= 0x20 && data[i] <= 0x7e) ? data[i] : '.';
    }

    i = i % 0x10;
    if (i != 0) {
        if (i < 0x8)
            printf(" ");
        while (i++ < 0x10)
            printf("   ");
    }
    printf(" |%s|\n", cs);
}

void print_usage()
{
    printf("Usage: ./kmem [-r] [-h] addr length\n");
}

int main(int argc, char** argv)
{
    int dump_raw = 0;       // print the raw bytes instead of a hexdump
    vm_address_t addr;
    vm_size_t size;
    char c;

    while ((c = getopt(argc, argv, "rh")) != -1) {
        switch (c) {
        case 'r':
            dump_raw = 1;
            break;
        case 'h':
            print_usage();
            return 0;
        }
    }

    if (optind + 2 <= argc) {
        addr = strtoul(argv[optind], NULL, 16);
        size = strtoul(argv[optind + 1], NULL, 10);
        if (size == 0) {
            print_usage();
            return -1;
        }
    } else {
        print_usage();
        return -1;
    }

    if (!dump_raw)
        printf("reading %i bytes from 0x" ADDR "\n", size, addr);
    unsigned char* buf = malloc(size);
    read_kernel(addr, size, buf);

    if (dump_raw)
        write(1, buf, size);
    else
        hexdump(buf, size);

    free(buf);
    return 0;
}
