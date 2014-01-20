/*
 * kern.h - Libkern library.
 *
 * Copyright (c) 2014 Samuel Groß
 */

#ifndef LIBKERN_H
#define LIBKERN_H

#include <mach/vm_types.h>

#include "arch.h"

/*
 * Functions to interact with the kernel address space.
 *
 * If not otherwise stated the following functions are 'unsafe', meaning
 * they are likely to panic the device if given invalid kernel addresses.
 *
 * You have been warned.
 */

/*
 * Return the base address of the running kernel.
 *
 * This function should be safe.
 */
vm_address_t get_kernel_base();

/*
 * Read data from the kernel address space.
 *
 * Returns the number of bytes read.
 */
vm_size_t read_kernel(vm_address_t addr, vm_size_t size, unsigned char* buf);

/*
 * Write data into the kernel address space.
 *
 * Returns the number of bytes written.
 */
vm_size_t write_kernel(vm_address_t addr, unsigned char* data, vm_size_t size);

/*
 * Find the given byte sequence in the kernel address space between start and end.
 *
 * Returns the address of the first occurance of bytes if found, otherwise 0.
 */
vm_address_t find_bytes(vm_address_t start, vm_address_t end, unsigned char* bytes, size_t length);


#endif
