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
 * Return the base address of the running kernel.
 */
vm_address_t get_kernel_base();


#endif
