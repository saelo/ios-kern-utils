/*
 * arch.h - Code to deal with different architectures.
 *
 * Copyright (c) 2014 Samuel Groß
 */


#if __LP64__
#define ADDR "%16lx"
#define IMAGE_OFFSET 0x2000
#else
#define ADDR "%8x"
#define IMAGE_OFFSET 0x1000
#endif
