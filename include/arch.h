/*
 * arch.h - Code to deal with different architectures.
 *
 * (c) 2014 Samuel Groß
 */


#if __LP64__
#define ADDR "%16lx"
#else
#define ADDR "%8x"
#endif
