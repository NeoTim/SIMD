/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2005,2009,2011,2013,2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Things common to many ciphertext formats.
 */

#ifndef _JOHN_COMMON_H
#define _JOHN_COMMON_H

#if !defined(_OPENCL_COMPILER)
#include "arch.h"
#include "memory.h"
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#if !defined(_OPENCL_COMPILER)

#if ARCH_INT_GT_32
typedef unsigned short ARCH_WORD_32;
typedef unsigned int ARCH_WORD_64;
#else
typedef unsigned int ARCH_WORD_32;
typedef unsigned long long ARCH_WORD_64;
#endif

/* ONLY use this to check alignments of even power of 2 (2, 4, 8, 16, etc) byte counts (CNT).
   The cast to void* MUST be done, due to C spec. http://stackoverflow.com/a/1898487 */
#define is_aligned(PTR, CNT) ((((ARCH_WORD)(const void *)(PTR))&(CNT-1))==0)

#ifdef __GNUC__
#if __GNUC__ >= 5
#define MAYBE_INLINE __attribute__((gnu_inline)) inline
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7) || defined(__INTEL_COMPILER) || __NVCC__
#define MAYBE_INLINE __attribute__((always_inline)) inline
#elif __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define MAYBE_INLINE __attribute__((always_inline))
#else
#define MAYBE_INLINE __inline__
#endif
#elif __STDC_VERSION__ >= 199901L
#define MAYBE_INLINE inline
#else
#define MAYBE_INLINE
#endif

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_CACHE_ALIGN \
	__attribute__ ((aligned (MEM_ALIGN_CACHE)))
#else
#define CC_CACHE_ALIGN			/* nothing */
#endif

/*
 * This "shift" is the number of bytes that may be inserted between arrays the
 * size of which would be a multiple of cache line size (some power of two) and
 * that might be accessed simultaneously.  The purpose of the shift is to avoid
 * cache bank conflicts with such accesses, actually allowing them to proceed
 * simultaneously.  This number should be a multiple of the machine's word size
 * but smaller than cache line size.
 */
#define CACHE_BANK_SHIFT		ARCH_SIZE

/*
 * ASCII <-> binary conversion tables.
 */
#define DIGITCHARS   "0123456789"
#define HEXCHARS_lc  DIGITCHARS"abcdef"
#define HEXCHARS_uc  DIGITCHARS"ABCDEF"
#define HEXCHARS_all DIGITCHARS"abcdefABCDEF"
#define BASE64_CRYPT "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#endif

#endif
