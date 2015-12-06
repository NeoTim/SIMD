/*
 * This software is
 * Copyright (c) 2011-2015 JimF,
 * Copyright (c) 2011-2015 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef __SSE_INTRINS_LOAD_FLAGS__
#define __SSE_INTRINS_LOAD_FLAGS__

/***************************************************************
 * WARNING!!!! any changes to these numbers requires a new
 * build of simd-intrinsics-32.S and simd-intrinsics-64.S
 ***************************************************************/

/*
 * SSEi_MIXED_IN
 * Input is a ready-to-use array of 16xCOEF ints that are properly SIMD
 * interleaved, cleaned, appended with 0x80 and has a proper a length word.
 * The data will be copied to stack workspace.
 *
 * SSEi_FLAT_IN
 * Input is an array of 64xCOEF (128xCOEF_64 for 64 bit crypts) byte 'flat'
 * values, the hash function has to shuffle it. But 0x80 and length must be
 * in place.
 *
 * SSEi_CSTRING_IN
 * Input will be just as for OpenSSL: A normal char[COEF][64] array where
 * each string ends in NULL, with no 0x80 or length prepared. The intrinsics
 * function needs to take care of that as well as cleaning (after NULL),
 * shuffling and possibly do endian swapping if applicable.
 *
 * SSEi_FLAT_OUT
 * Output will be just as from OpenSSL. Swapped if applicable, not interleaved.
 * This should only be used for "final" crypt (and only for slow formats).
 *
 * SSEi_RELOAD
 * No init; state from last crypt is held in output buffer.
 *
 * SSEi_RELOAD_INP_FMT
 * No init; state from last crypt is held in output buffer. However, it is in
 * 'INPUT' format. This is a no-op unless PARA > 1.
 *
 * SSEi_OUTPUT_AS_INP_FMT
 * Write final output using 'INPUT' format. Will not matter unless PARA > 1
 *
 * SSEi_REVERSE_STEPS
 * Reverse some steps, at minimum the "a = a + init". Only valid if not doing
 * reload, and if format does corresponding things in binary() et. al.
 *
 * SSEi_2BUF_INPUT
 * Input array is 2x in size, for a possible max input of 64+55 (119) bytes.
 *
 * SSEi_2BUF_INPUT_FIRST_BLK
 * Input array 2x in size. This is the first block, so we must rotate element
 * 14/15 if in flat mode.
 *
 * SSEi_4BUF_INPUT
 * Input array is 4x in size (This is seen in the dynamic type, for sha256. We
 * have 256 byte input buffers there).
 *
 * SSEi_4BUF_INPUT_FIRST_BLK
 * Input array 4x in size. This is the first block, so we must rotate element
 * 14/15 if in flat mode.
 *
 * SSEi_FLAT_RELOAD_SWAPLAST
 * Can be an issue for flat mode, and reload (i.e. multi buffers.) The last
 * limb should NEVER have this flag set. This also only 'affects' the SHA1
 * and SHA256 formats. Similar to SSEi_4BUF_INPUT_FIRST_BLK, but simply says
 * we will have more buffers coming after this one.
 *
 * SSEi_CRYPT_SHA224     use SHA224 IV.
 * SSEi_CRYPT_SHA384     use SHA384 IV.
 * These are specific to SHA2 hashes. Reusing the same bit, since only 1 will
 * be used (i.e. it is not valid to do SSE_CRYPT_SHA224|SSE_CRYPT_SHA224)
 *
 * WARNING, SHA224 requires a FULL SHA256 width output buffer, and SHA384
 * requires a full SHA512 width output buffer.  This is to allow proper
 * reloading and doing multi-limb crypts.
 */

typedef enum {
	SSEi_MIXED_IN                = 0x0,
	SSEi_FLAT_IN                 = 0x1,
/*	SSEi_CSTRING_IN              = 0x2,	NOT IMPLEMENTED YET*/
	SSEi_FLAT_OUT                = 0x4,
	SSEi_RELOAD                  = 0x8,
	SSEi_RELOAD_INP_FMT          = 0x10 | SSEi_RELOAD,
	SSEi_OUTPUT_AS_INP_FMT       = 0x20,
	SSEi_REVERSE_STEPS           = 0x40,
	SSEi_2BUF_INPUT              = 0x80,
	SSEi_2BUF_INPUT_FIRST_BLK    = 0x100 | SSEi_2BUF_INPUT,
	SSEi_4BUF_INPUT              = 0x200,
	SSEi_4BUF_INPUT_FIRST_BLK    = 0x400 | SSEi_4BUF_INPUT,
	SSEi_FLAT_RELOAD_SWAPLAST    = 0x800,
	SSEi_CRYPT_SHA224            = 0x1000,
	SSEi_CRYPT_SHA384            = 0x1000,
	SSEi_OUTPUT_AS_2BUF_INP_FMT  = 0x2000 | SSEi_OUTPUT_AS_INP_FMT
} SSEi_FLAGS;


#endif /* __SSE_INTRINS_LOAD_FLAGS__  */
