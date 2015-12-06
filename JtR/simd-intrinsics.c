/*
 * This software is
 * Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>,
 * Copyright (c) 2012 Solar Designer,
 * Copyright (c) 2011-2015 JimF,
 * Copyright (c) 2011-2015 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * SHA-2 Copyright 2013, epixoip. Redistribution and use in source and binary
 * forms, with or without modification, are permitted provided that
 * redistribution of source retains the above copyright.
 */

#include <string.h>
#include <stdio.h>

#include "arch.h"
#include "pseudo_intrinsics.h"
#include "memory.h"
#include "stdint.h"
#include "johnswap.h"
#include "simd-intrinsics-load-flags.h"
#include "aligned.h"

/* Shorter names for use in index calculations */
#define VS32 SIMD_COEF_32
#define VS64 SIMD_COEF_64


#if SIMD_PARA_SHA1
#define SHA1_SSE_NUM_KEYS	(SIMD_COEF_32*SIMD_PARA_SHA1)
#define SHA1_PARA_DO(x)		for((x)=0;(x)<SIMD_PARA_SHA1;(x)++)

#define SHA1_F(x,y,z)                           \
    tmp[i] = vcmov((y[i]),(z[i]),(x[i]));

#if __AVX512F__
#define SHA1_G(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);
#else
#define SHA1_G(x,y,z)                           \
    tmp[i] = vxor((y[i]),(z[i]));               \
    tmp[i] = vxor((tmp[i]),(x[i]));
#endif

#if __AVX512F__
#define SHA1_H(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0xE8);
#elif !VCMOV_EMULATED
#define SHA1_H(x,y,z)                           \
    tmp[i] = vxor((z[i]), (y[i]));              \
    tmp[i] = vcmov((x[i]), (y[i]), tmp[i]);
#else
#define SHA1_H(x,y,z)                                       \
    tmp[i] = vand((x[i]),(y[i]));                           \
    tmp[i] = vor((tmp[i]),vand(vor((x[i]),(y[i])),(z[i])));
#endif

#define SHA1_I(x,y,z) SHA1_G(x,y,z)

#define SHA1_EXPAND2a(t)                                \
    tmp[i] = vxor( data[i*16+t-3], data[i*16+t-8] );    \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );           \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );           \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2b(t)                                    \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], data[i*16+t-8] );   \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );               \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );               \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2c(t)                                        \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );                   \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                   \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2d(t)                                        \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], w[i*16+((t-14)&0xF)] );              \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                   \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2(t)                                         \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], w[i*16+((t-14)&0xF)] );              \
    tmp[i] = vxor( tmp[i], w[i*16+((t-16)&0xF)] );              \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_ROUND2a(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2a(t+16)                         \
    }

#define SHA1_ROUND2b(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2b(t+16)                         \
    }

#define SHA1_ROUND2c(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2c(t+16)                         \
    }

#define SHA1_ROUND2d(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2d(t+16)                         \
    }

#define SHA1_ROUND2(a,b,c,d,e,F,t)                  \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], w[i*16+(t&0xF)] ); \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2(t+16)                          \
    }

#define SHA1_ROUND2x(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], w[i*16+(t&0xF)] ); \
        b[i] = vroti_epi32(b[i], 30);               \
    }

#define INIT_E 0xC3D2E1F0

void sha1_reverse(uint32_t *hash)
{
	hash[4] -= INIT_E;
	hash[4]  = (hash[4] << 2) | (hash[4] >> 30);
}

void sha1_unreverse(uint32_t *hash)
{
	hash[4]  = (hash[4] << 30) | (hash[4] >> 2);
	hash[4] += INIT_E;
}

#undef INIT_E

void SIMDSHA1body(vtype* _data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state,
                 unsigned SSEi_flags)
{
	vtype w[16*SIMD_PARA_SHA1];
	vtype a[SIMD_PARA_SHA1];
	vtype b[SIMD_PARA_SHA1];
	vtype c[SIMD_PARA_SHA1];
	vtype d[SIMD_PARA_SHA1];
	vtype e[SIMD_PARA_SHA1];
	vtype tmp[SIMD_PARA_SHA1];
	vtype cst;
	unsigned int i;
	vtype *data;

	if(SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it SIMD_COEF_32 wise.
#if __SSE4_1__ || __MIC__
		unsigned k;
		vtype *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32*)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_4x(W[i], saved_key, i);
					vswap32(W[i]);
				}
				GATHER_4x(W[14], saved_key, 14);
				GATHER_4x(W[15], saved_key, 15);
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_2x(W[i], saved_key, i);
					vswap32(W[i]);
				}
				GATHER_2x(W[14], saved_key, 14);
				GATHER_2x(W[15], saved_key, 15);
				saved_key += (VS32<<5);
			} else {
				for (i=0; i < 14; ++i) {
					GATHER(W[i], saved_key, i);
					vswap32(W[i]);
				}
				GATHER(W[14], saved_key, 14);
				GATHER(W[15], saved_key, 15);
				saved_key += (VS32<<4);
			}
			if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) == SSEi_FLAT_RELOAD_SWAPLAST) ) {
				vswap32(W[14]);
				vswap32(W[15]);
			}
			W += 16;
		}
#else
		unsigned j, k;
		ARCH_WORD_32 *p = (ARCH_WORD_32*)w;
		vtype *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32*)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (VS32<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (VS32<<4);
			}
			for (i=0; i < 14; i++)
				vswap32(W[i]);
			if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) == SSEi_FLAT_RELOAD_SWAPLAST)) {
				vswap32(W[14]);
				vswap32(W[15]);
			}
			W += 16;
		}
#endif

		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = vset1_epi32(0x67452301);
			b[i] = vset1_epi32(0xefcdab89);
			c[i] = vset1_epi32(0x98badcfe);
			d[i] = vset1_epi32(0x10325476);
			e[i] = vset1_epi32(0xC3D2E1F0);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*16*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*16*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*16*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*16*VS32+4*VS32]);
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*5*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*5*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*5*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*5*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*5*VS32+4*VS32]);
			}
		}
	}

	cst = vset1_epi32(0x5A827999);
	SHA1_ROUND2a( a, b, c, d, e, SHA1_F,  0 );
	SHA1_ROUND2a( e, a, b, c, d, SHA1_F,  1 );
	SHA1_ROUND2a( d, e, a, b, c, SHA1_F,  2 );
	SHA1_ROUND2b( c, d, e, a, b, SHA1_F,  3 );
	SHA1_ROUND2b( b, c, d, e, a, SHA1_F,  4 );
	SHA1_ROUND2b( a, b, c, d, e, SHA1_F,  5 );
	SHA1_ROUND2b( e, a, b, c, d, SHA1_F,  6 );
	SHA1_ROUND2b( d, e, a, b, c, SHA1_F,  7 );
	SHA1_ROUND2c( c, d, e, a, b, SHA1_F,  8 );
	SHA1_ROUND2c( b, c, d, e, a, SHA1_F,  9 );
	SHA1_ROUND2c( a, b, c, d, e, SHA1_F, 10 );
	SHA1_ROUND2c( e, a, b, c, d, SHA1_F, 11 );
	SHA1_ROUND2c( d, e, a, b, c, SHA1_F, 12 );
	SHA1_ROUND2c( c, d, e, a, b, SHA1_F, 13 );
	SHA1_ROUND2d( b, c, d, e, a, SHA1_F, 14 );
	SHA1_ROUND2d( a, b, c, d, e, SHA1_F, 15 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_F, 16 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_F, 17 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_F, 18 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_F, 19 );

	cst = vset1_epi32(0x6ED9EBA1);
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 20 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 21 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 22 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 23 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 24 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 25 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 26 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 27 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 28 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 29 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 30 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 31 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 32 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 33 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 34 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 35 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 36 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 37 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 38 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 39 );

	cst = vset1_epi32(0x8F1BBCDC);
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 40 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 41 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 42 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 43 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 44 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 45 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 46 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 47 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 48 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 49 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 50 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 51 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 52 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 53 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 54 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 55 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 56 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 57 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 58 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 59 );

	cst = vset1_epi32(0xCA62C1D6);
	SHA1_ROUND2( a, b, c, d, e, SHA1_I, 60 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_I, 61 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_I, 62 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_I, 63 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 64 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 65 );
	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 66 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 67 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 68 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 69 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 70 );
	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 71 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 72 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 73 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 74 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 75 );

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		SHA1_PARA_DO(i)
		{
			vstore((vtype*)&out[i*5*VS32+4*VS32], e[i]);
		}
		return;
	}

	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 76 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 77 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 78 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 79 );

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = vadd_epi32(a[i], vset1_epi32(0x67452301));
			b[i] = vadd_epi32(b[i], vset1_epi32(0xefcdab89));
			c[i] = vadd_epi32(c[i], vset1_epi32(0x98badcfe));
			d[i] = vadd_epi32(d[i], vset1_epi32(0x10325476));
			e[i] = vadd_epi32(e[i], vset1_epi32(0xC3D2E1F0));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*16*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*16*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*16*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*16*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i], vload((vtype*)&reload_state[i*16*VS32+4*VS32]));
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*5*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*5*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*5*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*5*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i], vload((vtype*)&reload_state[i*5*VS32+4*VS32]));
			}
		}
	}

	if (SSEi_flags & SSEi_FLAT_OUT) {
		SHA1_PARA_DO(i)
		{
			uint32_t *o = (uint32_t*)&out[i*5*VS32];
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi32(15*5,14*5,13*5,12*5,
			                        11*5,10*5, 9*5, 8*5,
			                         7*5, 6*5, 5*5, 4*5,
			                         3*5, 2*5, 1*5, 0*5);

			vscatter_epi32(o + 0, idxs, vswap32(a[i]), 4);
			vscatter_epi32(o + 1, idxs, vswap32(b[i]), 4);
			vscatter_epi32(o + 2, idxs, vswap32(c[i]), 4);
			vscatter_epi32(o + 3, idxs, vswap32(d[i]), 4);
			vscatter_epi32(o + 4, idxs, vswap32(e[i]), 4);
#else
			uint32_t j, k;
			union {
				vtype v[5];
				uint32_t s[5 * VS32];
			} tmp;

			tmp.v[0] = vswap32(a[i]);
			tmp.v[1] = vswap32(b[i]);
			tmp.v[2] = vswap32(c[i]);
			tmp.v[3] = vswap32(d[i]);
			tmp.v[4] = vswap32(e[i]);

			for (j = 0; j < VS32; j++)
				for (k = 0; k < 5; k++)
					o[j*5+k] = tmp.s[k*VS32+j];
#endif
		}
	}
	else if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			SHA1_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*32*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*32*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*32*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*32*VS32+4*VS32], e[i]);
			}
		} else {
			SHA1_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*16*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*16*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*16*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*16*VS32+4*VS32], e[i]);
			}
		}
	}
	else
	{
		SHA1_PARA_DO(i)
		{
			vstore((vtype*)&out[i*5*VS32+0*VS32], a[i]);
			vstore((vtype*)&out[i*5*VS32+1*VS32], b[i]);
			vstore((vtype*)&out[i*5*VS32+2*VS32], c[i]);
			vstore((vtype*)&out[i*5*VS32+3*VS32], d[i]);
			vstore((vtype*)&out[i*5*VS32+4*VS32], e[i]);
		}
	}
}
#endif /* SIMD_PARA_SHA1 */
