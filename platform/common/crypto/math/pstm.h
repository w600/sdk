/*
 *	pstm.h
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	multiple-precision integer library
 */
/*
 *	Copyright (c) 2013-2014 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#ifndef _h_PSTMATH
#define _h_PSTMATH
#ifndef DISABLE_PSTM

/* Define this here to avoid including circular limits.h on some platforms */
#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif

/******************************************************************************/
/*
    If native 64 bit integers are not supported, we do not support 32x32->64 
	in hardware, so we must set the 16 bit flag to produce 16x16->32 products.
*/
#ifndef HAVE_NATIVE_INT64
    //#define PSTM_16BIT
#endif /* ! HAVE_NATIVE_INT64 */

/******************************************************************************/
/*
	Some default configurations.

	pstm_word should be the largest value the processor can hold as the product
		of a multiplication. Most platforms support a 32x32->64 MAC instruction,
		so 64bits is the default pstm_word size.
	pstm_digit should be half the size of pstm_word
 */
#ifdef PSTM_8BIT
/*	8-bit digits, 16-bit word products */
	typedef unsigned char		pstm_digit;
	typedef unsigned short		pstm_word;
	#define DIGIT_BIT			8
	
#elif defined(PSTM_16BIT)
/*	16-bit digits, 32-bit word products */
	typedef unsigned short		pstm_digit;
	typedef unsigned long		pstm_word;
	#define	DIGIT_BIT			16
	
#elif defined(PSTM_64BIT)
/*	64-bit digits, 128-bit word products */
	#ifndef __GNUC__
	#error "64bit digits requires GCC"
	#endif
	typedef unsigned long		pstm_digit;
	typedef unsigned long		pstm_word __attribute__ ((mode(TI)));
	#define DIGIT_BIT			64
	
#else
/*	This is the default case, 32-bit digits, 64-bit word products */
	//typedef u32			pstm_digit;
	typedef unsigned int pstm_digit;
	//typedef uint64			pstm_word;
	typedef unsigned long long pstm_word;
	#define DIGIT_BIT		32
	#define PSTM_32BIT
#endif /* digit and word size */

//typedef int32 psPool_t;
typedef int psPool_t;

#define PSTM_MASK			(pstm_digit)(-1)
#define PSTM_DIGIT_MAX		PSTM_MASK

/******************************************************************************/
/*
	equalities
 */
#define PSTM_LT			-1		/* less than */
#define PSTM_EQ			0		/* equal to */
#define PSTM_GT			1		/* greater than */

#define PSTM_ZPOS		0		/* positive integer */
#define PSTM_NEG		1		/* negative */

#define PSTM_OKAY		PS_SUCCESS
#define PSTM_MEM		PS_MEM_FAIL

/******************************************************************************/
/*
	Various build options
 */
#define PSTM_DEFAULT_INIT 8//64		/* default (64) digits of allocation */
#define PSTM_MAX_SIZE	512//4096

typedef struct  {
	s16	used, alloc, sign;
	pstm_digit *dp;
} pstm_int;

/******************************************************************************/
/*
	Operations on large integers
 */
#define pstm_iszero(a) (((a)->used == 0) ? PS_TRUE : PS_FALSE)
#define pstm_iseven(a) (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? PS_TRUE : PS_FALSE)
#define pstm_isodd(a)  (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? PS_TRUE : PS_FALSE)
#define pstm_abs(a, b)  { pstm_copy(a, b); (b)->sign  = 0; }

#if 1
 #include "libtommath.h"
 #define pstm_to_unsigned_bin_nr(pool, a, b) mp_to_unsigned_bin_nr((mp_int *)a, (unsigned char *)b)
#define pstm_reverse mp_reverse
#define pstm_set(a, b) mp_set((mp_int *)a, b)

#define pstm_zero(a) mp_zero((mp_int *)a)

#define pstm_init(pool, a) wpa_mp_init((mp_int *)a)

#define pstm_init_size(pool, a, size) mp_init_size((mp_int *)a, size)

#define pstm_init_copy(pool, a, b, toSqr) mp_init_copy((mp_int *)a, (mp_int *)b)

#define pstm_count_bits(a) mp_count_bits((mp_int *)a)

#define pstm_init_for_read_unsigned_bin(pool, a, len) mp_init_for_read_unsigned_bin((mp_int *)a, len)

#define pstm_read_unsigned_bin(a, b, c) mp_read_unsigned_bin((mp_int *)a, b, c)

#define pstm_unsigned_bin_size(a) mp_unsigned_bin_size((mp_int *)a)

#define pstm_copy(a, b) mp_copy((mp_int *)a, (mp_int *)b)

#define pstm_exch(a, b) mp_exch((mp_int *)a, (mp_int *)b)

#define pstm_clear(a) mp_clear((mp_int *)a)

#define pstm_clear_multi mp_clear_multi

#define pstm_grow(a, size) mp_grow((mp_int *)a, size)

#define pstm_clamp(a) mp_clamp((mp_int *)a)

#define pstm_cmp(a, b) mp_cmp((mp_int *)a, (mp_int *)b)

#define pstm_cmp_mag(a, b) mp_cmp_mag((mp_int *)a, (mp_int *)b)

#define pstm_rshd(a, size) mp_rshd((mp_int *)a, size)

#define pstm_lshd(a, size) mp_lshd((mp_int *)a, size)

#define pstm_div(pool, a, b, c, d) mp_div((mp_int *)a, (mp_int *)b, (mp_int *)c, (mp_int *)d)
				
#define pstm_div_2d(pool, a, b, c, d) mp_div_2d((mp_int *)a, b, (mp_int *)c, (mp_int *)d)
	
#define pstm_div_2(a, b) mp_div_2((mp_int *)a, (mp_int *)b)

//#define s_pstm_sub(pstm_int *a, pstm_int *b, pstm_int *c);

#define pstm_sub(a, b, c) mp_sub((mp_int *)a, (mp_int *)b, (mp_int *)c)

#define pstm_sub_d(pool, a, b, c) mp_sub_d(a, b, c)

#define pstm_mul_2 mp_mul_2

#define pstm_mod(pool, a, b, c) mp_mod((mp_int *)a, (mp_int *)b, (mp_int *)c)

#define pstm_mulmod(pool, a, b, c, d) mp_mulmod((mp_int *)a, (mp_int *)b, (mp_int *)c, (mp_int *)d)
			
#define pstm_exptmod(pool, G, X, P, Y) mp_exptmod((mp_int *)G, (mp_int *)X, (mp_int *)P, (mp_int *)Y)

#define pstm_2expt(a, size) mp_2expt((mp_int *)a, size)	
			
#define pstm_add(a, b, c) mp_add((mp_int *)a, (mp_int *)b, (mp_int *)c)

#define pstm_to_unsigned_bin(pool, a, b) mp_to_unsigned_bin((mp_int *)a, b)

//#define pstm_to_unsigned_bin_nr(psPool_t *pool, pstm_int *a,
//				unsigned char *b);
								
#define pstm_montgomery_setup(a, size) mp_montgomery_setup((mp_int *)a, size)
				
#define pstm_montgomery_reduce(pool, a, m, mp, paD, paDlen) fast_mp_montgomery_reduce((mp_int *)a, (mp_int *)m, mp)

extern s32 pstm_mul_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_int *C, pstm_digit *paD, u32 paDlen);
				
extern s32 pstm_sqr_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_digit *paD, u32 paDlen);
				
#define pstm_cmp_d(a, size) mp_cmp_d((mp_int *)a, size)
				
#define pstm_montgomery_calc_normalization(a, b) mp_montgomery_calc_normalization((mp_int *)a, (mp_int *)b)

#define pstm_mul_d(a, b, c) mp_mul_d((mp_int *)a, b, (mp_int *)c)

#define pstm_invmod(pool, a, b, c) mp_invmod((mp_int *)a, (mp_int *)b, (mp_int *)c)
#else

extern int16 pstm_get_bit (pstm_int * a, int16 idx);
extern void pstm_reverse (unsigned char *s, int16 len);
extern void pstm_set(pstm_int *a, pstm_digit b);

extern void pstm_zero(pstm_int * a);

extern int32 pstm_init(psPool_t *pool, pstm_int * a);

extern int32 pstm_init_size(psPool_t *pool, pstm_int * a, u32 size);

extern int32 pstm_init_copy(psPool_t *pool, pstm_int * a, pstm_int * b,
				int16 toSqr);

extern int16 pstm_count_bits (pstm_int * a);

extern int32 pstm_init_for_read_unsigned_bin(psPool_t *pool, pstm_int *a,
				u32 len);

extern int32 pstm_read_unsigned_bin(pstm_int *a, unsigned char *b, int32 c);

extern int32 pstm_unsigned_bin_size(pstm_int *a);	

extern int32 pstm_copy(pstm_int * a, pstm_int * b);

extern void pstm_exch(pstm_int * a, pstm_int * b);

extern void pstm_clear(pstm_int * a);

extern void pstm_clear_multi(pstm_int *mp0, pstm_int *mp1, pstm_int *mp2,
				pstm_int *mp3, pstm_int *mp4, pstm_int *mp5, pstm_int *mp6,
				pstm_int *mp7);

extern int32 pstm_grow(pstm_int * a, int16 size);

extern void pstm_clamp(pstm_int * a);

extern int32 pstm_cmp(pstm_int * a, pstm_int * b);

extern int32 pstm_cmp_mag(pstm_int * a, pstm_int * b);

extern void pstm_rshd(pstm_int *a, int16 x);

extern int32 pstm_lshd(pstm_int * a, int16 b);

extern int32 pstm_div(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c,
				pstm_int *d);
				
extern int32 pstm_div_2d(psPool_t *pool, pstm_int *a, int16 b, pstm_int *c,
				pstm_int *d);
	
extern int32 pstm_div_2(pstm_int * a, pstm_int * b);											

extern int32 s_pstm_sub(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_sub(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_sub_d(psPool_t *pool, pstm_int *a, pstm_digit b, pstm_int *c);

extern int32 pstm_mul_2(pstm_int * a, pstm_int * b);

extern int32 pstm_mod(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_mulmod(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c,
				pstm_int *d);
			
extern int32 pstm_exptmod(psPool_t *pool, pstm_int *G, pstm_int *X, pstm_int *P,
				pstm_int *Y);

extern int32 pstm_2expt(pstm_int *a, int16 b);				
			
extern int32 pstm_add(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_to_unsigned_bin(psPool_t *pool, pstm_int *a,
				unsigned char *b);

extern int32 pstm_to_unsigned_bin_nr(psPool_t *pool, pstm_int *a,
				unsigned char *b);
								
extern int32 pstm_montgomery_setup(pstm_int *a, pstm_digit *rho);
				
extern int32 pstm_montgomery_reduce(psPool_t *pool, pstm_int *a, pstm_int *m,
				pstm_digit mp, pstm_digit *paD, u32 paDlen);

extern int32 pstm_mul_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_int *C, pstm_digit *paD, u32 paDlen);
				
extern int32 pstm_sqr_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_digit *paD, u32 paDlen);
				
extern int32 pstm_cmp_d(pstm_int *a, pstm_digit b);
				
extern int32 pstm_montgomery_calc_normalization(pstm_int *a, pstm_int *b);

extern int32 pstm_mul_d(pstm_int *a, pstm_digit b, pstm_int *c);

extern int32 pstm_invmod(psPool_t *pool, pstm_int * a, pstm_int * b,
				pstm_int * c);
#endif
#else /* DISABLE_PSTM */
	typedef s32 pstm_int;
#endif /* !DISABLE_PSTM */
#endif /* _h_PSTMATH */

