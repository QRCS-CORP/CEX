/**
*** Copyright (C) 2007-2014 Intel Corporation.  All rights reserved.
***
*** The information and source code contained herein is the exclusive
*** property of Intel Corporation and may not be disclosed, examined
*** or reproduced in whole or in part without explicit written authorization
*** from the company.
***
**/

#ifndef _ZMMINTRIN_H_INCLUDED
#define _ZMMINTRIN_H_INCLUDED

#ifndef _INCLUDED_IMM
//#error "Header should only be included from <immintrin.h>."
#endif

/*
* Definitions and declarations for use with 512-bit compiler intrinsics.
*/

/*
*
* A word about intrinsic naming conventions.  Most 512-bit vector
* instructions have names such as v<operation><type>.  For example
* "vaddps" is an addition operation (add) on packed single precision (ps)
* values.  The corresponding intrinsic is usually (not always) named
* "_mm512_<operation>_<type>", for example _mm512_add_ps.  The corresponding
* write-masked flavor has "_mask" in the name, _mm512_mask_add_ps.
*
* The types are:
*
*    ps    -- packed single precision
*    pd    -- packed double precision
*    epi32 -- packed 32-bit integers
*    epu32 -- packed 32-bit unsigned integers
*    epi64 -- packed 64-bit integers
*/

typedef unsigned char       __mmask8;
typedef unsigned short      __mmask16;
typedef unsigned int        __mmask32;
typedef unsigned __int64    __mmask64;
/*
* __mmask is deprecated, use __mmask16 instead.
*/
typedef __mmask16 __mmask;

#ifdef __INTEL_CLANG_COMPILER

typedef float   __m512  __attribute__((__vector_size__(64)));
typedef double  __m512d __attribute__((__vector_size__(64)));
typedef __int64 __m512i __attribute__((__vector_size__(64)));

#else
#if !defined(__INTEL_COMPILER) && defined(_MSC_VER)
# define _MM512INTRIN_TYPE(X) __declspec(intrin_type)
#else
# define _MM512INTRIN_TYPE(X) _MMINTRIN_TYPE(X)
#endif


typedef union _MM512INTRIN_TYPE(64) __m512 {
	float       __m512_f32[16];
} __m512;

typedef union _MM512INTRIN_TYPE(64) __m512d {
	double      __m512d_f64[8];
} __m512d;

typedef union _MM512INTRIN_TYPE(64) __m512i {
	int         __m512i_i32[16];
} __m512i;

#endif /* __INTEL_CLANG_COMPILER */


#ifdef __cplusplus
extern "C" {
	/* Intrinsics use C name-mangling. */
#endif /* __cplusplus */

	/* Conversion from one type to another, no change in value. */

	extern __m512  __ICL_INTRINCC _mm512_castpd_ps(__m512d);
	extern __m512i __ICL_INTRINCC _mm512_castpd_si512(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_castps_pd(__m512);
	extern __m512i __ICL_INTRINCC _mm512_castps_si512(__m512);
	extern __m512  __ICL_INTRINCC _mm512_castsi512_ps(__m512i);
	extern __m512d __ICL_INTRINCC _mm512_castsi512_pd(__m512i);


	/* Constant for special read-only mask register 'k0'. */
#define _MM_K0_REG (0xffff)


	/* Constants for register swizzle primitives. */
	typedef enum {
		_MM_SWIZ_REG_NONE,      /* hgfe dcba - Nop */
#define _MM_SWIZ_REG_DCBA _MM_SWIZ_REG_NONE
		_MM_SWIZ_REG_CDAB,      /* ghef cdab - Swap pairs */
		_MM_SWIZ_REG_BADC,      /* fehg badc - Swap with two-away */
		_MM_SWIZ_REG_AAAA,      /* eeee aaaa - broadcast a element */
		_MM_SWIZ_REG_BBBB,      /* ffff bbbb - broadcast b element */
		_MM_SWIZ_REG_CCCC,      /* gggg cccc - broadcast c element */
		_MM_SWIZ_REG_DDDD,      /* hhhh dddd - broadcast d element */
		_MM_SWIZ_REG_DACB       /* hegf dacb - cross-product */
	} _MM_SWIZZLE_ENUM;

	/* Constants for broadcasts to vectors with 32-bit elements. */
	typedef enum {
		_MM_BROADCAST32_NONE,   /* identity swizzle/convert */
#define _MM_BROADCAST_16X16 _MM_BROADCAST32_NONE
		_MM_BROADCAST_1X16,     /* broadcast x 16 ( aaaa aaaa aaaa aaaa ) */
		_MM_BROADCAST_4X16      /* broadcast x 4  ( dcba dcba dcba dcba ) */
	} _MM_BROADCAST32_ENUM;

	/* Constants for broadcasts to vectors with 64-bit elements. */
	typedef enum {
		_MM_BROADCAST64_NONE,   /* identity swizzle/convert */
#define _MM_BROADCAST_8X8 _MM_BROADCAST64_NONE
		_MM_BROADCAST_1X8,      /* broadcast x 8 ( aaaa aaaa ) */
		_MM_BROADCAST_4X8       /* broadcast x 2 ( dcba dcba ) */
	} _MM_BROADCAST64_ENUM;

	/*
	* Constants for rounding mode.
	* These names beginnig with "_MM_ROUND" are deprecated.
	* Use the names beginning with "_MM_FROUND" going forward.
	*/
	typedef enum {
		_MM_ROUND_MODE_NEAREST,             /* round to nearest (even) */
		_MM_ROUND_MODE_DOWN,                /* round toward negative infinity */
		_MM_ROUND_MODE_UP,                  /* round toward positive infinity */
		_MM_ROUND_MODE_TOWARD_ZERO,         /* round toward zero */
		_MM_ROUND_MODE_DEFAULT              /* round mode from MXCSR */
	} _MM_ROUND_MODE_ENUM;

	/* Constants for exponent adjustment. */
	typedef enum {
		_MM_EXPADJ_NONE,               /* 2**0  (32.0 - no exp adjustment) */
		_MM_EXPADJ_4,                  /* 2**4  (28.4)  */
		_MM_EXPADJ_5,                  /* 2**5  (27.5)  */
		_MM_EXPADJ_8,                  /* 2**8  (24.8)  */
		_MM_EXPADJ_16,                 /* 2**16 (16.16) */
		_MM_EXPADJ_24,                 /* 2**24 (8.24)  */
		_MM_EXPADJ_31,                 /* 2**31 (1.31)  */
		_MM_EXPADJ_32                  /* 2**32 (0.32)  */
	} _MM_EXP_ADJ_ENUM;

	/* Constants for index scale (vgather/vscatter). */
	typedef enum {
		_MM_SCALE_1 = 1,
		_MM_SCALE_2 = 2,
		_MM_SCALE_4 = 4,
		_MM_SCALE_8 = 8
	} _MM_INDEX_SCALE_ENUM;

	/*
	* Constants for load/store temporal hints.
	*/
#define _MM_HINT_NONE           0x0
#define _MM_HINT_NT             0x1     /* Load or store is non-temporal. */

	typedef enum {
		_MM_PERM_AAAA = 0x00, _MM_PERM_AAAB = 0x01, _MM_PERM_AAAC = 0x02,
		_MM_PERM_AAAD = 0x03, _MM_PERM_AABA = 0x04, _MM_PERM_AABB = 0x05,
		_MM_PERM_AABC = 0x06, _MM_PERM_AABD = 0x07, _MM_PERM_AACA = 0x08,
		_MM_PERM_AACB = 0x09, _MM_PERM_AACC = 0x0A, _MM_PERM_AACD = 0x0B,
		_MM_PERM_AADA = 0x0C, _MM_PERM_AADB = 0x0D, _MM_PERM_AADC = 0x0E,
		_MM_PERM_AADD = 0x0F, _MM_PERM_ABAA = 0x10, _MM_PERM_ABAB = 0x11,
		_MM_PERM_ABAC = 0x12, _MM_PERM_ABAD = 0x13, _MM_PERM_ABBA = 0x14,
		_MM_PERM_ABBB = 0x15, _MM_PERM_ABBC = 0x16, _MM_PERM_ABBD = 0x17,
		_MM_PERM_ABCA = 0x18, _MM_PERM_ABCB = 0x19, _MM_PERM_ABCC = 0x1A,
		_MM_PERM_ABCD = 0x1B, _MM_PERM_ABDA = 0x1C, _MM_PERM_ABDB = 0x1D,
		_MM_PERM_ABDC = 0x1E, _MM_PERM_ABDD = 0x1F, _MM_PERM_ACAA = 0x20,
		_MM_PERM_ACAB = 0x21, _MM_PERM_ACAC = 0x22, _MM_PERM_ACAD = 0x23,
		_MM_PERM_ACBA = 0x24, _MM_PERM_ACBB = 0x25, _MM_PERM_ACBC = 0x26,
		_MM_PERM_ACBD = 0x27, _MM_PERM_ACCA = 0x28, _MM_PERM_ACCB = 0x29,
		_MM_PERM_ACCC = 0x2A, _MM_PERM_ACCD = 0x2B, _MM_PERM_ACDA = 0x2C,
		_MM_PERM_ACDB = 0x2D, _MM_PERM_ACDC = 0x2E, _MM_PERM_ACDD = 0x2F,
		_MM_PERM_ADAA = 0x30, _MM_PERM_ADAB = 0x31, _MM_PERM_ADAC = 0x32,
		_MM_PERM_ADAD = 0x33, _MM_PERM_ADBA = 0x34, _MM_PERM_ADBB = 0x35,
		_MM_PERM_ADBC = 0x36, _MM_PERM_ADBD = 0x37, _MM_PERM_ADCA = 0x38,
		_MM_PERM_ADCB = 0x39, _MM_PERM_ADCC = 0x3A, _MM_PERM_ADCD = 0x3B,
		_MM_PERM_ADDA = 0x3C, _MM_PERM_ADDB = 0x3D, _MM_PERM_ADDC = 0x3E,
		_MM_PERM_ADDD = 0x3F, _MM_PERM_BAAA = 0x40, _MM_PERM_BAAB = 0x41,
		_MM_PERM_BAAC = 0x42, _MM_PERM_BAAD = 0x43, _MM_PERM_BABA = 0x44,
		_MM_PERM_BABB = 0x45, _MM_PERM_BABC = 0x46, _MM_PERM_BABD = 0x47,
		_MM_PERM_BACA = 0x48, _MM_PERM_BACB = 0x49, _MM_PERM_BACC = 0x4A,
		_MM_PERM_BACD = 0x4B, _MM_PERM_BADA = 0x4C, _MM_PERM_BADB = 0x4D,
		_MM_PERM_BADC = 0x4E, _MM_PERM_BADD = 0x4F, _MM_PERM_BBAA = 0x50,
		_MM_PERM_BBAB = 0x51, _MM_PERM_BBAC = 0x52, _MM_PERM_BBAD = 0x53,
		_MM_PERM_BBBA = 0x54, _MM_PERM_BBBB = 0x55, _MM_PERM_BBBC = 0x56,
		_MM_PERM_BBBD = 0x57, _MM_PERM_BBCA = 0x58, _MM_PERM_BBCB = 0x59,
		_MM_PERM_BBCC = 0x5A, _MM_PERM_BBCD = 0x5B, _MM_PERM_BBDA = 0x5C,
		_MM_PERM_BBDB = 0x5D, _MM_PERM_BBDC = 0x5E, _MM_PERM_BBDD = 0x5F,
		_MM_PERM_BCAA = 0x60, _MM_PERM_BCAB = 0x61, _MM_PERM_BCAC = 0x62,
		_MM_PERM_BCAD = 0x63, _MM_PERM_BCBA = 0x64, _MM_PERM_BCBB = 0x65,
		_MM_PERM_BCBC = 0x66, _MM_PERM_BCBD = 0x67, _MM_PERM_BCCA = 0x68,
		_MM_PERM_BCCB = 0x69, _MM_PERM_BCCC = 0x6A, _MM_PERM_BCCD = 0x6B,
		_MM_PERM_BCDA = 0x6C, _MM_PERM_BCDB = 0x6D, _MM_PERM_BCDC = 0x6E,
		_MM_PERM_BCDD = 0x6F, _MM_PERM_BDAA = 0x70, _MM_PERM_BDAB = 0x71,
		_MM_PERM_BDAC = 0x72, _MM_PERM_BDAD = 0x73, _MM_PERM_BDBA = 0x74,
		_MM_PERM_BDBB = 0x75, _MM_PERM_BDBC = 0x76, _MM_PERM_BDBD = 0x77,
		_MM_PERM_BDCA = 0x78, _MM_PERM_BDCB = 0x79, _MM_PERM_BDCC = 0x7A,
		_MM_PERM_BDCD = 0x7B, _MM_PERM_BDDA = 0x7C, _MM_PERM_BDDB = 0x7D,
		_MM_PERM_BDDC = 0x7E, _MM_PERM_BDDD = 0x7F, _MM_PERM_CAAA = 0x80,
		_MM_PERM_CAAB = 0x81, _MM_PERM_CAAC = 0x82, _MM_PERM_CAAD = 0x83,
		_MM_PERM_CABA = 0x84, _MM_PERM_CABB = 0x85, _MM_PERM_CABC = 0x86,
		_MM_PERM_CABD = 0x87, _MM_PERM_CACA = 0x88, _MM_PERM_CACB = 0x89,
		_MM_PERM_CACC = 0x8A, _MM_PERM_CACD = 0x8B, _MM_PERM_CADA = 0x8C,
		_MM_PERM_CADB = 0x8D, _MM_PERM_CADC = 0x8E, _MM_PERM_CADD = 0x8F,
		_MM_PERM_CBAA = 0x90, _MM_PERM_CBAB = 0x91, _MM_PERM_CBAC = 0x92,
		_MM_PERM_CBAD = 0x93, _MM_PERM_CBBA = 0x94, _MM_PERM_CBBB = 0x95,
		_MM_PERM_CBBC = 0x96, _MM_PERM_CBBD = 0x97, _MM_PERM_CBCA = 0x98,
		_MM_PERM_CBCB = 0x99, _MM_PERM_CBCC = 0x9A, _MM_PERM_CBCD = 0x9B,
		_MM_PERM_CBDA = 0x9C, _MM_PERM_CBDB = 0x9D, _MM_PERM_CBDC = 0x9E,
		_MM_PERM_CBDD = 0x9F, _MM_PERM_CCAA = 0xA0, _MM_PERM_CCAB = 0xA1,
		_MM_PERM_CCAC = 0xA2, _MM_PERM_CCAD = 0xA3, _MM_PERM_CCBA = 0xA4,
		_MM_PERM_CCBB = 0xA5, _MM_PERM_CCBC = 0xA6, _MM_PERM_CCBD = 0xA7,
		_MM_PERM_CCCA = 0xA8, _MM_PERM_CCCB = 0xA9, _MM_PERM_CCCC = 0xAA,
		_MM_PERM_CCCD = 0xAB, _MM_PERM_CCDA = 0xAC, _MM_PERM_CCDB = 0xAD,
		_MM_PERM_CCDC = 0xAE, _MM_PERM_CCDD = 0xAF, _MM_PERM_CDAA = 0xB0,
		_MM_PERM_CDAB = 0xB1, _MM_PERM_CDAC = 0xB2, _MM_PERM_CDAD = 0xB3,
		_MM_PERM_CDBA = 0xB4, _MM_PERM_CDBB = 0xB5, _MM_PERM_CDBC = 0xB6,
		_MM_PERM_CDBD = 0xB7, _MM_PERM_CDCA = 0xB8, _MM_PERM_CDCB = 0xB9,
		_MM_PERM_CDCC = 0xBA, _MM_PERM_CDCD = 0xBB, _MM_PERM_CDDA = 0xBC,
		_MM_PERM_CDDB = 0xBD, _MM_PERM_CDDC = 0xBE, _MM_PERM_CDDD = 0xBF,
		_MM_PERM_DAAA = 0xC0, _MM_PERM_DAAB = 0xC1, _MM_PERM_DAAC = 0xC2,
		_MM_PERM_DAAD = 0xC3, _MM_PERM_DABA = 0xC4, _MM_PERM_DABB = 0xC5,
		_MM_PERM_DABC = 0xC6, _MM_PERM_DABD = 0xC7, _MM_PERM_DACA = 0xC8,
		_MM_PERM_DACB = 0xC9, _MM_PERM_DACC = 0xCA, _MM_PERM_DACD = 0xCB,
		_MM_PERM_DADA = 0xCC, _MM_PERM_DADB = 0xCD, _MM_PERM_DADC = 0xCE,
		_MM_PERM_DADD = 0xCF, _MM_PERM_DBAA = 0xD0, _MM_PERM_DBAB = 0xD1,
		_MM_PERM_DBAC = 0xD2, _MM_PERM_DBAD = 0xD3, _MM_PERM_DBBA = 0xD4,
		_MM_PERM_DBBB = 0xD5, _MM_PERM_DBBC = 0xD6, _MM_PERM_DBBD = 0xD7,
		_MM_PERM_DBCA = 0xD8, _MM_PERM_DBCB = 0xD9, _MM_PERM_DBCC = 0xDA,
		_MM_PERM_DBCD = 0xDB, _MM_PERM_DBDA = 0xDC, _MM_PERM_DBDB = 0xDD,
		_MM_PERM_DBDC = 0xDE, _MM_PERM_DBDD = 0xDF, _MM_PERM_DCAA = 0xE0,
		_MM_PERM_DCAB = 0xE1, _MM_PERM_DCAC = 0xE2, _MM_PERM_DCAD = 0xE3,
		_MM_PERM_DCBA = 0xE4, _MM_PERM_DCBB = 0xE5, _MM_PERM_DCBC = 0xE6,
		_MM_PERM_DCBD = 0xE7, _MM_PERM_DCCA = 0xE8, _MM_PERM_DCCB = 0xE9,
		_MM_PERM_DCCC = 0xEA, _MM_PERM_DCCD = 0xEB, _MM_PERM_DCDA = 0xEC,
		_MM_PERM_DCDB = 0xED, _MM_PERM_DCDC = 0xEE, _MM_PERM_DCDD = 0xEF,
		_MM_PERM_DDAA = 0xF0, _MM_PERM_DDAB = 0xF1, _MM_PERM_DDAC = 0xF2,
		_MM_PERM_DDAD = 0xF3, _MM_PERM_DDBA = 0xF4, _MM_PERM_DDBB = 0xF5,
		_MM_PERM_DDBC = 0xF6, _MM_PERM_DDBD = 0xF7, _MM_PERM_DDCA = 0xF8,
		_MM_PERM_DDCB = 0xF9, _MM_PERM_DDCC = 0xFA, _MM_PERM_DDCD = 0xFB,
		_MM_PERM_DDDA = 0xFC, _MM_PERM_DDDB = 0xFD, _MM_PERM_DDDC = 0xFE,
		_MM_PERM_DDDD = 0xFF
	} _MM_PERM_ENUM;

	/*
	* Helper type and macro for computing the values of the immediate
	* used in mm512_fixup_ps.
	*/
	typedef enum {
		_MM_FIXUP_NO_CHANGE,
		_MM_FIXUP_NEG_INF,
		_MM_FIXUP_NEG_ZERO,
		_MM_FIXUP_POS_ZERO,
		_MM_FIXUP_POS_INF,
		_MM_FIXUP_NAN,
		_MM_FIXUP_MAX_FLOAT,
		_MM_FIXUP_MIN_FLOAT
	} _MM_FIXUPRESULT_ENUM;

#define _MM_FIXUP(_NegInf, \
                  _Neg, \
                  _NegZero, \
                  _PosZero, \
                  _Pos, \
                  _PosInf, \
                  _Nan) \
   ((int) (_NegInf) | \
   ((int) (_Neg) << 3) | \
   ((int) (_NegZero) << 6) | \
   ((int) (_PosZero) << 9) | \
   ((int) (_Pos) << 12) | \
   ((int) (_PosInf) << 15) | \
   ((int) (_Nan) << 18))


	/*
	* Write-masked vector copy.
	*/
	extern __m512  __ICL_INTRINCC _mm512_mask_mov_ps(__m512, __mmask16, __m512);
	extern __m512d __ICL_INTRINCC _mm512_mask_mov_pd(__m512d, __mmask8, __m512d);

#define _mm512_mask_mov_epi32(v_old, k1, src) \
    _mm512_mask_swizzle_epi32((v_old), (k1), (src), _MM_SWIZ_REG_NONE)

#define _mm512_mask_mov_epi64(v_old, k1, src) \
    _mm512_mask_swizzle_epi64((v_old), (k1), (src), _MM_SWIZ_REG_NONE)


	/* Constants for upconversion to packed single precision. */

	typedef enum {

		_MM_UPCONV_PS_NONE,         /* no conversion      */
		_MM_UPCONV_PS_FLOAT16,      /* float16 => float32 */
		_MM_UPCONV_PS_UINT8,        /* uint8   => float32 */
		_MM_UPCONV_PS_SINT8,        /* sint8   => float32 */
		_MM_UPCONV_PS_UINT16,       /* uint16  => float32 */
		_MM_UPCONV_PS_SINT16        /* sint16  => float32 */


	} _MM_UPCONV_PS_ENUM;

	extern __m512 __ICL_INTRINCC _mm512_extload_ps(void const*,
		_MM_UPCONV_PS_ENUM,
		_MM_BROADCAST32_ENUM,
		int /* mem hint */);
	extern __m512 __ICL_INTRINCC _mm512_mask_extload_ps(__m512, __mmask16,
		void const*,
		_MM_UPCONV_PS_ENUM,
		_MM_BROADCAST32_ENUM,
		int /* mem hint */);

	extern __m512 __ICL_INTRINCC _mm512_load_ps(void const*);
	extern __m512 __ICL_INTRINCC _mm512_mask_load_ps(__m512, __mmask16,
		void const*);


	/* Constants for upconversion to packed 32-bit integers. */

	typedef enum {

		_MM_UPCONV_EPI32_NONE,      /* no conversion      */
		_MM_UPCONV_EPI32_UINT8,     /* uint8   => uint32  */
		_MM_UPCONV_EPI32_SINT8,     /* sint8   => sint32  */
		_MM_UPCONV_EPI32_UINT16,    /* uint16  => uint32  */
		_MM_UPCONV_EPI32_SINT16     /* sint16  => sint32  */

	} _MM_UPCONV_EPI32_ENUM;

	extern __m512i __ICL_INTRINCC _mm512_extload_epi32(void const*,
		_MM_UPCONV_EPI32_ENUM,
		_MM_BROADCAST32_ENUM,
		int /* mem hint */);
	extern __m512i __ICL_INTRINCC _mm512_mask_extload_epi32(__m512i, __mmask16,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		_MM_BROADCAST32_ENUM,
		int /* mem hint */);

#define _mm512_load_si512 _mm512_load_epi32
	extern __m512i __ICL_INTRINCC _mm512_load_epi32(void const*);
	extern __m512i __ICL_INTRINCC _mm512_mask_load_epi32(__m512i, __mmask16,
		void const*);

	/* Constants for upconversion to packed double precision. */

	typedef enum {
		_MM_UPCONV_PD_NONE          /* no conversion */
	} _MM_UPCONV_PD_ENUM;

	extern __m512d __ICL_INTRINCC _mm512_extload_pd(void const*,
		_MM_UPCONV_PD_ENUM,
		_MM_BROADCAST64_ENUM,
		int /* mem hint */);
	extern __m512d __ICL_INTRINCC _mm512_mask_extload_pd(__m512d, __mmask8,
		void const*,
		_MM_UPCONV_PD_ENUM,
		_MM_BROADCAST64_ENUM,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_load_pd(void const*);
	extern __m512d __ICL_INTRINCC _mm512_mask_load_pd(__m512d, __mmask8,
		void const*);


	/* Constants for upconversion to packed 64-bit integers. */

	typedef enum {
		_MM_UPCONV_EPI64_NONE       /* no conversion */
	} _MM_UPCONV_EPI64_ENUM;

	extern __m512i __ICL_INTRINCC _mm512_extload_epi64(void const*,
		_MM_UPCONV_EPI64_ENUM,
		_MM_BROADCAST64_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_extload_epi64(__m512i, __mmask8,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		_MM_BROADCAST64_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_load_epi64(void const*);
	extern __m512i __ICL_INTRINCC _mm512_mask_load_epi64(__m512i, __mmask8,
		void const*);

	/*
	* Swizzle/broadcast/upconversion operations.
	*/
	extern __m512  __ICL_INTRINCC _mm512_swizzle_ps(__m512, _MM_SWIZZLE_ENUM);
	extern __m512d __ICL_INTRINCC _mm512_swizzle_pd(__m512d, _MM_SWIZZLE_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_swizzle_epi32(__m512i, _MM_SWIZZLE_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_swizzle_epi64(__m512i, _MM_SWIZZLE_ENUM);

	extern __m512  __ICL_INTRINCC _mm512_mask_swizzle_ps(__m512, __mmask16,
		__m512,
		_MM_SWIZZLE_ENUM);
	extern __m512d __ICL_INTRINCC _mm512_mask_swizzle_pd(__m512d, __mmask8,
		__m512d,
		_MM_SWIZZLE_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_swizzle_epi32(__m512i, __mmask16,
		__m512i,
		_MM_SWIZZLE_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_swizzle_epi64(__m512i, __mmask8,
		__m512i,
		_MM_SWIZZLE_ENUM);

	/* Constants for downconversion from packed single precision. */

	typedef enum {

		_MM_DOWNCONV_PS_NONE,         /* no conversion      */
		_MM_DOWNCONV_PS_FLOAT16,      /* float32 => float16 */
		_MM_DOWNCONV_PS_UINT8,        /* float32 => uint8   */
		_MM_DOWNCONV_PS_SINT8,        /* float32 => sint8   */
		_MM_DOWNCONV_PS_UINT16,       /* float32 => uint16  */
		_MM_DOWNCONV_PS_SINT16        /* float32 => sint16  */


	} _MM_DOWNCONV_PS_ENUM;

	/* Constants for downconversion from packed 32-bit integers. */

	typedef enum {
		_MM_DOWNCONV_EPI32_NONE,      /* no conversion      */
		_MM_DOWNCONV_EPI32_UINT8,     /* uint32 => uint8    */
		_MM_DOWNCONV_EPI32_SINT8,     /* sint32 => sint8    */
		_MM_DOWNCONV_EPI32_UINT16,    /* uint32 => uint16   */
		_MM_DOWNCONV_EPI32_SINT16     /* sint32 => sint16   */
	} _MM_DOWNCONV_EPI32_ENUM;

	/* Constants for downconversion from packed double precision. */

	typedef enum {
		_MM_DOWNCONV_PD_NONE          /* no conversion      */
	} _MM_DOWNCONV_PD_ENUM;

	/* Constants for downconversion from packed 64-bit integers. */

	typedef enum {
		_MM_DOWNCONV_EPI64_NONE       /* no conversion      */
	} _MM_DOWNCONV_EPI64_ENUM;

	extern void __ICL_INTRINCC _mm512_extstore_ps(void*, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_extstore_epi32(void*, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_extstore_pd(void*, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_extstore_epi64(void*, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extstore_ps(void*, __mmask16, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extstore_pd(void*, __mmask8, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extstore_epi32(void*, __mmask16,
		__m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extstore_epi64(void*, __mmask8, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_store_ps(void*, __m512);
#define _mm512_store_si512 _mm512_store_epi32
	extern void __ICL_INTRINCC _mm512_store_epi32(void*, __m512i);
	extern void __ICL_INTRINCC _mm512_store_pd(void*, __m512d);
	extern void __ICL_INTRINCC _mm512_store_epi64(void*, __m512i);
	extern void __ICL_INTRINCC _mm512_mask_store_ps(void*, __mmask16, __m512);
	extern void __ICL_INTRINCC _mm512_mask_store_pd(void*, __mmask8, __m512d);
	extern void __ICL_INTRINCC _mm512_mask_store_epi32(void*, __mmask16, __m512i);
	extern void __ICL_INTRINCC _mm512_mask_store_epi64(void*, __mmask8, __m512i);


	/*
	* Store aligned float32/float64 vector with No-Read hint.
	*/

	extern void __ICL_INTRINCC _mm512_storenr_ps(void*, __m512);
	extern void __ICL_INTRINCC _mm512_storenr_pd(void*, __m512d);

	/*
	* Non-globally ordered store aligned float32/float64 vector with No-Read hint.
	*/

	extern void __ICL_INTRINCC _mm512_storenrngo_ps(void*, __m512);
	extern void __ICL_INTRINCC _mm512_storenrngo_pd(void*, __m512d);

	/*
	* Absolute values of float32 or float64 vector.
	*/
	extern __m512  __ICL_INTRINCC _mm512_abs_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_abs_ps(__m512, __mmask16, __m512);
	extern __m512d __ICL_INTRINCC _mm512_abs_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_abs_pd(__m512d, __mmask8, __m512d);

	/*
	* Add int32 vectors with carry.
	* The carry of the sum is returned via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_adc_epi32(__m512i, __mmask16, __m512i,
		__mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_adc_epi32(__m512i, __mmask16,
		__mmask16,
		__m512i, __mmask16*);
	/*
	* Add float32 or float64 vectors and negate the sum.
	*/
	extern __m512d __ICL_INTRINCC _mm512_addn_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_addn_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_addn_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_addn_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_addn_round_pd(__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_addn_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);

	extern __m512 __ICL_INTRINCC _mm512_addn_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_addn_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);

	/*
	* Add, subtract or multiply float64, float32, int64 or int32 vectors.
	*/
	extern __m512d __ICL_INTRINCC _mm512_add_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_add_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_add_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_add_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_mul_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_mul_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512 __ICL_INTRINCC _mm512_mul_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_mul_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_sub_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sub_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512 __ICL_INTRINCC _mm512_sub_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_sub_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_subr_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_subr_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512 __ICL_INTRINCC _mm512_subr_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_subr_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_add_round_pd(__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_add_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);

	extern __m512 __ICL_INTRINCC _mm512_add_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_add_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);

	extern __m512i __ICL_INTRINCC _mm512_add_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_add_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_add_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_add_epi64(__m512i, __mmask8,
		__m512i, __m512i);

	extern __m512d __ICL_INTRINCC _mm512_mul_round_pd(__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_mul_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);

	extern __m512 __ICL_INTRINCC _mm512_mul_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_mul_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);

	extern __m512d __ICL_INTRINCC _mm512_sub_round_pd(__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_sub_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);

	extern __m512 __ICL_INTRINCC _mm512_sub_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_sub_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);

	extern __m512i __ICL_INTRINCC _mm512_sub_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sub_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512d __ICL_INTRINCC _mm512_subr_round_pd(__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_subr_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);

	extern __m512 __ICL_INTRINCC _mm512_subr_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_subr_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);

	extern __m512i __ICL_INTRINCC _mm512_subr_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_subr_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	/*
	* Add int32 vectors and set carry.
	* The carry from the sum is returned via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_addsetc_epi32(__m512i, __m512i,
		__mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_addsetc_epi32(__m512i, __mmask16,
		__mmask16, __m512i,
		__mmask16*);

	/*
	* Add int32 or float32 Vectors and Set Mask to Sign.  The sign of the result
	* for the n-th element is returned via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_addsets_epi32(__m512i, __m512i,
		__mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_addsets_epi32(__m512i, __mmask16,
		__m512i, __m512i,
		__mmask16*);

	extern __m512 __ICL_INTRINCC _mm512_addsets_ps(__m512, __m512, __mmask16*);
	extern __m512 __ICL_INTRINCC _mm512_mask_addsets_ps(__m512, __mmask16,
		__m512, __m512,
		__mmask16*);

	extern __m512 __ICL_INTRINCC _mm512_addsets_round_ps(__m512, __m512,
		__mmask16*,
		int /* rounding */);
	extern __m512 __ICL_INTRINCC _mm512_mask_addsets_round_ps(__m512, __mmask16,
		__m512, __m512,
		__mmask16*,
		int /* rounding */);

	/*
	* Concatenate vectors, shift right by 'count' int32 elements,
	* and return the low 16 elements.
	*/
	extern __m512i __ICL_INTRINCC _mm512_alignr_epi32(__m512i, __m512i,
		const int /* count */);
	extern __m512i __ICL_INTRINCC _mm512_mask_alignr_epi32(__m512i, __mmask16,
		__m512i, __m512i,
		const int /* count */);
	/*
	* Blending between two vectors.
	*/
	extern __m512i __ICL_INTRINCC _mm512_mask_blend_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_blend_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512  __ICL_INTRINCC _mm512_mask_blend_ps(__mmask16, __m512,
		__m512);
	extern __m512d __ICL_INTRINCC _mm512_mask_blend_pd(__mmask8, __m512d,
		__m512d);

	/*
	* Subtract int32 vectors and set borrow.
	* The borrow from the subtraction for the n-th element
	* is written into the n-th bit of vector mask, via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_subsetb_epi32(__m512i, __m512i,
		__mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_subsetb_epi32(__m512i, __mmask16,
		__mmask16, __m512i,
		__mmask16*);

	/*
	* Reverse subtract int32 vectors and set borrow.
	* The borrow from the subtraction for the n-th element
	* is written into the n-th bit of vector mask, via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_subrsetb_epi32(__m512i, __m512i,
		__mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_subrsetb_epi32(__m512i, __mmask16,
		__mmask16, __m512i,
		__mmask16*);
	/*
	* Subtract int32 vectors with borrow.
	*    Performs an element-by-element three-input subtraction of second int32
	*    vector as well as the corresponding bit of the first mask, from the
	*    first int32 vector.
	*
	*    In addition, the borrow from the subtraction difference for the n-th
	*    element is written into the n-th mask bit via the __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_sbb_epi32(__m512i, __mmask16,
		__m512i, __mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_sbb_epi32(__m512i, __mmask16,
		__mmask16, __m512i,
		__mmask16*);

	/*
	* Reverse subtract int32 vectors with borrow.
	* In addition, the borrow from the subtraction difference for the n-th
	* element is written via the n-th bit of __mmask16 pointer.
	*/
	extern __m512i __ICL_INTRINCC _mm512_sbbr_epi32(__m512i, __mmask16,
		__m512i, __mmask16*);
	extern __m512i __ICL_INTRINCC _mm512_mask_sbbr_epi32(__m512i, __mmask16,
		__mmask16, __m512i,
		__mmask16*);

	/*
	* Bitwise and, and not, or, and xor of int32 or int64 vectors.
	* "and not" ands the ones complement of the first vector operand
	* with the second.
	*/

#define _mm512_and_si512      _mm512_and_epi32
	extern __m512i __ICL_INTRINCC _mm512_and_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_and_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_and_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_and_epi64(__m512i, __mmask8,
		__m512i, __m512i);

#define _mm512_andnot_si512   _mm512_andnot_epi32
	extern __m512i __ICL_INTRINCC _mm512_andnot_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_andnot_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_andnot_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_andnot_epi64(__m512i, __mmask8,
		__m512i, __m512i);

#define _mm512_or_si512       _mm512_or_epi32
	extern __m512i __ICL_INTRINCC _mm512_or_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_or_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_or_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_or_epi64(__m512i, __mmask8,
		__m512i, __m512i);

#define _mm512_xor_si512      _mm512_xor_epi32
	extern __m512i __ICL_INTRINCC _mm512_xor_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_xor_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_xor_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_xor_epi64(__m512i, __mmask8,
		__m512i, __m512i);

	/*
	* Compare float32, float64 or int32 vectors and set mask.
	*/

	/* Constants for integer comparison predicates */
	typedef enum {
		_MM_CMPINT_EQ,      /* Equal */
		_MM_CMPINT_LT,      /* Less than */
		_MM_CMPINT_LE,      /* Less than or Equal */
		_MM_CMPINT_UNUSED,
		_MM_CMPINT_NE,      /* Not Equal */
		_MM_CMPINT_NLT,     /* Not Less than */
#define _MM_CMPINT_GE   _MM_CMPINT_NLT  /* Greater than or Equal */
		_MM_CMPINT_NLE      /* Not Less than or Equal */
#define _MM_CMPINT_GT   _MM_CMPINT_NLE  /* Greater than */
	} _MM_CMPINT_ENUM;

	extern __mmask16 __ICL_INTRINCC _mm512_cmp_epi32_mask(__m512i, __m512i,
		const _MM_CMPINT_ENUM);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_cmp_epi32_mask(__mmask16, __m512i,
		__m512i,
		const _MM_CMPINT_ENUM);

#define _mm512_cmpeq_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpneq_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_NE)
#define _mm512_cmpge_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpgt_epi32_mask(v1, v2) \
    _mm512_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epi32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GT)

	extern __mmask16 __ICL_INTRINCC _mm512_cmp_epu32_mask(__m512i, __m512i,
		const _MM_CMPINT_ENUM);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_cmp_epu32_mask(__mmask16, __m512i,
		__m512i,
		const _MM_CMPINT_ENUM);

#define _mm512_cmpeq_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpneq_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_NE)
#define _mm512_cmpge_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpgt_epu32_mask(v1, v2) \
    _mm512_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epu32_mask(k1, v1, v2) \
    _mm512_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GT)

	extern __mmask8 __ICL_INTRINCC _mm512_cmp_pd_mask(__m512d, __m512d, const int);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_cmp_pd_mask(__mmask8, __m512d,
		__m512d,
		const int);

#define _mm512_cmpeq_pd_mask(v1, v2) _mm512_cmp_pd_mask((v1), (v2), _CMP_EQ_OQ)
#define _mm512_mask_cmpeq_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_EQ_OQ)
#define _mm512_cmplt_pd_mask(v1, v2) _mm512_cmp_pd_mask((v1), (v2), _CMP_LT_OS)
#define _mm512_mask_cmplt_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_LT_OS)
#define _mm512_cmple_pd_mask(v1, v2) _mm512_cmp_pd_mask((v1), (v2), _CMP_LE_OS)
#define _mm512_mask_cmple_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_LE_OS)
#define _mm512_cmpunord_pd_mask(v1, v2) \
    _mm512_cmp_pd_mask((v1), (v2), _CMP_UNORD_Q)
#define _mm512_mask_cmpunord_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_UNORD_Q)
#define _mm512_cmpneq_pd_mask(v1, v2) \
    _mm512_cmp_pd_mask((v1), (v2), _CMP_NEQ_UQ)
#define _mm512_mask_cmpneq_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_NEQ_UQ)
#define _mm512_cmpnlt_pd_mask(v1, v2) \
    _mm512_cmp_pd_mask((v1), (v2), _CMP_NLT_US)
#define _mm512_mask_cmpnlt_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_NLT_US)
#define _mm512_cmpnle_pd_mask(v1, v2) \
    _mm512_cmp_pd_mask((v1), (v2), _CMP_NLE_US)
#define _mm512_mask_cmpnle_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_NLE_US)
#define _mm512_cmpord_pd_mask(v1, v2) \
    _mm512_cmp_pd_mask((v1), (v2), _CMP_ORD_Q)
#define _mm512_mask_cmpord_pd_mask(k1, v1, v2) \
    _mm512_mask_cmp_pd_mask((k1), (v1), (v2), _CMP_ORD_Q)

	extern __mmask8 __ICL_INTRINCC _mm512_cmp_round_pd_mask(__m512d, __m512d,
		const int, const int);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_cmp_round_pd_mask(__mmask8, __m512d,
		__m512d,
		const int,
		const int);

	extern __mmask16 __ICL_INTRINCC _mm512_cmp_ps_mask(__m512, __m512, const int);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_cmp_ps_mask(__mmask16, __m512,
		__m512, const int);

#define _mm512_cmpeq_ps_mask(v1, v2) _mm512_cmp_ps_mask((v1), (v2), _CMP_EQ_OQ)
#define _mm512_mask_cmpeq_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_EQ_OQ)
#define _mm512_cmplt_ps_mask(v1, v2) _mm512_cmp_ps_mask((v1), (v2), _CMP_LT_OS)
#define _mm512_mask_cmplt_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_LT_OS)
#define _mm512_cmple_ps_mask(v1, v2) _mm512_cmp_ps_mask((v1), (v2), _CMP_LE_OS)
#define _mm512_mask_cmple_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_LE_OS)
#define _mm512_cmpunord_ps_mask(v1, v2) \
    _mm512_cmp_ps_mask((v1), (v2), _CMP_UNORD_Q)
#define _mm512_mask_cmpunord_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_UNORD_Q)
#define _mm512_cmpneq_ps_mask(v1, v2) \
    _mm512_cmp_ps_mask((v1), (v2), _CMP_NEQ_UQ)
#define _mm512_mask_cmpneq_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_NEQ_UQ)
#define _mm512_cmpnlt_ps_mask(v1, v2) \
    _mm512_cmp_ps_mask((v1), (v2), _CMP_NLT_US)
#define _mm512_mask_cmpnlt_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_NLT_US)
#define _mm512_cmpnle_ps_mask(v1, v2) \
    _mm512_cmp_ps_mask((v1), (v2), _CMP_NLE_US)
#define _mm512_mask_cmpnle_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_NLE_US)
#define _mm512_cmpord_ps_mask(v1, v2) \
    _mm512_cmp_ps_mask((v1), (v2), _CMP_ORD_Q)
#define _mm512_mask_cmpord_ps_mask(k1, v1, v2) \
    _mm512_mask_cmp_ps_mask((k1), (v1), (v2), _CMP_ORD_Q)

	extern __mmask16 __ICL_INTRINCC _mm512_cmp_round_ps_mask(__m512, __m512,
		const int, const int);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_cmp_round_ps_mask(__mmask16,
		__m512, __m512,
		const int,
		const int);

	extern __m512 __ICL_INTRINCC _mm512_cvt_roundpd_pslo(__m512d, int);
	extern __m512 __ICL_INTRINCC _mm512_mask_cvt_roundpd_pslo(__m512, __mmask8,
		__m512d, int);
#define _mm512_cvtpd_pslo(v2) \
    _mm512_cvt_roundpd_pslo((v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_pslo(v1_old, k1, v2) \
    _mm512_mask_cvt_roundpd_pslo((v1_old), (k1), (v2), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvtfxpnt_roundpd_epi32lo(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtfxpnt_roundpd_epi32lo(__m512i,
		__mmask8,
		__m512d,
		int);
	extern __m512i __ICL_INTRINCC _mm512_cvtfxpnt_roundpd_epu32lo(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtfxpnt_roundpd_epu32lo(__m512i,
		__mmask8,
		__m512d,
		int);

	extern __m512d  __ICL_INTRINCC _mm512_cvtpslo_pd(__m512);
	extern __m512d  __ICL_INTRINCC _mm512_mask_cvtpslo_pd(__m512d, __mmask8,
		__m512);

	extern __m512i __ICL_INTRINCC _mm512_cvtfxpnt_round_adjustps_epi32(__m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtfxpnt_round_adjustps_epi32(
		__m512i,
		__mmask16, __m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512i __ICL_INTRINCC _mm512_cvtfxpnt_round_adjustps_epu32(__m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtfxpnt_round_adjustps_epu32(
		__m512i,
		__mmask16, __m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	/*
	* Convert int32 or unsigned int32 vector to float32 or float64 vector.
	*/

	extern __m512d __ICL_INTRINCC _mm512_cvtepi32lo_pd(__m512i);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvtepi32lo_pd(__m512d, __mmask8,
		__m512i);
	extern __m512d __ICL_INTRINCC _mm512_cvtepu32lo_pd(__m512i);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvtepu32lo_pd(__m512d, __mmask8,
		__m512i);

	extern __m512 __ICL_INTRINCC _mm512_cvtfxpnt_round_adjustepi32_ps(__m512i,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_mask_cvtfxpnt_round_adjustepi32_ps(
		__m512,
		__mmask16,
		__m512i,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_cvtfxpnt_round_adjustepu32_ps(__m512i,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_mask_cvtfxpnt_round_adjustepu32_ps(__m512,
		__mmask16, __m512i,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	/*
	* Approximate the base-2 exponential of an int32 vector representing
	* fixed point values with 8 bits for sign and integer part, and 24 bits
	* for the fraction.
	*/
	extern __m512 __ICL_INTRINCC _mm512_exp223_ps(__m512i);
	extern __m512 __ICL_INTRINCC _mm512_mask_exp223_ps(__m512, __mmask16, __m512i);

	extern __m512d __ICL_INTRINCC _mm512_fixupnan_pd(__m512d, __m512d, __m512i);
	extern __m512d __ICL_INTRINCC _mm512_mask_fixupnan_pd(__m512d, __mmask8,
		__m512d, __m512i);

	extern __m512  __ICL_INTRINCC _mm512_fixupnan_ps(__m512, __m512, __m512i);
	extern __m512  __ICL_INTRINCC _mm512_mask_fixupnan_ps(__m512, __mmask16,
		__m512, __m512i);

	/*
	* Gathers with 32-bit indices.
	*/
	extern __m512i __ICL_INTRINCC _mm512_i32extgather_epi32(__m512i, void const*,
		_MM_UPCONV_EPI32_ENUM,
		int,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_i32extgather_epi32(__m512i,
		__mmask16,
		__m512i /* index */,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int, int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_i32loextgather_epi64(__m512i, void const*,
		_MM_UPCONV_EPI64_ENUM,
		int,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_i32loextgather_epi64(__m512i,
		__mmask8,
		__m512i,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_i32extgather_ps(__m512i, void const*,
		_MM_UPCONV_PS_ENUM, int,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_mask_i32extgather_ps(__m512, __mmask16,
		__m512i, void const*,
		_MM_UPCONV_PS_ENUM,
		int,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_i32loextgather_pd(__m512i, void const*,
		_MM_UPCONV_PD_ENUM, int,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_mask_i32loextgather_pd(__m512d, __mmask8,
		__m512i,
		void const*,
		_MM_UPCONV_PD_ENUM,
		int,
		int /* mem hint */);

#define _mm512_i32gather_epi32(index, addr, scale) \
    _mm512_i32extgather_epi32((index), (addr), _MM_UPCONV_EPI32_NONE, \
                              (scale), _MM_HINT_NONE)

#define _mm512_mask_i32gather_epi32(v1_old, k1, index, addr, scale) \
    _mm512_mask_i32extgather_epi32((v1_old), (k1), (index), (addr), \
                                   _MM_UPCONV_EPI32_NONE, (scale), \
                                   _MM_HINT_NONE)

#define _mm512_i32logather_epi64(index, addr, scale) \
    _mm512_i32loextgather_epi64((index), (addr), _MM_UPCONV_EPI64_NONE, \
                                (scale), _MM_HINT_NONE)

#define _mm512_mask_i32logather_epi64(v1_old, k1, index, addr, scale) \
    _mm512_mask_i32loextgather_epi64((v1_old), (k1), (index), (addr), \
                                     _MM_UPCONV_EPI64_NONE, (scale), \
                                     _MM_HINT_NONE)

#define _mm512_i32gather_ps(index, addr, scale) \
    _mm512_i32extgather_ps((index), (addr), _MM_UPCONV_PS_NONE, \
                           (scale), _MM_HINT_NONE)

#define _mm512_mask_i32gather_ps(v1_old, k1, index, addr, scale) \
    _mm512_mask_i32extgather_ps((v1_old), (k1), (index), (addr), \
                                _MM_UPCONV_PS_NONE, (scale), _MM_HINT_NONE)

#define _mm512_i32logather_pd(index, addr, scale) \
    _mm512_i32loextgather_pd((index), (addr), _MM_UPCONV_PD_NONE, \
                             (scale), _MM_HINT_NONE)

#define _mm512_mask_i32logather_pd(v1_old, k1, index, addr, scale) \
    _mm512_mask_i32loextgather_pd((v1_old), (k1), (index), (addr), \
                                  _MM_UPCONV_PD_NONE, (scale), _MM_HINT_NONE)

	/*
	* Gathers with 64-bit indices.
	*/
	extern __m512i __ICL_INTRINCC _mm512_i64extgather_epi32lo(__m512i, void const*,
		_MM_UPCONV_EPI32_ENUM,
		int,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_i64extgather_epi32lo(__m512i,
		__mmask8,
		__m512i /* index */,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int, int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_i64extgather_epi64(__m512i, void const*,
		_MM_UPCONV_EPI64_ENUM,
		int,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_i64extgather_epi64(__m512i,
		__mmask8,
		__m512i,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_i64extgather_pslo(__m512i, void const*,
		_MM_UPCONV_PS_ENUM, int,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_mask_i64extgather_pslo(__m512, __mmask8,
		__m512i, void const*,
		_MM_UPCONV_PS_ENUM,
		int,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_i64extgather_pd(__m512i, void const*,
		_MM_UPCONV_PD_ENUM, int,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_mask_i64extgather_pd(__m512d, __mmask8,
		__m512i,
		void const*,
		_MM_UPCONV_PD_ENUM,
		int,
		int /* mem hint */);

#define _mm512_i64gather_epi32lo(index, addr, scale)                    \
    _mm512_i64extgather_epi32lo((index), (addr), _MM_UPCONV_EPI32_NONE, \
                                (scale), _MM_HINT_NONE)

#define _mm512_mask_i64gather_epi32lo(v1_old, k1, index, addr, scale) \
    _mm512_mask_i64extgather_epi32lo((v1_old), (k1), (index), (addr), \
                                     _MM_UPCONV_EPI32_NONE, (scale),  \
                                     _MM_HINT_NONE)

#define _mm512_i64gather_epi64(index, addr, scale)                    \
    _mm512_i64extgather_epi64((index), (addr), _MM_UPCONV_EPI64_NONE, \
                              (scale), _MM_HINT_NONE)

#define _mm512_mask_i64gather_epi64(v1_old, k1, index, addr, scale) \
    _mm512_mask_i64extgather_epi64((v1_old), (k1), (index), (addr), \
                                   _MM_UPCONV_EPI64_NONE, (scale),  \
                                   _MM_HINT_NONE)

#define _mm512_i64gather_pslo(index, addr, scale)                 \
    _mm512_i64extgather_pslo((index), (addr), _MM_UPCONV_PS_NONE, \
                             (scale), _MM_HINT_NONE)

#define _mm512_mask_i64gather_pslo(v1_old, k1, index, addr, scale) \
    _mm512_mask_i64extgather_pslo((v1_old), (k1), (index), (addr), \
                                  _MM_UPCONV_PS_NONE, (scale), _MM_HINT_NONE)

#define _mm512_i64gather_pd(index, addr, scale)                 \
    _mm512_i64extgather_pd((index), (addr), _MM_UPCONV_PD_NONE, \
                           (scale), _MM_HINT_NONE)

#define _mm512_mask_i64gather_pd(v1_old, k1, index, addr, scale) \
    _mm512_mask_i64extgather_pd((v1_old), (k1), (index), (addr), \
                                  _MM_UPCONV_PD_NONE, (scale), _MM_HINT_NONE)


	extern void __ICL_INTRINCC _mm512_prefetch_i32extgather_ps(__m512i,
		void const*,
		_MM_UPCONV_PS_ENUM,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i32extgather_ps(
		__m512i /* index */,
		__mmask16,
		void const*,
		_MM_UPCONV_PS_ENUM,
		int /* scale */,
		int /* pf hint */);

#define _mm512_prefetch_i32gather_ps(index, addr, scale, pf_hint) \
    _mm512_prefetch_i32extgather_ps((index), (addr), _MM_UPCONV_PS_NONE, \
                                    (scale), (pf_hint))

#define _mm512_mask_prefetch_i32gather_ps(index, k1, addr, scale, pf_hint) \
    _mm512_mask_prefetch_i32extgather_ps((index), (k1), (addr), \
                                         _MM_UPCONV_PS_NONE, (scale), \
                                         (pf_hint))

	extern void __ICL_INTRINCC _mm512_i32extscatter_ps(void*, __m512i, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i32extscatter_ps(void*, __mmask16,
		__m512i, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i32loextscatter_pd(void*, __m512i, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i32loextscatter_pd(void*, __mmask8,
		__m512i, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i32extscatter_epi32(void*, __m512i, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i32extscatter_epi32(void*, __mmask16,
		__m512i, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i32loextscatter_epi64(void*, __m512i,
		__m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i32loextscatter_epi64(void*, __mmask8,
		__m512i, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* scale */,
		int /* mem hint */);

#define _mm512_i32scatter_ps(addr, index, v1, scale) \
    _mm512_i32extscatter_ps((addr), (index), (v1), _MM_DOWNCONV_PS_NONE, \
                            (scale), _MM_HINT_NONE)

#define _mm512_mask_i32scatter_ps(addr, k1, index, v1, scale) \
    _mm512_mask_i32extscatter_ps((addr), (k1), (index), (v1), \
                                 _MM_DOWNCONV_PS_NONE, (scale), _MM_HINT_NONE)

#define _mm512_i32loscatter_pd(addr, index, v1, scale) \
    _mm512_i32loextscatter_pd((addr), (index), (v1), _MM_DOWNCONV_PD_NONE, \
                              (scale), _MM_HINT_NONE)

#define _mm512_mask_i32loscatter_pd(addr, k1, index, v1, scale) \
    _mm512_mask_i32loextscatter_pd((addr), (k1), (index), (v1), \
                                   _MM_DOWNCONV_PD_NONE, (scale), \
                                   _MM_HINT_NONE)

#define _mm512_i32scatter_epi32(addr, index, v1, scale) \
    _mm512_i32extscatter_epi32((addr), (index), (v1), \
                               _MM_DOWNCONV_EPI32_NONE, (scale), _MM_HINT_NONE)

#define _mm512_mask_i32scatter_epi32(addr, k1, index, v1, scale) \
    _mm512_mask_i32extscatter_epi32((addr), (k1), (index), (v1), \
                                    _MM_DOWNCONV_EPI32_NONE, (scale), \
                                    _MM_HINT_NONE)

#define _mm512_i32loscatter_epi64(addr, index, v1, scale) \
    _mm512_i32loextscatter_epi64((addr), (index), (v1), \
                                 _MM_DOWNCONV_EPI64_NONE, (scale), \
                                 _MM_HINT_NONE)

#define _mm512_mask_i32loscatter_epi64(addr, k1, index, v1, scale) \
    _mm512_mask_i32loextscatter_epi64((addr), (k1), (index), (v1), \
                                      _MM_DOWNCONV_EPI64_NONE, (scale), \
                                      _MM_HINT_NONE)

	/*
	* Scatters with 64-bit indices.
	*/
	extern void __ICL_INTRINCC _mm512_i64extscatter_pslo(void*, __m512i, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i64extscatter_pslo(void*, __mmask8,
		__m512i, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i64extscatter_pd(void*, __m512i, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i64extscatter_pd(void*, __mmask8,
		__m512i, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i64extscatter_epi32lo(void*, __m512i,
		__m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i64extscatter_epi32lo(void*, __mmask8,
		__m512i, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_i64extscatter_epi64(void*, __m512i,
		__m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* scale */,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_mask_i64extscatter_epi64(void*, __mmask8,
		__m512i, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* scale */,
		int /* mem hint */);

#define _mm512_i64scatter_pslo(addr, index, v1, scale) \
    _mm512_i64extscatter_pslo((addr), (index), (v1),   \
                              _MM_DOWNCONV_PS_NONE,    \
                              (scale), _MM_HINT_NONE)

#define _mm512_mask_i64scatter_pslo(addr, k1, index, v1, scale) \
    _mm512_mask_i64extscatter_pslo((addr), (k1), (index), (v1), \
                                    _MM_DOWNCONV_PS_NONE,       \
                                    (scale), _MM_HINT_NONE)

#define _mm512_i64scatter_pd(addr, index, v1, scale) \
    _mm512_i64extscatter_pd((addr), (index), (v1),   \
                            _MM_DOWNCONV_PD_NONE,    \
                            (scale), _MM_HINT_NONE)

#define _mm512_mask_i64scatter_pd(addr, k1, index, v1, scale) \
    _mm512_mask_i64extscatter_pd((addr), (k1), (index), (v1), \
                                 _MM_DOWNCONV_PD_NONE,        \
                                 (scale), _MM_HINT_NONE)

#define _mm512_i64scatter_epi32lo(addr, index, v1, scale) \
    _mm512_i64extscatter_epi32lo((addr), (index), (v1),   \
                                 _MM_DOWNCONV_EPI32_NONE, \
                                 (scale), _MM_HINT_NONE)

#define _mm512_mask_i64scatter_epi32lo(addr, k1, index, v1, scale) \
    _mm512_mask_i64extscatter_epi32lo((addr), (k1), (index), (v1), \
                                      _MM_DOWNCONV_EPI32_NONE,     \
                                      (scale), _MM_HINT_NONE)

#define _mm512_i64scatter_epi64(addr, index, v1, scale) \
    _mm512_i64extscatter_epi64((addr), (index), (v1),   \
                               _MM_DOWNCONV_EPI64_NONE, \
                               (scale), _MM_HINT_NONE)

#define _mm512_mask_i64scatter_epi64(addr, k1, index, v1, scale) \
    _mm512_mask_i64extscatter_epi64((addr), (k1), (index), (v1), \
                                    _MM_DOWNCONV_EPI64_NONE,     \
                                    (scale), _MM_HINT_NONE)

	/*
	* Scatter prefetch element vector.
	*/

	extern void __ICL_INTRINCC _mm512_prefetch_i32extscatter_ps(void*, __m512i,
		_MM_UPCONV_PS_ENUM,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i32extscatter_ps(void*,
		__mmask16, __m512i,
		_MM_UPCONV_PS_ENUM,
		int /* scale */,
		int /* pf hint */);

#define _mm512_prefetch_i32scatter_ps(addr, index, scale, pf_hint) \
    _mm512_prefetch_i32extscatter_ps((addr), (index), _MM_UPCONV_PS_NONE, \
                                     (scale), (pf_hint))

#define _mm512_mask_prefetch_i32scatter_ps(addr, k1, index, scale, pf_hint) \
    _mm512_mask_prefetch_i32extscatter_ps((addr), (k1), (index), \
                                          _MM_UPCONV_PS_NONE, (scale), \
                                          (pf_hint))


	/*
	* Extract float32 vector of exponents.
	*/
	extern __m512 __ICL_INTRINCC _mm512_getexp_ps(__m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_getexp_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_getexp_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_getexp_pd(__m512d, __mmask8,
		__m512d);

	/*
	* Extract float32 or float64 normalized mantissas.
	*/

	/* Constants for mantissa extraction */
	typedef enum {
		_MM_MANT_NORM_1_2,      /* interval [1, 2)      */
		_MM_MANT_NORM_p5_2,     /* interval [1.5, 2)    */
		_MM_MANT_NORM_p5_1,     /* interval [1.5, 1)    */
		_MM_MANT_NORM_p75_1p5   /* interval [0.75, 1.5) */
	} _MM_MANTISSA_NORM_ENUM;

	typedef enum {
		_MM_MANT_SIGN_src,      /* sign = sign(SRC)     */
		_MM_MANT_SIGN_zero,     /* sign = 0             */
		_MM_MANT_SIGN_nan       /* DEST = NaN if sign(SRC) = 1 */
	} _MM_MANTISSA_SIGN_ENUM;

	extern __m512d __ICL_INTRINCC _mm512_getmant_pd(__m512d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m512d __ICL_INTRINCC _mm512_mask_getmant_pd(__m512d, __mmask8,
		__m512d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	extern __m512  __ICL_INTRINCC _mm512_getmant_ps(__m512,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m512  __ICL_INTRINCC _mm512_mask_getmant_ps(__m512, __mmask16, __m512,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	/*
	* Load unaligned high and unpack to doubleword vector.
	*    The high-64-byte portion of the byte/word/doubleword stream starting
	*    at the element-aligned address is loaded, converted and expanded
	*    into the writemask-enabled elements of doubleword vector.
	*    Doubleword vector is returned.
	*
	*    The number of set bits in the writemask determines the length of the
	*    converted doubleword stream, as each converted doubleword is mapped
	*    to exactly one of the doubleword elements in returned vector, skipping
	*    over writemasked elements.
	*/
	extern __m512i __ICL_INTRINCC _mm512_extloadunpackhi_epi32(__m512i,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_extloadunpackhi_epi32(__m512i,
		__mmask16,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_extloadunpacklo_epi32(__m512i,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_extloadunpacklo_epi32(__m512i,
		__mmask16,
		void const*,
		_MM_UPCONV_EPI32_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_extloadunpackhi_epi64(__m512i,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_extloadunpackhi_epi64(__m512i,
		__mmask8,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_extloadunpacklo_epi64(__m512i,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int /* mem hint */);

	extern __m512i __ICL_INTRINCC _mm512_mask_extloadunpacklo_epi64(__m512i,
		__mmask8,
		void const*,
		_MM_UPCONV_EPI64_ENUM,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_extloadunpackhi_ps(__m512, void const*,
		_MM_UPCONV_PS_ENUM,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_mask_extloadunpackhi_ps(__m512, __mmask16,
		void const*,
		_MM_UPCONV_PS_ENUM,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_extloadunpacklo_ps(__m512, void const*,
		_MM_UPCONV_PS_ENUM,
		int /* mem hint */);

	extern __m512  __ICL_INTRINCC _mm512_mask_extloadunpacklo_ps(__m512,
		__mmask16,
		void const*,
		_MM_UPCONV_PS_ENUM,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_extloadunpackhi_pd(__m512d,
		void const*,
		_MM_UPCONV_PD_ENUM,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_mask_extloadunpackhi_pd(__m512d, __mmask8,
		void const*,
		_MM_UPCONV_PD_ENUM,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_extloadunpacklo_pd(__m512d, void const*,
		_MM_UPCONV_PD_ENUM,
		int /* mem hint */);

	extern __m512d __ICL_INTRINCC _mm512_mask_extloadunpacklo_pd(__m512d, __mmask8,
		void const*,
		_MM_UPCONV_PD_ENUM,
		int /* mem hint */);

#define _mm512_loadunpackhi_epi32(v1_old, addr) \
    _mm512_extloadunpackhi_epi32((v1_old), (addr), \
                                 _MM_UPCONV_EPI32_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpackhi_epi32(v1_old, k1, addr) \
    _mm512_mask_extloadunpackhi_epi32((v1_old), (k1), (addr), \
                                      _MM_UPCONV_EPI32_NONE, _MM_HINT_NONE)

#define _mm512_loadunpacklo_epi32(v1_old, addr) \
    _mm512_extloadunpacklo_epi32((v1_old), (addr), \
                                 _MM_UPCONV_EPI32_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpacklo_epi32(v1_old, k1, addr) \
    _mm512_mask_extloadunpacklo_epi32((v1_old), (k1), (addr), \
                                      _MM_UPCONV_EPI32_NONE, _MM_HINT_NONE)

#define _mm512_loadunpackhi_epi64(v1_old, addr) \
    _mm512_extloadunpackhi_epi64((v1_old), (addr), \
                                 _MM_UPCONV_EPI64_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpackhi_epi64(v1_old, k1, addr) \
    _mm512_mask_extloadunpackhi_epi64((v1_old), (k1), (addr), \
                                      _MM_UPCONV_EPI64_NONE, _MM_HINT_NONE)

#define _mm512_loadunpacklo_epi64(v1_old, addr) \
    _mm512_extloadunpacklo_epi64((v1_old), (addr), \
                                 _MM_UPCONV_EPI64_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpacklo_epi64(v1_old, k1, addr) \
    _mm512_mask_extloadunpacklo_epi64((v1_old), (k1), (addr), \
                                      _MM_UPCONV_EPI64_NONE, _MM_HINT_NONE)

#define _mm512_loadunpackhi_ps(v1_old, addr) \
    _mm512_extloadunpackhi_ps((v1_old), (addr), \
                              _MM_UPCONV_PS_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpackhi_ps(v1_old, k1, addr) \
    _mm512_mask_extloadunpackhi_ps((v1_old), (k1), (addr), \
                                   _MM_UPCONV_PS_NONE, _MM_HINT_NONE)

#define _mm512_loadunpacklo_ps(v1_old, addr) \
    _mm512_extloadunpacklo_ps((v1_old), (addr), \
                              _MM_UPCONV_PS_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpacklo_ps(v1_old, k1, addr) \
    _mm512_mask_extloadunpacklo_ps((v1_old), (k1), (addr), \
                                   _MM_UPCONV_PS_NONE, _MM_HINT_NONE)

#define _mm512_loadunpackhi_pd(v1_old, addr) \
    _mm512_extloadunpackhi_pd((v1_old), (addr), \
                              _MM_UPCONV_PD_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpackhi_pd(v1_old, k1, addr) \
    _mm512_mask_extloadunpackhi_pd((v1_old), (k1), (addr), \
                                   _MM_UPCONV_PD_NONE, _MM_HINT_NONE)

#define _mm512_loadunpacklo_pd(v1_old, addr) \
    _mm512_extloadunpacklo_pd((v1_old), (addr), \
                              _MM_UPCONV_PD_NONE, _MM_HINT_NONE)
#define _mm512_mask_loadunpacklo_pd(v1_old, k1, addr) \
    _mm512_mask_extloadunpacklo_pd((v1_old), (k1), (addr), \
                                   _MM_UPCONV_PD_NONE, _MM_HINT_NONE)


	extern void __ICL_INTRINCC _mm512_extpackstorehi_epi32(void*, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorehi_epi32(void*, __mmask16,
		__m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorelo_epi32(void*, __m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorelo_epi32(void*, __mmask16,
		__m512i,
		_MM_DOWNCONV_EPI32_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorehi_epi64(void*, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorehi_epi64(void*, __mmask8,
		__m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorelo_epi64(void*, __m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorelo_epi64(void*, __mmask8,
		__m512i,
		_MM_DOWNCONV_EPI64_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorehi_ps(void*, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorehi_ps(void*, __mmask16,
		__m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorelo_ps(void*, __m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorelo_ps(void*, __mmask16,
		__m512,
		_MM_DOWNCONV_PS_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorehi_pd(void*, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorehi_pd(void*, __mmask8,
		__m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);

	extern void __ICL_INTRINCC _mm512_extpackstorelo_pd(void*, __m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);
	extern void __ICL_INTRINCC _mm512_mask_extpackstorelo_pd(void*, __mmask8,
		__m512d,
		_MM_DOWNCONV_PD_ENUM,
		int /* mem hint */);

#define _mm512_packstorehi_epi32(addr, v1) \
    _mm512_extpackstorehi_epi32((addr), (v1), \
                                _MM_DOWNCONV_EPI32_NONE, 0)
#define _mm512_mask_packstorehi_epi32(addr, k1, v1) \
    _mm512_mask_extpackstorehi_epi32((addr), (k1), (v1), \
                                _MM_DOWNCONV_EPI32_NONE, 0)

#define _mm512_packstorelo_epi32(addr, v1) \
    _mm512_extpackstorelo_epi32((addr), (v1), \
                                _MM_DOWNCONV_EPI32_NONE, 0)
#define _mm512_mask_packstorelo_epi32(addr, k1, v1) \
    _mm512_mask_extpackstorelo_epi32((addr), (k1), (v1), \
                                _MM_DOWNCONV_EPI32_NONE, 0)

#define _mm512_packstorehi_epi64(addr, v1) \
    _mm512_extpackstorehi_epi64((addr), (v1), _MM_DOWNCONV_EPI64_NONE, 0)
#define _mm512_mask_packstorehi_epi64(addr, k1, v1) \
    _mm512_mask_extpackstorehi_epi64((addr), (k1), (v1), \
                                     _MM_DOWNCONV_EPI64_NONE, 0)

#define _mm512_packstorelo_epi64(addr, v1) \
    _mm512_extpackstorelo_epi64((addr), (v1), _MM_DOWNCONV_EPI64_NONE, 0)
#define _mm512_mask_packstorelo_epi64(addr, k1, v1) \
    _mm512_mask_extpackstorelo_epi64((addr), (k1), (v1), \
                                     _MM_DOWNCONV_EPI64_NONE, 0)

#define _mm512_packstorehi_ps(addr, v1) \
    _mm512_extpackstorehi_ps((addr), (v1), _MM_DOWNCONV_PS_NONE, 0)
#define _mm512_mask_packstorehi_ps(addr, k1, v1) \
    _mm512_mask_extpackstorehi_ps((addr), (k1), (v1), _MM_DOWNCONV_PS_NONE, 0)

#define _mm512_packstorelo_ps(addr, v1) \
    _mm512_extpackstorelo_ps((addr), (v1), _MM_DOWNCONV_PS_NONE, 0)
#define _mm512_mask_packstorelo_ps(addr, k1, v1) \
    _mm512_mask_extpackstorelo_ps((addr), (k1), (v1), _MM_DOWNCONV_PS_NONE, 0)

#define _mm512_packstorehi_pd(addr, v1) \
    _mm512_extpackstorehi_pd((addr), (v1), _MM_DOWNCONV_PD_NONE, 0)
#define _mm512_mask_packstorehi_pd(addr, k1, v1) \
    _mm512_mask_extpackstorehi_pd((addr), (k1), (v1) ,_MM_DOWNCONV_PD_NONE, 0)

#define _mm512_packstorelo_pd(addr, v1) \
    _mm512_extpackstorelo_pd((addr), (v1), _MM_DOWNCONV_PD_NONE, 0)
#define _mm512_mask_packstorelo_pd(addr, k1, v1) \
    _mm512_mask_extpackstorelo_pd((addr), (k1), (v1), _MM_DOWNCONV_PD_NONE, 0)


	/*
	* Logarithm base-2 of float32 vector, with absolute error
	* bounded by 2^(-23).
	*/

	extern __m512 __ICL_INTRINCC _mm512_log2ae23_ps(__m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_log2ae23_ps(__m512, __mmask16,
		__m512);

	/*
	* Fused multiply and add of float32, float64 or int32 vectors.
	*
	* This group of FMA instructions computes the following
	*
	*  fmadd       (v1 * v2) + v3
	*  fmsub       (v1 * v2) - v3
	*  fnmadd     -(v1 * v2) + v3
	*  fnmsub     -(v1 * v2) - v3
	*  fnmadd1    -(v1 * v2) + 1.0
	*
	* When a write-mask is used, the pass-through values come from the
	* vector parameter immediately preceding the mask parameter.  For example,
	* for _mm512_mask_fmadd_ps(__m512 v1, __mmask16 k1, __m512 v2, __m512 v3) the
	* pass through values come from v1, while for
	* _mm512_mask3_fmadd_ps(__m512 v1, __m512 v2, __m512 v3, __mmask16 k3)
	* the pass through values come from v3.  To get pass through values
	* from v2, just reverse the order of v1 and v2 in the "_mask_" form.
	*/

	extern __m512  __ICL_INTRINCC _mm512_fmadd_round_ps(__m512, __m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_fmadd_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask3_fmadd_round_ps(__m512, __m512,
		__m512, __mmask16,
		int /* rounding */);
#define _mm512_fmadd_ps(v1, v2, v3) \
    _mm512_fmadd_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmadd_ps(v1, k1, v2, v3) \
    _mm512_mask_fmadd_round_ps((v1), (k1), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmadd_ps(v1, v2, v3, k3) \
    _mm512_mask3_fmadd_round_ps((v1), (v2), (v3), (k3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fmadd_round_pd(__m512d, __m512d,
		__m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_fmadd_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fmadd_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		int /* rounding */);
#define _mm512_fmadd_pd(v1, v2, v3) \
    _mm512_fmadd_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmadd_pd(v1, k1, v2, v3) \
    _mm512_mask_fmadd_round_pd((v1), (k1), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmadd_pd(v1, v2, v3, k3) \
    _mm512_mask3_fmadd_round_pd((v1), (v2), (v3), (k3), \
                                _MM_FROUND_CUR_DIRECTION)


	extern __m512i __ICL_INTRINCC _mm512_fmadd_epi32(__m512i, __m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_fmadd_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask3_fmadd_epi32(__m512i, __m512i,
		__m512i, __mmask16);

	extern __m512  __ICL_INTRINCC _mm512_fmsub_round_ps(__m512, __m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_fmsub_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask3_fmsub_round_ps(__m512, __m512,
		__m512, __mmask16,
		int /* rounding */);
#define _mm512_fmsub_ps(v1, v2, v3) \
    _mm512_fmsub_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmsub_ps(v1, k1, v2, v3) \
    _mm512_mask_fmsub_round_ps((v1), (k1), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmsub_ps(v1, v2, v3, k3) \
    _mm512_mask3_fmsub_round_ps((v1), (v2), (v3), (k3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fmsub_round_pd(__m512d, __m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_fmsub_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fmsub_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		int /* rounding */);
#define _mm512_fmsub_pd(v1, v2, v3) \
    _mm512_fmsub_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmsub_pd(v1, k1, v2, v3) \
    _mm512_mask_fmsub_round_pd((v1), (k1), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmsub_pd(v1, v2, v3, k3) \
    _mm512_mask3_fmsub_round_pd((v1), (v2), (v3), (k3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_fnmadd_round_ps(__m512, __m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_fnmadd_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask3_fnmadd_round_ps(__m512, __m512,
		__m512, __mmask16,
		int /* rounding */);
#define _mm512_fnmadd_ps(v1, v2, v3) \
    _mm512_fnmadd_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fnmadd_ps(v1, k1, v2, v3) \
    _mm512_mask_fnmadd_round_ps((v1), (k1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fnmadd_ps(v1, v2, v3, k3) \
    _mm512_mask3_fnmadd_round_ps((v1), (v2), (v3), (k3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fnmadd_round_pd(__m512d, __m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_fnmadd_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fnmadd_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		int /* rounding */);
#define _mm512_fnmadd_pd(v1, v2, v3) \
    _mm512_fnmadd_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fnmadd_pd(v1, k1, v2, v3) \
    _mm512_mask_fnmadd_round_pd((v1), (k1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fnmadd_pd(v1, v2, v3, k3) \
    _mm512_mask3_fnmadd_round_pd((v1), (v2), (v3), (k3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_fnmsub_round_ps(__m512, __m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_fnmsub_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask3_fnmsub_round_ps(__m512, __m512,
		__m512, __mmask16,
		int /* rounding */);
#define _mm512_fnmsub_ps(v1, v2, v3) \
    _mm512_fnmsub_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fnmsub_ps(v1, k1, v2, v3) \
    _mm512_mask_fnmsub_round_ps((v1), (k1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fnmsub_ps(v1, v2, v3, k3) \
    _mm512_mask3_fnmsub_round_ps((v1), (v2), (v3), (k3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fnmsub_round_pd(__m512d, __m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_fnmsub_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fnmsub_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		int /* rounding */);
#define _mm512_fnmsub_pd(v1, v2, v3) \
    _mm512_fnmsub_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fnmsub_pd(v1, k1, v2, v3) \
    _mm512_mask_fnmsub_round_pd((v1), (k1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fnmsub_pd(v1, v2, v3, k3) \
    _mm512_mask3_fnmsub_round_pd((v1), (v2), (v3), (k3), \
                                 _MM_FROUND_CUR_DIRECTION)

	/*
	* Multiply and add int32 or float32 vectors with alternating elements.
	*
	*    Multiply vector v2 by certain elements of vector v3, and add that
	*    result to certain other elements of v3.
	*
	*    This intrinsic is built around the concept of 4-element sets, of which
	*    there are four elements 0-3, 4-7, 8-11, and 12-15.
	*    Each element 0-3 of vector v2 is multiplied by element 1 of v3,
	*    the result is added to element 0 of v3, and the final sum is written
	*    into the corresponding element 0-3 of the result vector.
	*    Similarly each element 4-7 of v2 is multiplied by element 5 of v3,
	*    and added to element 4 of v3.
	*    Each element 8-11 of v2 is multiplied by element 9 of v3,
	*    and added to element 8 of v3.
	*    Each element 12-15 of vector v2 is multiplied by element 13 of v3,
	*    and added to element 12 of v3.
	*/
	extern __m512i __ICL_INTRINCC _mm512_fmadd233_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_fmadd233_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512  __ICL_INTRINCC _mm512_fmadd233_round_ps(__m512, __m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_fmadd233_round_ps(__m512, __mmask16,
		__m512, __m512,
		int /* rounding */);
#define _mm512_fmadd233_ps(v2, v3) \
    _mm512_fmadd233_round_ps((v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmadd233_ps(v1_old, k1, v2, v3) \
    _mm512_mask_fmadd233_round_ps((v1_old), (k1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)

	/*
	* Minimum or maximum of float32, float64, int32 or unsigned int32 vectors.
	*
	* gmaxabs returns maximum of absolute values of source operands.
	* gmax, gmaxabs and gmin have DX10 and IEEE 754R semantics:
	*
	* gmin     dest = src0 < src1 ? src0 : src1
	* gmax:    dest = src0 >= src1 ? src0 : src1
	*          >= is used instead of > so that
	*          if gmin(x,y) = x then gmax(x,y) = y.
	*
	*    NaN has special handling: If one source operand is NaN, then the other
	*    source operand is returned (choice made per-component).  If both are NaN,
	*    then the quietized NaN from the first source is returned.
	*/

	extern __m512 __ICL_INTRINCC _mm512_max_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_max_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512 __ICL_INTRINCC _mm512_maxabs_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_maxabs_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_max_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_max_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512i __ICL_INTRINCC _mm512_max_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_max_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epu32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512 __ICL_INTRINCC _mm512_min_ps(__m512, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_min_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_min_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_min_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512i __ICL_INTRINCC _mm512_min_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_min_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_min_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_min_epu32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512  __ICL_INTRINCC _mm512_gmax_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_gmax_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512  __ICL_INTRINCC _mm512_gmaxabs_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_gmaxabs_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_gmax_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_gmax_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_gmin_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_gmin_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_gmin_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_gmin_pd(__m512d, __mmask8,
		__m512d, __m512d);

	/*
	* Multiply int32 or unsigned int32 vectors, and select the high or low
	* half of the 64-bit result.
	*/
	extern __m512i __ICL_INTRINCC _mm512_mulhi_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mulhi_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_mulhi_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mulhi_epu32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_mullo_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mullo_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	/*
	* Multiply packed signed int64 elements, and select the low 64-bits
	* of each product.
	*/
	extern __m512i __ICL_INTRINCC _mm512_mullox_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mullox_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	/*
	* Permute 32-bit elements of last vector according to indexes in next
	* to last vector.
	* The i'th element of the result is the j'th element of last vector,
	* where j is the i'th element of next to last vector.
	*/
	extern __m512i __ICL_INTRINCC _mm512_permutevar_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutevar_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	/*
	* These "permutev" names are deprecated and will be removed.
	* Use the "permutevar" names going forward.
	*/
#define _mm512_permutev_epi32 _mm512_permutevar_epi32
#define _mm512_mask_permutev_epi32 _mm512_mask_permutevar_epi32

	/*
	* Permute the four 128-bit elements of v2 according to indexes in 'perm'.
	*/
	extern __m512i __ICL_INTRINCC _mm512_permute4f128_epi32(__m512i,
		_MM_PERM_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_permute4f128_epi32(__m512i,
		__mmask16,
		__m512i,
		_MM_PERM_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_permute4f128_ps(__m512, _MM_PERM_ENUM);
	extern __m512 __ICL_INTRINCC _mm512_mask_permute4f128_ps(__m512, __mmask16,
		__m512,
		_MM_PERM_ENUM);

	/*
	* Approximate the reciprocals of the float32 elements in v2 with
	* 23 bits of accuracy.
	*/
	extern __m512 __ICL_INTRINCC _mm512_rcp23_ps(__m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_rcp23_ps(__m512, __mmask16, __m512);

	/*
	* Round float32 or float64 vector.
	*/
	extern __m512 __ICL_INTRINCC _mm512_round_ps(__m512, int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_mask_round_ps(__m512, __mmask16,
		__m512, int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_roundfxpnt_adjust_ps(__m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512 __ICL_INTRINCC _mm512_mask_roundfxpnt_adjust_ps(__m512,
		__mmask16, __m512,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512d __ICL_INTRINCC _mm512_roundfxpnt_adjust_pd(__m512d,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	extern __m512d __ICL_INTRINCC _mm512_mask_roundfxpnt_adjust_pd(__m512d,
		__mmask8, __m512d,
		int /* rounding */,
		_MM_EXP_ADJ_ENUM);

	/*
	* Reciprocal square root of float32 vector to 0.775ULP accuracy.
	*/
	extern __m512 __ICL_INTRINCC _mm512_rsqrt23_ps(__m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_rsqrt23_ps(__m512, __mmask16, __m512);

	/*
	* Scale float32 vectors.
	*/
	extern __m512  __ICL_INTRINCC _mm512_scale_ps(__m512, __m512i);
	extern __m512  __ICL_INTRINCC _mm512_mask_scale_ps(__m512, __mmask16,
		__m512, __m512i);

	extern __m512  __ICL_INTRINCC _mm512_scale_round_ps(__m512, __m512i,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_scale_round_ps(__m512, __mmask16,
		__m512, __m512i,
		int /* rounding */);

	extern __m512i __ICL_INTRINCC _mm512_shuffle_epi32(__m512i, _MM_PERM_ENUM);
	extern __m512i __ICL_INTRINCC _mm512_mask_shuffle_epi32(__m512i, __mmask16,
		__m512i,
		_MM_PERM_ENUM);

	/*
	* Shift int32 vector by full variable count.
	*
	*    Performs an element-by-element shift of int32 vector, shifting by the
	*    number of bits given by the corresponding int32 element of last vector.
	*    If the shift count is greater than 31 then for logical shifts the result
	*    is zero, and for arithmetic right shifts the result is all ones or all
	*    zeroes depending on the original sign bit.
	*
	*    sllv   logical shift left
	*    srlv   logical shift right
	*    srav   arithmetic shift right
	*/

	extern __m512i __ICL_INTRINCC _mm512_sllv_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sllv_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_srav_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srav_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_srlv_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srlv_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	/*
	* Shift int32 vector by full immediate count.
	*
	*    Performs an element-by-element shift of int32 vector , shifting
	*    by the number of bits given by count.  If the count is greater than
	*    31 then for logical shifts the result is zero, and for arithmetic
	*    right shifts the result is all ones or all zeroes depending on the
	*    original sign bit.
	*
	*    slli   logical shift left
	*    srli   logical shift right
	*    srai   arithmetic shift right
	*/

	extern __m512i __ICL_INTRINCC _mm512_slli_epi32(__m512i,
		unsigned int /* count */);
	extern __m512i __ICL_INTRINCC _mm512_mask_slli_epi32(__m512i, __mmask16,
		__m512i, unsigned int);

	extern __m512i __ICL_INTRINCC _mm512_srai_epi32(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srai_epi32(__m512i, __mmask16,
		__m512i, unsigned int);

	extern __m512i __ICL_INTRINCC _mm512_srli_epi32(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srli_epi32(__m512i, __mmask16,
		__m512i, unsigned int);

	/*
	* Logical AND and set vector mask.
	*
	*    Performs an element-by-element bitwise AND between int32 vectors
	*    and uses the result to construct a 16-bit
	*    vector mask, with a 0-bit for each element for which the result of
	*    the AND was 0, and a 1-bit where the result of the AND was not zero.
	*    Vector mask is returned.
	*
	*    The writemask does not perform the normal writemasking function
	*    for this instruction.  While it does enable/disable comparisons,
	*    it does not block updating of the result; instead, if a writemask
	*    bit is 0, the corresponding destination bit is set to 0.
	*/

	extern __mmask16 __ICL_INTRINCC _mm512_test_epi32_mask(__m512i, __m512i);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_test_epi32_mask(__mmask16, __m512i,
		__m512i);

	/*
	* Return 512 vector with undefined elements.  It is recommended to use the
	* result of this intrinsic as the old value for masked versions of intrinsics
	* when the old values will never be meaningfully used.
	*/
	extern __m512 __ICL_INTRINCC _mm512_undefined(void);
#define _mm512_undefined_pd() _mm512_castps_pd(_mm512_undefined())
#define _mm512_undefined_ps() _mm512_undefined()
#define _mm512_undefined_epi32() _mm512_castps_si512(_mm512_undefined())

	/*
	* Return 512 vector with all elements 0.
	*/
	extern __m512 __ICL_INTRINCC _mm512_setzero(void);

#define _mm512_setzero_pd() _mm512_castps_pd(_mm512_setzero())
#define _mm512_setzero_ps() _mm512_setzero()
#define _mm512_setzero_epi32() _mm512_castps_si512(_mm512_setzero())
#define _mm512_setzero_si512 _mm512_setzero_epi32

	/*
	* Return float64 vector with all 8 elements equal to given scalar.
	*/
	extern __m512d __ICL_INTRINCC _mm512_set1_pd(double);
#define _mm512_set_1to8_pd(x) _mm512_set1_pd((x))

	/*
	* Return int64 vector with all 8 elements equal to given scalar.
	*/
	extern __m512i __ICL_INTRINCC _mm512_set1_epi64(__int64);
#define _mm512_set_1to8_pq(x) _mm512_set1_epi64((x))
#define _mm512_set_1to8_epi64(x) _mm512_set1_epi64((x))

	/*
	* Return float32 vector with all 16 elements equal to given scalar.
	*/
	extern __m512  __ICL_INTRINCC _mm512_set1_ps(float);
#define _mm512_set_1to16_ps(x) _mm512_set1_ps((x))

	/*
	* Return int32 vector with all 16 elements equal to given scalar.
	*/
	extern __m512i __ICL_INTRINCC _mm512_set1_epi32(int);
#define _mm512_set_1to16_pi(x) _mm512_set1_epi32((x))
#define _mm512_set_1to16_epi32(x) _mm512_set1_epi32((x))

	/*
	* Return float64 vector dcbadcba.
	* (v4, v0 = a; v5, v1 = b; v6, v2 = c; v7, v3 = d).
	*/
	extern __m512d __ICL_INTRINCC _mm512_set4_pd(double /* d */, double /* c */,
		double /* b */, double /* a */);
#define _mm512_setr4_pd(a,b,c,d) \
    _mm512_set4_pd((d),(c),(b),(a))
#define _mm512_set_4to8_pd(a,b,c,d) \
    _mm512_set4_pd((d),(c),(b),(a))

	/*
	* Return int64 vector dcbadcba.
	* (v4, v0 = a; v5, v1 = b; v6, v2 = c; v7, v3 = d).
	*/
	extern __m512i __ICL_INTRINCC _mm512_set4_epi64(__int64 /* d */,
		__int64 /* c */,
		__int64 /* b */,
		__int64 /* a */);
#define _mm512_setr4_epi64(a,b,c,d) \
    _mm512_set4_epi64((d),(c),(b),(a))
#define _mm512_set_4to8_pq(a,b,c,d) \
    _mm512_set4_epi64((d),(c),(b),(a))
#define _mm512_set_4to8_epi64(a,b,c,d) \
    _mm512_set4_epi64((d),(c),(b),(a))

	/*
	* Return float32 vector dcbadcbadcbadcba.
	* (v12, v8, v4, v0 = a; v13, v9, v5, v1 = b; v14, v10, v6, v2 = c;
	*  v15, v11, v7, v3 = d).
	*/
	extern __m512  __ICL_INTRINCC _mm512_set4_ps(float /* d */, float /* c */,
		float /* b */, float /* a */);
#define _mm512_setr4_ps(a,b,c,d) \
    _mm512_set4_ps((d),(c),(b),(a))
#define _mm512_set_4to16_ps(a,b,c,d) \
    _mm512_set4_ps((d),(c),(b),(a))

	/*
	* Return int32 vector dcbadcbadcbadcba.
	* (v12, v8, v4, v0 = a; v13, v9, v5, v1 = b; v14, v10, v6, v2 = c;
	*  v15, v11, v7, v3 = d).
	*/
	extern __m512i __ICL_INTRINCC _mm512_set4_epi32(int /* d */, int /* c */,
		int /* b */, int /* a */);

#define _mm512_setr4_epi32(a,b,c,d) \
    _mm512_set4_epi32((d),(c),(b),(a))
#define _mm512_set_4to16_pi(a,b,c,d) \
    _mm512_set4_epi32((d),(c),(b),(a))
#define _mm512_set_4to16_epi32(a,b,c,d) \
    _mm512_set4_epi32((d),(c),(b),(a))

	/*
	* Return float32 vector e15 e14 e13 ... e1 e0 (v15=e15, v14=e14, ..., v0=e0).
	*/
	extern __m512 __ICL_INTRINCC _mm512_set_ps(float /* e15 */, float, float,
		float, float, float,
		float, float, float,
		float, float, float,
		float, float, float,
		float /* e0 */);
#define _mm512_setr_ps(e0,e1,e2,e3,e4,e5,e6,e7,e8, \
                       e9,e10,e11,e12,e13,e14,e15) \
    _mm512_set_ps((e15),(e14),(e13),(e12),(e11),(e10), \
                  (e9),(e8),(e7),(e6),(e5),(e4),(e3),(e2),(e1),(e0))

#define _mm512_set_16to16_ps(e0,e1,e2,e3,e4,e5,e6,e7,e8, \
                             e9,e10,e11,e12,e13,e14,e15) \
    _mm512_set_ps((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7), \
                  (e8),(e9),(e10),(e11),(e12),(e13),(e14),(e15))

	/*
	* Return int32 vector e15 e14 e13 ... e1 e0 (v15=e15, v14=e14, ..., v0=e0).
	*/
	extern __m512i __ICL_INTRINCC _mm512_set_epi32(int /* e15 */, int, int, int,
		int, int, int, int,
		int, int, int, int,
		int, int, int, int /* e0 */);

#define _mm512_setr_epi32(e0,e1,e2,e3,e4,e5,e6,e7,e8, \
                          e9,e10,e11,e12,e13,e14,e15) \
    _mm512_set_epi32((e15),(e14),(e13),(e12),(e11),(e10), \
                     (e9),(e8),(e7),(e6),(e5),(e4),(e3),(e2),(e1),(e0))

#define _mm512_set_16to16_pi(e0,e1,e2,e3,e4,e5,e6,e7,e8, \
                             e9,e10,e11,e12,e13,e14,e15) \
    _mm512_set_epi32((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7), \
                     (e8),(e9),(e10),(e11),(e12),(e13),(e14),(e15))

#define _mm512_set_16to16_epi32(e0,e1,e2,e3,e4,e5,e6,e7,e8, \
                                e9,e10,e11,e12,e13,e14,e15) \
    _mm512_set_epi32((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7), \
                     (e8),(e9),(e10),(e11),(e12),(e13),(e14),(e15))


	/*
	* Return float64 vector e7 e6 e5 ... e1 e0 (v7=e7, v6=e6, ..., v0=e0).
	*/
	extern __m512d __ICL_INTRINCC _mm512_set_pd(double /* e7 */, double, double,
		double, double, double,
		double, double /* e0 */);

#define _mm512_setr_pd(e0,e1,e2,e3,e4,e5,e6,e7) \
    _mm512_set_pd((e7),(e6),(e5),(e4),(e3),(e2),(e1),(e0))
#define _mm512_set_8to8_pd(e0,e1,e2,e3,e4,e5,e6,e7) \
    _mm512_set_pd((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7))

	/*
	* Return int64 vector e7 e6 e5 ... e1 e0 (v7=e7, v6=e6, ..., v0=e0).
	*/
	extern __m512i __ICL_INTRINCC _mm512_set_epi64(__int64 /* e7 */, __int64,
		__int64, __int64,
		__int64, __int64,
		__int64, __int64 /* e0 */);

#define _mm512_setr_epi64(e0,e1,e2,e3,e4,e5,e6,e7) \
    _mm512_set_epi64((e7),(e6),(e5),(e4),(e3),(e2),(e1),(e0))

#define _mm512_set_8to8_pq(e0,e1,e2,e3,e4,e5,e6,e7) \
    _mm512_set_epi64((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7))

#define _mm512_set_8to8_epi64(e0,e1,e2,e3,e4,e5,e6,e7) \
    _mm512_set_epi64((e0),(e1),(e2),(e3),(e4),(e5),(e6),(e7))


	/*
	* Math intrinsics.
	*/

	extern __m512d __ICL_INTRINCC _mm512_acos_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_acos_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_acos_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_acos_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_acosh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_acosh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_acosh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_acosh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_asin_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_asin_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_asin_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_asin_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_asinh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_asinh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_asinh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_asinh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_atan2_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_atan2_pd(__m512d, __mmask8, __m512d,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_atan2_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_atan2_ps(__m512, __mmask16, __m512,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_atan_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_atan_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_atan_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_atan_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_atanh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_atanh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_atanh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_atanh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_cbrt_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cbrt_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_cbrt_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cbrt_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_cdfnorm_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cdfnorm_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_cdfnorm_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cdfnorm_ps(__m512, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_cdfnorminv_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cdfnorminv_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_cdfnorminv_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cdfnorminv_ps(__m512, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_ceil_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_ceil_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_ceil_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_ceil_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_cos_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cos_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_cos_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cos_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_cosd_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cosd_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_cosd_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cosd_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_cosh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_cosh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_cosh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_cosh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_erf_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_erf_pd(__m512d, __mmask8, __m512d);

	extern __m512d __ICL_INTRINCC _mm512_erfc_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_erfc_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_erf_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_erf_ps(__m512, __mmask16, __m512);

	extern __m512  __ICL_INTRINCC _mm512_erfc_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_erfc_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_erfinv_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_erfinv_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_erfinv_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_erfinv_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_erfcinv_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_erfcinv_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_erfcinv_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_erfcinv_ps(__m512, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_exp10_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_exp10_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_exp10_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_exp10_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_exp2_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_exp2_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_exp2_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_exp2_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_exp_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_exp_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_exp_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_exp_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_expm1_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_expm1_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_expm1_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_expm1_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_floor_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_floor_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_floor_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_floor_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_hypot_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_hypot_pd(__m512d, __mmask8, __m512d,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_hypot_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_hypot_ps(__m512, __mmask16, __m512,
		__m512);

	extern __m512i __ICL_INTRINCC _mm512_div_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_div_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_div_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_div_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_div_epi64(__m512i, __m512i);

	extern __m512  __ICL_INTRINCC _mm512_div_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_div_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_div_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_div_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512d __ICL_INTRINCC _mm512_invsqrt_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_invsqrt_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_invsqrt_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_invsqrt_ps(__m512, __mmask16,
		__m512);

	extern __m512i __ICL_INTRINCC _mm512_rem_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rem_epi32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_rem_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_rem_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_rem_epi64(__m512i, __m512i);

	extern __m512d __ICL_INTRINCC _mm512_log10_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_log10_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_log10_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_log10_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_log1p_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_log1p_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_log1p_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_log1p_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_log2_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_log2_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_log2_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_log2_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_log_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_log_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_log_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_log_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_logb_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_logb_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_logb_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_logb_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_nearbyint_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_nearbyint_pd(__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_nearbyint_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_nearbyint_ps(__m512, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_pow_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_pow_pd(__m512d, __mmask8,
		__m512d, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_pow_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_pow_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m512d __ICL_INTRINCC _mm512_recip_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_recip_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_recip_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_recip_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_rint_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_rint_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_rint_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_rint_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_svml_round_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_svml_round_pd(__m512d, __mmask8,
		__m512d);

	extern __m512d __ICL_INTRINCC _mm512_sin_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sin_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_sin_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_sin_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_sincos_pd(__m512d*, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sincos_pd(__m512d*, __m512d,
		__m512d, __mmask8,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_sincos_ps(__m512*, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_sincos_ps(__m512*, __m512,
		__m512, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_sinh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sinh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_sinh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_sinh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_sind_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sind_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_sind_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_sind_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_sqrt_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_sqrt_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_sqrt_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_sqrt_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_tan_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_tan_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_tan_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_tan_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_tand_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_tand_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_tand_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_tand_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_tanh_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_tanh_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_tanh_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_tanh_ps(__m512, __mmask16, __m512);

	extern __m512d __ICL_INTRINCC _mm512_trunc_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_trunc_pd(__m512d, __mmask8, __m512d);

	extern __m512  __ICL_INTRINCC _mm512_trunc_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_trunc_ps(__m512, __mmask16, __m512);

	extern __m512i __ICL_INTRINCC _mm512_div_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_div_epu32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_div_epu8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_div_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_div_epu64(__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_rem_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rem_epu32(__m512i, __mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_rem_epu8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_rem_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_rem_epu64(__m512i, __m512i);

	/*
	* Reduction intrinsics - perform corresponding operation on all elements
	* of source vector and return scalar value.
	* For example, _mm512_reduce_add_ps returns float32 value
	* calculated as v1[0] + v1[1] + ... + v1[15].
	*/
	extern float   __ICL_INTRINCC _mm512_reduce_add_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_add_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_add_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_add_pd(__mmask8, __m512d);

	extern int     __ICL_INTRINCC _mm512_reduce_add_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_add_epi32(__mmask16, __m512i);

	extern float   __ICL_INTRINCC _mm512_reduce_mul_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_mul_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_mul_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_mul_pd(__mmask8, __m512d);

	extern int     __ICL_INTRINCC _mm512_reduce_mul_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_mul_epi32(__mmask16, __m512i);

	extern float   __ICL_INTRINCC _mm512_reduce_min_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_min_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_min_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_min_pd(__mmask8, __m512d);

	extern int     __ICL_INTRINCC _mm512_reduce_min_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_min_epi32(__mmask16, __m512i);

	extern unsigned int __ICL_INTRINCC _mm512_reduce_min_epu32(__m512i);
	extern unsigned int __ICL_INTRINCC _mm512_mask_reduce_min_epu32(__mmask16,
		__m512i);

	extern float   __ICL_INTRINCC _mm512_reduce_max_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_max_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_max_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_max_pd(__mmask8, __m512d);

	extern int     __ICL_INTRINCC _mm512_reduce_max_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_max_epi32(__mmask16, __m512i);

	extern unsigned int __ICL_INTRINCC _mm512_reduce_max_epu32(__m512i);
	extern unsigned int __ICL_INTRINCC _mm512_mask_reduce_max_epu32(__mmask16,
		__m512i);

	extern int     __ICL_INTRINCC _mm512_reduce_or_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_or_epi32(__mmask16, __m512i);

	extern int     __ICL_INTRINCC _mm512_reduce_and_epi32(__m512i);
	extern int     __ICL_INTRINCC _mm512_mask_reduce_and_epi32(__mmask16, __m512i);

	extern float   __ICL_INTRINCC _mm512_reduce_gmin_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_gmin_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_gmin_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_gmin_pd(__mmask8, __m512d);

	extern float   __ICL_INTRINCC _mm512_reduce_gmax_ps(__m512);
	extern float   __ICL_INTRINCC _mm512_mask_reduce_gmax_ps(__mmask16, __m512);

	extern double  __ICL_INTRINCC _mm512_reduce_gmax_pd(__m512d);
	extern double  __ICL_INTRINCC _mm512_mask_reduce_gmax_pd(__mmask8, __m512d);

	/*
	* Scalar intrinsics.
	*/

	/* Trailing zero bit count */
	extern int            __ICL_INTRINCC _mm_tzcnt_32(unsigned int);
	extern __int64        __ICL_INTRINCC _mm_tzcnt_64(unsigned __int64);

	/* Initialized trailing zero bit count */
	extern int            __ICL_INTRINCC _mm_tzcnti_32(int, unsigned int);
	extern __int64        __ICL_INTRINCC _mm_tzcnti_64(__int64, unsigned __int64);

	/* Bit population count */
	extern unsigned int      __ICL_INTRINCC _mm_countbits_32(unsigned int);
	extern unsigned __int64  __ICL_INTRINCC _mm_countbits_64(unsigned __int64);

	/* Stall thread.
	*
	*    Stall thread for specified clock without blocking other threads.
	*    Hints that the processor should not fetch/issue instructions for the
	*    current thread for the specified number of clock cycles.
	*    Any of the following events will cause the processor to start fetching
	*    instructions for the delayed thread again: the counter counting down
	*    to zero, an interrupt, an NMI or SMI, a debug exception, a machine check
	*    exception, the BINIT# signal, the INIT# signal, or the RESET# signal.
	*    Note that an interrupt will cause the processor to start fetching
	*    instructions for that thread only if the state was entered with
	*    interrupts enabled.
	*/
	extern void __ICL_INTRINCC _mm_delay_32(unsigned int);
	extern void __ICL_INTRINCC _mm_delay_64(unsigned __int64);


	/*
	* Set performance monitor filtering mask for current thread.
	*/
	extern void __ICL_INTRINCC _mm_spflt_32(unsigned int);
	extern void __ICL_INTRINCC _mm_spflt_64(unsigned __int64);

	/*
	* Evict cache line from specified cache level:
	* _MM_HINT_T0 -- first level
	* _MM_HINT_T1 -- second level
	*/

	extern void __ICL_INTRINCC _mm_clevict(const void*, int /* level */);

	/*
	* Mask arithmetic operations.
	*/
	extern __mmask16 __ICL_INTRINCC _mm512_kand(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kandn(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kandnr(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kmovlhb(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_knot(__mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kor(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kxnor(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kxor(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kswapb(__mmask16, __mmask16);
	extern int       __ICL_INTRINCC _mm512_kortestz(__mmask16, __mmask16);
	extern int       __ICL_INTRINCC _mm512_kortestc(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kmov(__mmask16);
	extern int       __ICL_INTRINCC _mm512_mask2int(__mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_int2mask(int);
	extern __int64   __ICL_INTRINCC _mm512_kconcathi_64(__mmask16, __mmask16);
	extern __int64   __ICL_INTRINCC _mm512_kconcatlo_64(__mmask16, __mmask16);
	extern __mmask16 __ICL_INTRINCC _mm512_kextract_64(__int64,
		const int /* select */);

#define _mm512_kmerge2l1h(k1, k2) _mm512_kswapb((k1), (k2))
#define _mm512_kmerge2l1l(k1, k2) _mm512_kmovlhb((k1), (k2))


	/*
	* Intel(R) Advanced Vector Extensions 512 (Intel(R) AVX-512).
	*/

	/*
	* Casts from a larger type to a smaller type.
	*/
	extern __m128d __ICL_INTRINCC _mm512_castpd512_pd128(__m512d);
	extern __m128  __ICL_INTRINCC _mm512_castps512_ps128(__m512);
	extern __m128i __ICL_INTRINCC _mm512_castsi512_si128(__m512i);
	extern __m256d __ICL_INTRINCC _mm512_castpd512_pd256(__m512d);
	extern __m256  __ICL_INTRINCC _mm512_castps512_ps256(__m512);
	extern __m256i __ICL_INTRINCC _mm512_castsi512_si256(__m512i);

	/*
	* Casts from a smaller type to a larger type.
	* Upper elements of the result are undefined.
	*/
	extern __m512d __ICL_INTRINCC _mm512_castpd128_pd512(__m128d);
	extern __m512  __ICL_INTRINCC _mm512_castps128_ps512(__m128);
	extern __m512i __ICL_INTRINCC _mm512_castsi128_si512(__m128i);
	extern __m512d __ICL_INTRINCC _mm512_castpd256_pd512(__m256d);
	extern __m512  __ICL_INTRINCC _mm512_castps256_ps512(__m256);
	extern __m512i __ICL_INTRINCC _mm512_castsi256_si512(__m256i);

	extern __m512d __ICL_INTRINCC _mm512_maskz_load_pd(__mmask8, void const*);
	extern __m512  __ICL_INTRINCC _mm512_maskz_load_ps(__mmask16, void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_load_epi32(__mmask16, void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_load_epi64(__mmask8, void const*);
	extern __m128d __ICL_INTRINCC _mm_mask_load_sd(__m128d, __mmask8,
		const double*);
	extern __m128d __ICL_INTRINCC _mm_maskz_load_sd(__mmask8, const double*);
	extern __m128  __ICL_INTRINCC _mm_mask_load_ss(__m128, __mmask8, const float*);
	extern __m128  __ICL_INTRINCC _mm_maskz_load_ss(__mmask8, const float*);

	/* Unaligned loads and stores. */

	extern __m512d __ICL_INTRINCC _mm512_loadu_pd(void const*);
	extern __m512  __ICL_INTRINCC _mm512_loadu_ps(void const*);
	extern __m512i __ICL_INTRINCC _mm512_loadu_si512(void const*);
	extern __m512d __ICL_INTRINCC _mm512_mask_loadu_pd(__m512d, __mmask8,
		void const*);
	extern __m512  __ICL_INTRINCC _mm512_mask_loadu_ps(__m512, __mmask16,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_mask_loadu_epi32(__m512i, __mmask16,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_mask_loadu_epi64(__m512i, __mmask8,
		void const*);
	extern __m512d __ICL_INTRINCC _mm512_maskz_loadu_pd(__mmask8, void const*);
	extern __m512  __ICL_INTRINCC _mm512_maskz_loadu_ps(__mmask16, void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_loadu_epi32(__mmask16, void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_loadu_epi64(__mmask8, void const*);

	extern void    __ICL_INTRINCC _mm512_storeu_pd(void*, __m512d);
	extern void    __ICL_INTRINCC _mm512_storeu_ps(void*, __m512);
	extern void    __ICL_INTRINCC _mm512_storeu_si512(void*, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_storeu_pd(void*, __mmask8, __m512d);
	extern void    __ICL_INTRINCC _mm512_mask_storeu_ps(void*, __mmask16, __m512);
	extern void    __ICL_INTRINCC _mm512_mask_storeu_epi32(void*, __mmask16,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_storeu_epi64(void*, __mmask8,
		__m512i);

	extern void    __ICL_INTRINCC _mm_mask_store_sd(double*, __mmask8, __m128d);
	extern void    __ICL_INTRINCC _mm_mask_store_ss(float*, __mmask8, __m128);

	extern void    __ICL_INTRINCC _mm512_stream_pd(void*, __m512d);
	extern void    __ICL_INTRINCC _mm512_stream_ps(void*, __m512);
	extern void    __ICL_INTRINCC _mm512_stream_si512(void*, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_stream_load_si512(void const*);

	extern __m512d  __ICL_INTRINCC _mm512_broadcastsd_pd(__m128d);
	extern __m512d  __ICL_INTRINCC _mm512_mask_broadcastsd_pd(__m512d,
		__mmask8, __m128d);
	extern __m512d  __ICL_INTRINCC _mm512_maskz_broadcastsd_pd(__mmask8, __m128d);

	extern __m512  __ICL_INTRINCC _mm512_broadcastss_ps(__m128);
	extern __m512  __ICL_INTRINCC _mm512_mask_broadcastss_ps(__m512,
		__mmask16, __m128);
	extern __m512  __ICL_INTRINCC _mm512_maskz_broadcastss_ps(__mmask16, __m128);

	extern __m512  __ICL_INTRINCC _mm512_broadcast_f32x4(__m128);
	extern __m512  __ICL_INTRINCC _mm512_mask_broadcast_f32x4(__m512,
		__mmask16,
		__m128);
	extern __m512  __ICL_INTRINCC _mm512_maskz_broadcast_f32x4(__mmask16,
		__m128);
	extern __m512d  __ICL_INTRINCC _mm512_broadcast_f64x4(__m256d);
	extern __m512d  __ICL_INTRINCC _mm512_mask_broadcast_f64x4(__m512d,
		__mmask8,
		__m256d);
	extern __m512d  __ICL_INTRINCC _mm512_maskz_broadcast_f64x4(__mmask8,
		__m256d);
	extern __m512i  __ICL_INTRINCC _mm512_broadcast_i32x4(__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_broadcast_i32x4(__m512i,
		__mmask16,
		__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_broadcast_i32x4(__mmask16,
		__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_broadcast_i64x4(__m256i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_broadcast_i64x4(__m512i,
		__mmask8,
		__m256i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_broadcast_i64x4(__mmask8,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_broadcastd_epi32(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_broadcastd_epi32(__m512i, __mmask16,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_broadcastd_epi32(__mmask16,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_broadcastq_epi64(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_broadcastq_epi64(__m512i, __mmask8,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_broadcastq_epi64(__mmask8, __m128i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_mov_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mov_epi64(__mmask8, __m512i);
	extern __m512d __ICL_INTRINCC _mm512_maskz_mov_pd(__mmask8, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_maskz_mov_ps(__mmask16, __m512);
	extern __m128d __ICL_INTRINCC _mm_mask_move_sd(__m128d, __mmask8, __m128d,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_move_sd(__mmask8, __m128d, __m128d);
	extern __m128  __ICL_INTRINCC _mm_mask_move_ss(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_move_ss(__mmask8, __m128, __m128);

	extern __m512d   __ICL_INTRINCC _mm512_mask_movedup_pd(__m512d, __mmask8,
		__m512d);
	extern __m512    __ICL_INTRINCC _mm512_mask_movehdup_ps(__m512, __mmask16,
		__m512);
	extern __m512    __ICL_INTRINCC _mm512_mask_moveldup_ps(__m512, __mmask16,
		__m512);
	extern __m512d   __ICL_INTRINCC _mm512_maskz_movedup_pd(__mmask8, __m512d);
	extern __m512    __ICL_INTRINCC _mm512_maskz_movehdup_ps(__mmask16, __m512);
	extern __m512    __ICL_INTRINCC _mm512_maskz_moveldup_ps(__mmask16, __m512);
	extern __m512d   __ICL_INTRINCC _mm512_movedup_pd(__m512d);
	extern __m512    __ICL_INTRINCC _mm512_movehdup_ps(__m512);
	extern __m512    __ICL_INTRINCC _mm512_moveldup_ps(__m512);

	extern __mmask8 __ICL_INTRINCC _mm_cmp_round_sd_mask(__m128d, __m128d,
		const int, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_round_sd_mask(__mmask8, __m128d,
		__m128d, const int,
		const int);
#define _mm_cmp_sd_mask(v1, v2, c) \
        _mm_cmp_round_sd_mask((v1), (v2), (c), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_cmp_sd_mask(k1, v1, v2, c) \
        _mm_mask_cmp_round_sd_mask((k1), (v1), (v2), (c), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern int __ICL_INTRINCC _mm_comi_round_sd(__m128d, __m128d, const int,
		const int);

	extern __mmask8 __ICL_INTRINCC _mm_cmp_round_ss_mask(__m128, __m128,
		const int, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_round_ss_mask(__mmask8, __m128,
		__m128, const int,
		const int);
#define _mm_cmp_ss_mask(v1, v2, c) \
        _mm_cmp_round_ss_mask((v1), (v2), (c), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_cmp_ss_mask(k1, v1, v2, c) \
        _mm_mask_cmp_round_ss_mask((k1), (v1), (v2), (c), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __mmask8 __ICL_INTRINCC _mm512_cmp_epi64_mask(__m512i, __m512i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_cmp_epi64_mask(__mmask8, __m512i,
		__m512i,
		const _MM_CMPINT_ENUM);

	extern int __ICL_INTRINCC _mm_comi_round_ss(__m128, __m128, const int,
		const int);

#define _mm512_cmpeq_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epi64_mask(v1, v2) \
        _mm512_cmp_epi64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epi64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm512_cmp_epu64_mask(__m512i, __m512i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_cmp_epu64_mask(__mmask8, __m512i,
		__m512i,
		const _MM_CMPINT_ENUM);

#define _mm512_cmpeq_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epu64_mask(v1, v2) \
        _mm512_cmp_epu64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epu64_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm512_test_epi64_mask(__m512i, __m512i);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_test_epi64_mask(__mmask8, __m512i,
		__m512i);

	extern __mmask16 __ICL_INTRINCC _mm512_testn_epi32_mask(__m512i, __m512i);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_testn_epi32_mask(__mmask16,
		__m512i, __m512i);

	extern __mmask8 __ICL_INTRINCC _mm512_testn_epi64_mask(__m512i, __m512i);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_testn_epi64_mask(__mmask8,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_and_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_and_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_or_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_or_epi64(__mmask8, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_andnot_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_andnot_epi64(__mmask8, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_alignr_epi32(__mmask16, __m512i,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_alignr_epi64(__m512i, __m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_alignr_epi64(__m512i, __mmask8,
		__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_alignr_epi64(__mmask8, __m512i,
		__m512i, const int);

	extern __m512i __ICL_INTRINCC _mm512_mask_expand_epi32(__m512i, __mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_expand_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_expandloadu_epi32(__m512i, __mmask16,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_expandloadu_epi32(__mmask16,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_mask_expand_epi64(__m512i, __mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_expand_epi64(__mmask8, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_expandloadu_epi64(__m512i, __mmask8,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_expandloadu_epi64(__mmask8,
		void const*);
	extern __m512d __ICL_INTRINCC _mm512_mask_expand_pd(__m512d, __mmask8,
		__m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_expand_pd(__mmask8, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_expandloadu_pd(__m512d, __mmask8,
		void const*);
	extern __m512d __ICL_INTRINCC _mm512_maskz_expandloadu_pd(__mmask8,
		void const*);
	extern __m512  __ICL_INTRINCC _mm512_mask_expand_ps(__m512, __mmask16,
		__m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_expand_ps(__mmask16, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_expandloadu_ps(__m512, __mmask16,
		void const*);
	extern __m512  __ICL_INTRINCC _mm512_maskz_expandloadu_ps(__mmask16,
		void const*);

	extern __m128d __ICL_INTRINCC _mm_getexp_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_getexp_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_getexp_round_sd(__mmask8, __m128d,
		__m128d, int);
#define _mm_getexp_sd(v1, v2) \
    _mm_getexp_round_sd((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_getexp_sd(v1, k, v2, v3) \
    _mm_mask_getexp_round_sd((v1), (k), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_getexp_sd(k, v1, v2) \
    _mm_maskz_getexp_round_sd((k), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_getexp_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_getexp_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_getexp_round_ss(__mmask8, __m128,
		__m128, int);
#define _mm_getexp_ss(v1, v2) \
    _mm_getexp_round_ss((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_getexp_ss(v1, k, v2, v3) \
    _mm_mask_getexp_round_ss((v1), (k), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_getexp_ss(k, v1, v2) \
    _mm_maskz_getexp_round_ss((k), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_getexp_round_pd(__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_getexp_round_pd(__m512d, __mmask8,
		__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_getexp_round_pd(__mmask8, __m512d,
		int);
#define _mm512_maskz_getexp_pd(k, v) \
    _mm512_maskz_getexp_round_pd((k), (v), _MM_FROUND_CUR_DIRECTION)

	extern __m512 __ICL_INTRINCC _mm512_getexp_round_ps(__m512, int);
	extern __m512 __ICL_INTRINCC _mm512_mask_getexp_round_ps(__m512, __mmask16,
		__m512, int);
	extern __m512 __ICL_INTRINCC _mm512_maskz_getexp_round_ps(__mmask16, __m512,
		int);
#define _mm512_maskz_getexp_ps(k, v)                              \
    _mm512_maskz_getexp_round_ps((k), (v), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_unpackhi_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpackhi_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpackhi_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_unpackhi_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpackhi_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpackhi_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512d __ICL_INTRINCC _mm512_unpackhi_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_unpackhi_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_unpackhi_pd(__mmask8, __m512d,
		__m512d);
	extern __m512  __ICL_INTRINCC _mm512_unpackhi_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_unpackhi_ps(__m512, __mmask16,
		__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_unpackhi_ps(__mmask16, __m512,
		__m512);

	extern __m512i __ICL_INTRINCC _mm512_unpacklo_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpacklo_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpacklo_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_unpacklo_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpacklo_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpacklo_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512d __ICL_INTRINCC _mm512_unpacklo_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_unpacklo_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_unpacklo_pd(__mmask8, __m512d,
		__m512d);
	extern __m512  __ICL_INTRINCC _mm512_unpacklo_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_unpacklo_ps(__m512, __mmask16,
		__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_unpacklo_ps(__mmask16, __m512,
		__m512);

	extern __m512i  __ICL_INTRINCC _mm512_maskz_shuffle_epi32(__mmask16, __m512i,
		_MM_PERM_ENUM);

	extern __m512  __ICL_INTRINCC _mm512_shuffle_f32x4(__m512, __m512, const int);
	extern __m512  __ICL_INTRINCC _mm512_mask_shuffle_f32x4(__m512, __mmask16,
		__m512, __m512,
		const int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_shuffle_f32x4(__mmask16, __m512,
		__m512, const int);
	extern __m512d __ICL_INTRINCC _mm512_shuffle_f64x2(__m512d, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_shuffle_f64x2(__m512d, __mmask8,
		__m512d, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_shuffle_f64x2(__mmask8, __m512d,
		__m512d, const int);
	extern __m512i __ICL_INTRINCC _mm512_shuffle_i32x4(__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_shuffle_i32x4(__m512i, __mmask16,
		__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_shuffle_i32x4(__mmask16, __m512i,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_shuffle_i64x2(__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_shuffle_i64x2(__m512i, __mmask8,
		__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_shuffle_i64x2(__mmask8, __m512i,
		__m512i, const int);
	extern __m512d __ICL_INTRINCC _mm512_shuffle_pd(__m512d, __m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_shuffle_pd(__m512d, __mmask8,
		__m512d, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_shuffle_pd(__mmask8, __m512d,
		__m512d, const int);
	extern __m512  __ICL_INTRINCC _mm512_shuffle_ps(__m512, __m512, const int);
	extern __m512  __ICL_INTRINCC _mm512_mask_shuffle_ps(__m512, __mmask16, __m512,
		__m512, const int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_shuffle_ps(__mmask16, __m512,
		__m512,
		const int);

	extern __m512i __ICL_INTRINCC _mm512_permutex2var_epi32(__m512i,
		__m512i /* index */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutex2var_epi32(__m512i,
		__mmask16,
		__m512i /* idx */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask2_permutex2var_epi32(__m512i,
		__m512i /* idx */,
		__mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutex2var_epi32(__mmask16,
		__m512i,
		__m512i /* idx */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_permutex2var_epi64(__m512i,
		__m512i /* index */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutex2var_epi64(__m512i, __mmask8,
		__m512i /* idx */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask2_permutex2var_epi64(__m512i,
		__m512i /* idx */,
		__mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutex2var_epi64(__mmask8,
		__m512i,
		__m512i /* idx */,
		__m512i);
	extern __m512  __ICL_INTRINCC _mm512_permutex2var_ps(__m512, __m512i /* idx */,
		__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_permutex2var_ps(__m512, __mmask16,
		__m512i /* index */,
		__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask2_permutex2var_ps(__m512,
		__m512i /* index */,
		__mmask16, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_permutex2var_ps(__mmask16, __m512,
		__m512i /* index */,
		__m512);
	extern __m512d __ICL_INTRINCC _mm512_permutex2var_pd(__m512d,
		__m512i /* idx */,
		__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_permutex2var_pd(__m512d, __mmask8,
		__m512i /* index */,
		__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask2_permutex2var_pd(__m512d,
		__m512i /* index */,
		__mmask8, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_permutex2var_pd(__mmask8, __m512d,
		__m512i /* index */,
		__m512d);

	extern __m512d __ICL_INTRINCC _mm512_permute_pd(__m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_permute_pd(__m512d, __mmask8,
		__m512d, const int);
	extern __m512d  __ICL_INTRINCC _mm512_maskz_permute_pd(__mmask8,
		__m512d, const int);

	extern __m512  __ICL_INTRINCC _mm512_permute_ps(__m512, const int);
	extern __m512  __ICL_INTRINCC _mm512_mask_permute_ps(__m512, __mmask16,
		__m512, const int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_permute_ps(__mmask16,
		__m512, const int);

	extern __m512d __ICL_INTRINCC _mm512_permutevar_pd(__m512d, __m512i);
	extern __m512d __ICL_INTRINCC _mm512_mask_permutevar_pd(__m512d, __mmask8,
		__m512d, __m512i);
	extern __m512d  __ICL_INTRINCC _mm512_maskz_permutevar_pd(__mmask8,
		__m512d, __m512i);

	extern __m512d __ICL_INTRINCC _mm512_permutex_pd(__m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_permutex_pd(__m512d, __mmask8,
		__m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_permutex_pd(__mmask8, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_permutexvar_pd(__m512i, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_permutexvar_pd(__m512d, __mmask8,
		__m512i, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_permutexvar_pd(__mmask8, __m512i,
		__m512d);

	extern __m512  __ICL_INTRINCC _mm512_permutevar_ps(__m512, __m512i);
	extern __m512  __ICL_INTRINCC _mm512_mask_permutevar_ps(__m512, __mmask16,
		__m512, __m512i);
	extern __m512  __ICL_INTRINCC _mm512_maskz_permutevar_ps(__mmask16,
		__m512, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_permutexvar_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutexvar_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutexvar_epi32(__mmask16,
		__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_permutex_epi64(__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutex_epi64(__m512i, __mmask8,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutex_epi64(__mmask8,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_permutexvar_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutexvar_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutexvar_epi64(__mmask8,
		__m512i, __m512i);
	extern __m512 __ICL_INTRINCC _mm512_permutexvar_ps(__m512i, __m512);
	extern __m512 __ICL_INTRINCC _mm512_mask_permutexvar_ps(__m512, __mmask16,
		__m512i, __m512);
	extern __m512 __ICL_INTRINCC _mm512_maskz_permutexvar_ps(__mmask16,
		__m512i, __m512);

	extern __m512i __ICL_INTRINCC _mm512_abs_epi32(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_abs_epi32(__m512i, __mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_abs_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_abs_epi64(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_abs_epi64(__m512i, __mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_abs_epi64(__mmask8, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_add_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_add_epi64(__mmask8, __m512i,
		__m512i);
	extern __m128d __ICL_INTRINCC _mm_add_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_add_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_add_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_add_sd(v1, k, v2, v3) \
         _mm_mask_add_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_add_sd(k, v2, v3) \
         _mm_maskz_add_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_add_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_add_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_add_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_add_ss(v1, k, v2, v3) \
         _mm_mask_add_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_add_ss(k, v2, v3) \
         _mm_maskz_add_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_div_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_div_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_div_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_div_sd(v1, k, v2, v3) \
         _mm_mask_div_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_div_sd(k, v2, v3) \
         _mm_maskz_div_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_div_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_div_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_div_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_div_ss(v1, k, v2, v3) \
         _mm_mask_div_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_div_ss(k, v2, v3) \
         _mm_maskz_div_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)


	extern __m128d __ICL_INTRINCC _mm_max_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_max_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_max_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_max_sd(v1, k, v2, v3) \
         _mm_mask_max_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_max_sd(k, v2, v3) \
         _mm_maskz_max_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_max_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_max_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_max_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_max_ss(v1, k, v2, v3) \
         _mm_mask_max_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_max_ss(k, v2, v3) \
         _mm_maskz_max_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_min_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_min_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_min_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_min_sd(v1, k, v2, v3) \
         _mm_mask_min_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_min_sd(k, v2, v3) \
         _mm_maskz_min_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_min_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_min_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_min_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_min_ss(v1, k, v2, v3) \
         _mm_mask_min_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_min_ss(k, v2, v3) \
         _mm_maskz_min_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_maskz_mullo_epi32(__mmask16, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_mul_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mul_epi32(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mul_epi32(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mul_epu32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mul_epu32(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mul_epu32(__mmask8, __m512i,
		__m512i);

	extern __m128d __ICL_INTRINCC _mm_mul_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_mul_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_mul_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_mul_sd(v1, k, v2, v3) \
         _mm_mask_mul_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_mul_sd(k, v2, v3) \
         _mm_maskz_mul_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_mul_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_mul_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_mul_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_mul_ss(v1, k, v2, v3) \
         _mm_mask_mul_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_mul_ss(k, v2, v3) \
         _mm_maskz_mul_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_rcp14_sd(__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_rcp14_sd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_rcp14_sd(__mmask8,
		__m128d, __m128d);

	extern __m128 __ICL_INTRINCC _mm_rcp14_ss(__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_mask_rcp14_ss(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_rcp14_ss(__mmask8,
		__m128, __m128);

	extern __m512i __ICL_INTRINCC _mm512_rol_epi32(__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_rol_epi32(__m512i, __mmask16,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rol_epi32(__mmask16, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_rol_epi64(__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_rol_epi64(__m512i, __mmask8,
		__m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rol_epi64(__mmask8, __m512i,
		const int);

	extern __m512i __ICL_INTRINCC _mm512_rolv_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rolv_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rolv_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_rolv_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rolv_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rolv_epi64(__mmask8, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_ror_epi32(__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_ror_epi32(__m512i, __mmask16,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_ror_epi32(__mmask16, __m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_ror_epi64(__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_ror_epi64(__m512i, __mmask8,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_ror_epi64(__mmask8, __m512i, int);

	extern __m512i __ICL_INTRINCC _mm512_rorv_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rorv_epi32(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rorv_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_rorv_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_rorv_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_rorv_epi64(__mmask8, __m512i,
		__m512i);

	extern __m128d __ICL_INTRINCC _mm_rsqrt14_sd(__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_rsqrt14_sd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_rsqrt14_sd(__mmask8,
		__m128d, __m128d);

	extern __m128 __ICL_INTRINCC _mm_rsqrt14_ss(__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_mask_rsqrt14_ss(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_rsqrt14_ss(__mmask8,
		__m128, __m128);

	extern __m512i __ICL_INTRINCC _mm512_sll_epi32(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sll_epi32(__m512i, __mmask16,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sll_epi32(__mmask16, __m512i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_sra_epi32(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sra_epi32(__m512i, __mmask16,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sra_epi32(__mmask16, __m512i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_srl_epi32(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srl_epi32(__m512i, __mmask16,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srl_epi32(__mmask16, __m512i,
		__m128i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_slli_epi32(__mmask16, __m512i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srai_epi32(__mmask16, __m512i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srli_epi32(__mmask16, __m512i,
		unsigned int);

	extern __m512i __ICL_INTRINCC _mm512_maskz_sllv_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srav_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srlv_epi32(__mmask16, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_sll_epi64(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sll_epi64(__m512i, __mmask8,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sll_epi64(__mmask8, __m512i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_sra_epi64(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sra_epi64(__m512i, __mmask8,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sra_epi64(__mmask8, __m512i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_srl_epi64(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srl_epi64(__m512i, __mmask8,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srl_epi64(__mmask8, __m512i,
		__m128i);

	extern __m512i __ICL_INTRINCC _mm512_slli_epi64(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_slli_epi64(__m512i, __mmask8,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_slli_epi64(__mmask8, __m512i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_srai_epi64(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srai_epi64(__m512i, __mmask8,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srai_epi64(__mmask8, __m512i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_srli_epi64(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srli_epi64(__m512i, __mmask8,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srli_epi64(__mmask8, __m512i,
		unsigned int);

	extern __m512i __ICL_INTRINCC _mm512_sllv_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sllv_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sllv_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_srav_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srav_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srav_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_srlv_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srlv_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srlv_epi64(__m512i, __mmask8,
		__m512i, __m512i);

	extern __m128d __ICL_INTRINCC _mm_sub_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_sub_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_sub_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_sub_sd(v1, k, v2, v3) \
         _mm_mask_sub_round_sd((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_sub_sd(k, v2, v3) \
         _mm_maskz_sub_round_sd((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_sub_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_sub_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_sub_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_sub_ss(v1, k, v2, v3) \
         _mm_mask_sub_round_ss((v1), (k), (v2), (v3), \
                               _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_sub_ss(k, v2, v3) \
         _mm_maskz_sub_round_ss((k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvtepi8_epi32(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi8_epi32(__m512i, __mmask16,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi8_epi32(__mmask16, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepi8_epi64(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi8_epi64(__m512i, __mmask8,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi8_epi64(__mmask8, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepi16_epi32(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi16_epi32(__m512i, __mmask16,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi16_epi32(__mmask16, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepi16_epi64(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi16_epi64(__m512i, __mmask8,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi16_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm512_cvtepi32_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtepi32_epi8(__m128i, __mmask16,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtepi32_epi8(__mmask16, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi32_storeu_epi8(void*,
		__mmask16,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtsepi32_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtsepi32_epi8(__m128i, __mmask16,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtsepi32_epi8(__mmask16, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi32_storeu_epi8(void*,
		__mmask16,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtusepi32_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtusepi32_epi8(__m128i, __mmask16,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtusepi32_epi8(__mmask16, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi32_storeu_epi8(void*,
		__mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtepi32_epi16(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtepi32_epi16(__m256i, __mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtepi32_epi16(__mmask16, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi32_storeu_epi16(void*,
		__mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtsepi32_epi16(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtsepi32_epi16(__m256i, __mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtsepi32_epi16(__mmask16, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi32_storeu_epi16(void*,
		__mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtusepi32_epi16(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtusepi32_epi16(__m256i, __mmask16,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtusepi32_epi16(__mmask16,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi32_storeu_epi16(void*,
		__mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepi32_epi64(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi32_epi64(__m512i, __mmask8,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi32_epi64(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm512_cvtepi64_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtepi64_epi8(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtepi64_epi8(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi64_storeu_epi8(void*,
		__mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtsepi64_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtsepi64_epi8(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtsepi64_epi8(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi64_storeu_epi8(void*,
		__mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtusepi64_epi8(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtusepi64_epi8(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtusepi64_epi8(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi64_storeu_epi8(void*,
		__mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtepi64_epi16(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtepi64_epi16(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtepi64_epi16(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi64_storeu_epi16(void*,
		__mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtsepi64_epi16(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtsepi64_epi16(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtsepi64_epi16(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi64_storeu_epi16(void*,
		__mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_cvtusepi64_epi16(__m512i);
	extern __m128i __ICL_INTRINCC _mm512_mask_cvtusepi64_epi16(__m128i, __mmask8,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm512_maskz_cvtusepi64_epi16(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi64_storeu_epi16(void*,
		__mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtepi64_epi32(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtepi64_epi32(__m256i, __mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtepi64_epi32(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi64_storeu_epi32(void*,
		__mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtsepi64_epi32(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtsepi64_epi32(__m256i, __mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtsepi64_epi32(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi64_storeu_epi32(void*,
		__mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtusepi64_epi32(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtusepi64_epi32(__m256i, __mmask8,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtusepi64_epi32(__mmask8, __m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi64_storeu_epi32(void*,
		__mmask8,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_cvtepu8_epi32(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu8_epi32(__m512i, __mmask16,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu8_epi32(__mmask16, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepu8_epi64(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu8_epi64(__m512i, __mmask8,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu8_epi64(__mmask8, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepu16_epi32(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu16_epi32(__m512i, __mmask16,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu16_epi32(__mmask16, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepu16_epi64(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu16_epi64(__m512i, __mmask8,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu16_epi64(__mmask8, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepu32_epi64(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu32_epi64(__m512i, __mmask8,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu32_epi64(__mmask8, __m256i);

	extern __m512d __ICL_INTRINCC _mm512_cvtepi32_pd(__m256i);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvtepi32_pd(__m512d, __mmask8,
		__m256i);
	extern __m512d __ICL_INTRINCC _mm512_maskz_cvtepi32_pd(__mmask8, __m256i);

	extern __m512  __ICL_INTRINCC _mm512_cvt_roundepi32_ps(__m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_cvt_roundepi32_ps(__m512, __mmask16,
		__m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_cvt_roundepi32_ps(__mmask16,
		__m512i, int);
#define _mm512_cvtepi32_ps(v) \
        _mm512_cvt_roundepi32_ps((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepi32_ps(v1, k1, v2) \
        _mm512_mask_cvt_roundepi32_ps((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepi32_ps(k1, v2) \
        _mm512_maskz_cvt_roundepi32_ps((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_cvt_roundepu32_ps(__m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_cvt_roundepu32_ps(__m512, __mmask16,
		__m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_cvt_roundepu32_ps(__mmask16,
		__m512i, int);
#define _mm512_cvtepu32_ps(v) \
        _mm512_cvt_roundepu32_ps((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepu32_ps(v1, k1, v2) \
        _mm512_mask_cvt_roundepu32_ps((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepu32_ps(k1, v2) \
        _mm512_maskz_cvt_roundepu32_ps((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_cvtepu32_pd(__m256i);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvtepu32_pd(__m512d, __mmask8,
		__m256i);
	extern __m512d __ICL_INTRINCC _mm512_maskz_cvtepu32_pd(__mmask8, __m256i);

	extern __m512d __ICL_INTRINCC _mm512_cvt_roundps_pd(__m256, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvt_roundps_pd(__m512d, __mmask8,
		__m256, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_cvt_roundps_pd(__mmask8, __m256,
		int);
#define _mm512_cvtps_pd(v) \
        _mm512_cvt_roundps_pd((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtps_pd(v1, k1, v2) \
        _mm512_mask_cvt_roundps_pd((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtps_pd(k1, v2) \
        _mm512_maskz_cvt_roundps_pd((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvt_roundps_epi32(__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundps_epi32(__m512i, __mmask16,
		__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundps_epi32(__mmask16, __m512,
		int);
#define _mm512_cvtps_epi32(v) \
        _mm512_cvt_roundps_epi32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtps_epi32(v1, k1, v2) \
        _mm512_mask_cvt_roundps_epi32((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtps_epi32(k1, v2) \
        _mm512_maskz_cvt_roundps_epi32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundps_epi32(__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundps_epi32(__m512i,
		__mmask16,
		__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundps_epi32(__mmask16,
		__m512, int);
#define _mm512_cvttps_epi32(v) \
        _mm512_cvtt_roundps_epi32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttps_epi32(v1, k1, v2) \
        _mm512_mask_cvtt_roundps_epi32((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttps_epi32(k1, v2) \
        _mm512_maskz_cvtt_roundps_epi32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvt_roundps_epu32(__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundps_epu32(__m512i, __mmask16,
		__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundps_epu32(__mmask16,
		__m512, int);
#define _mm512_cvtps_epu32(v) \
        _mm512_cvt_roundps_epu32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtps_epu32(v1, k1, v2) \
        _mm512_mask_cvt_roundps_epu32((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtps_epu32(k1, v2) \
        _mm512_maskz_cvt_roundps_epu32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundps_epu32(__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundps_epu32(__m512i,
		__mmask16,
		__m512, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundps_epu32(__mmask16,
		__m512, int);
#define _mm512_cvttps_epu32(v) \
        _mm512_cvtt_roundps_epu32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttps_epu32(v1, k1, v2) \
        _mm512_mask_cvtt_roundps_epu32((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttps_epu32(k1, v2) \
        _mm512_maskz_cvtt_roundps_epu32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m256 __ICL_INTRINCC _mm512_cvt_roundpd_ps(__m512d, int);
	extern __m256 __ICL_INTRINCC _mm512_mask_cvt_roundpd_ps(__m256, __mmask8,
		__m512d, int);
	extern __m256 __ICL_INTRINCC _mm512_maskz_cvt_roundpd_ps(__mmask8, __m512d,
		int);
#define _mm512_cvtpd_ps(v2) \
    _mm512_cvt_roundpd_ps((v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_ps(v1_old, k1, v2) \
    _mm512_mask_cvt_roundpd_ps((v1_old), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtpd_ps(k1, v2) \
    _mm512_maskz_cvt_roundpd_ps((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m256i __ICL_INTRINCC _mm512_cvt_roundpd_epi32(__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvt_roundpd_epi32(__m256i, __mmask8,
		__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvt_roundpd_epi32(__mmask8, __m512d,
		int);
#define _mm512_cvtpd_epi32(v) \
        _mm512_cvt_roundpd_epi32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_epi32(v1, k1, v2) \
        _mm512_mask_cvt_roundpd_epi32((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtpd_epi32(k1, v2) \
        _mm512_maskz_cvt_roundpd_epi32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m256i __ICL_INTRINCC _mm512_cvtt_roundpd_epi32(__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtt_roundpd_epi32(__m256i, __mmask8,
		__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtt_roundpd_epi32(__mmask8,
		__m512d, int);
#define _mm512_cvttpd_epi32(v) \
        _mm512_cvtt_roundpd_epi32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttpd_epi32(v1, k1, v2) \
        _mm512_mask_cvtt_roundpd_epi32((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttpd_epi32(k1, v2) \
        _mm512_maskz_cvtt_roundpd_epi32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m256i __ICL_INTRINCC _mm512_cvt_roundpd_epu32(__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvt_roundpd_epu32(__m256i, __mmask8,
		__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvt_roundpd_epu32(__mmask8, __m512d,
		int);
#define _mm512_cvtpd_epu32(v) \
        _mm512_cvt_roundpd_epu32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_epu32(v1, k1, v2) \
        _mm512_mask_cvt_roundpd_epu32((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtpd_epu32(k1, v2) \
        _mm512_maskz_cvt_roundpd_epu32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m256i __ICL_INTRINCC _mm512_cvtt_roundpd_epu32(__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtt_roundpd_epu32(__m256i, __mmask8,
		__m512d, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtt_roundpd_epu32(__mmask8,
		__m512d, int);
#define _mm512_cvttpd_epu32(v) \
        _mm512_cvtt_roundpd_epu32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttpd_epu32(v1, k1, v2) \
        _mm512_mask_cvtt_roundpd_epu32((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttpd_epu32(k1, v2) \
        _mm512_maskz_cvtt_roundpd_epu32((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512 __ICL_INTRINCC        _mm512_cvt_roundph_ps(__m256i, int);
	extern __m512 __ICL_INTRINCC   _mm512_mask_cvt_roundph_ps(__m512, __mmask16,
		__m256i, int);
	extern __m512 __ICL_INTRINCC  _mm512_maskz_cvt_roundph_ps(__mmask16, __m256i,
		int);
#define _mm512_cvtph_ps(v1) \
        _mm512_cvt_roundph_ps((v1), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtph_ps(v1, k, v2) \
        _mm512_mask_cvt_roundph_ps((v1), (k), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtph_ps(k, v1) \
        _mm512_maskz_cvt_roundph_ps((k), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m256i  __ICL_INTRINCC       _mm512_cvt_roundps_ph(__m512, int);
	extern __m256i  __ICL_INTRINCC  _mm512_mask_cvt_roundps_ph(__m256i, __mmask16,
		__m512, int);
	extern __m256i  __ICL_INTRINCC _mm512_maskz_cvt_roundps_ph(__mmask16, __m512,
		int);
#define _mm512_cvtps_ph(v1, a) \
        _mm512_cvt_roundps_ph((v1), (a))
#define _mm512_mask_cvtps_ph(v1, k, v2, a) \
        _mm512_mask_cvt_roundps_ph((v1), (k), (v2), (a))
#define _mm512_maskz_cvtps_ph(k, v2, a) \
        _mm512_maskz_cvt_roundps_ph((k), (v2), (a))

	extern int      __ICL_INTRINCC _mm_cvt_roundsd_i32(__m128d, int);
	extern __int64  __ICL_INTRINCC _mm_cvt_roundsd_i64(__m128d, int);
#define _mm_cvtsd_i32 _mm_cvtsd_si32
#define _mm_cvtsd_i64 _mm_cvtsd_si64
#define _mm_cvt_roundsd_si32 _mm_cvt_roundsd_i32
#define _mm_cvt_roundsd_si64 _mm_cvt_roundsd_i64

	extern unsigned int      __ICL_INTRINCC _mm_cvt_roundsd_u32(__m128d, int);
	extern unsigned __int64  __ICL_INTRINCC _mm_cvt_roundsd_u64(__m128d, int);
#define _mm_cvtsd_u32(v) _mm_cvt_roundsd_u32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm_cvtsd_u64(v) _mm_cvt_roundsd_u64((v), _MM_FROUND_CUR_DIRECTION)

	extern int      __ICL_INTRINCC _mm_cvtt_roundsd_i32(__m128d, int);
	extern __int64  __ICL_INTRINCC _mm_cvtt_roundsd_i64(__m128d, int);
#define _mm_cvttsd_i64(v) _mm_cvtt_roundsd_i64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm_cvttsd_i32(v) _mm_cvtt_roundsd_i32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm_cvtt_roundsd_si32 _mm_cvtt_roundsd_i32
#define _mm_cvtt_roundsd_si64 _mm_cvtt_roundsd_i64

	extern unsigned __int64 __ICL_INTRINCC _mm_cvtt_roundsd_u64(__m128d, int);
	extern unsigned     int __ICL_INTRINCC _mm_cvtt_roundsd_u32(__m128d, int);
#define _mm_cvttsd_u64(v) _mm_cvtt_roundsd_u64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm_cvttsd_u32(v) _mm_cvtt_roundsd_u32((v), _MM_FROUND_CUR_DIRECTION)

	extern __m128d  __ICL_INTRINCC _mm_cvt_roundi64_sd(__m128d, __int64, int);
#define _mm_cvti32_sd _mm_cvtsi32_sd
#define _mm_cvti64_sd _mm_cvtsi64_sd
#define _mm_cvt_roundsi64_sd _mm_cvt_roundi64_sd

	extern __m128d  __ICL_INTRINCC _mm_cvtu32_sd(__m128d, unsigned int);
	extern __m128d  __ICL_INTRINCC _mm_cvt_roundu64_sd(__m128d, unsigned __int64,
		int);
#define _mm_cvtu64_sd(v, a) _mm_cvt_roundu64_sd((v), (a), \
                                                _MM_FROUND_CUR_DIRECTION)

	extern int      __ICL_INTRINCC _mm_cvt_roundss_i32(__m128, int);
	extern __int64  __ICL_INTRINCC _mm_cvt_roundss_i64(__m128, int);
#define _mm_cvtss_i32 _mm_cvtss_si32
#define _mm_cvtss_i64 _mm_cvtss_si64
#define _mm_cvt_roundss_si32 _mm_cvt_roundss_i32
#define _mm_cvt_roundss_si64 _mm_cvt_roundss_i64

	extern unsigned int      __ICL_INTRINCC _mm_cvt_roundss_u32(__m128, int);
	extern unsigned __int64  __ICL_INTRINCC _mm_cvt_roundss_u64(__m128, int);
#define _mm_cvtss_u32(v) _mm_cvt_roundss_u32((v), _MM_FROUND_CUR_DIRECTION)
#define _mm_cvtss_u64(v) _mm_cvt_roundss_u64((v), _MM_FROUND_CUR_DIRECTION)

	extern __int64 __ICL_INTRINCC _mm_cvtt_roundss_i64(__m128, int);
	extern     int __ICL_INTRINCC _mm_cvtt_roundss_i32(__m128, int);
#define _mm_cvttss_i32(v) _mm_cvtt_roundss_i32(v, _MM_FROUND_CUR_DIRECTION)
#define _mm_cvttss_i64(v) _mm_cvtt_roundss_i64(v, _MM_FROUND_CUR_DIRECTION)
#define _mm_cvtt_roundss_si32 _mm_cvtt_roundss_i32
#define _mm_cvtt_roundss_si64 _mm_cvtt_roundss_i64

	extern unsigned __int64 __ICL_INTRINCC _mm_cvtt_roundss_u64(__m128, int);
	extern unsigned     int __ICL_INTRINCC _mm_cvtt_roundss_u32(__m128, int);
#define _mm_cvttss_u64(v) _mm_cvtt_roundss_u64(v, _MM_FROUND_CUR_DIRECTION)
#define _mm_cvttss_u32(v) _mm_cvtt_roundss_u32(v, _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm_cvt_roundi32_ss(__m128, int, int);
	extern __m128  __ICL_INTRINCC _mm_cvt_roundi64_ss(__m128, __int64, int);
#define _mm_cvti32_ss _mm_cvtsi32_ss
#define _mm_cvti64_ss _mm_cvtsi64_ss
#define _mm_cvt_roundsi32_ss _mm_cvt_roundi32_ss
#define _mm_cvt_roundsi64_ss _mm_cvt_roundi64_ss

	extern __m128  __ICL_INTRINCC _mm_cvt_roundu32_ss(__m128, unsigned int, int);
	extern __m128  __ICL_INTRINCC _mm_cvt_roundu64_ss(__m128, unsigned __int64,
		int);
#define _mm_cvtu32_ss(v, a) _mm_cvt_roundu32_ss((v), (a), \
                                                _MM_FROUND_CUR_DIRECTION)
#define _mm_cvtu64_ss(v, a) _mm_cvt_roundu64_ss((v), (a), \
                                                _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC       _mm_cvt_roundss_sd(__m128d, __m128, int);
	extern __m128d __ICL_INTRINCC  _mm_mask_cvt_roundss_sd(__m128d, __mmask8,
		__m128d, __m128, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_cvt_roundss_sd(__mmask8, __m128d,
		__m128, int);
#define  _mm_mask_cvtss_sd(v1, k, v2, v3) \
   _mm_mask_cvt_roundss_sd((v1), (k), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_cvtss_sd(k, v1, v2) \
  _mm_maskz_cvt_roundss_sd((k), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_cvt_roundsd_ss(__m128, __m128d, int);
	extern __m128 __ICL_INTRINCC _mm_mask_cvt_roundsd_ss(__m128, __mmask8,
		__m128, __m128d, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_cvt_roundsd_ss(__mmask8, __m128,
		__m128d, int);
#define _mm_mask_cvtsd_ss(v1, k, v2, v3) \
  _mm_mask_cvt_roundsd_ss((v1), (k), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_cvtsd_ss(k, v1, v2) \
  _mm_maskz_cvt_roundsd_ss((k), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_rcp14_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_rcp14_pd(__m512d, __mmask8, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_rcp14_pd(__mmask8, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_rcp14_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_rcp14_ps(__m512, __mmask16, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_rcp14_ps(__mmask16, __m512);


	extern __m512d __ICL_INTRINCC _mm512_roundscale_pd(__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_roundscale_pd(__m512d, __mmask8,
		__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_roundscale_pd(__mmask8, __m512d,
		int);
	extern __m512d __ICL_INTRINCC _mm512_roundscale_round_pd(__m512d, int,
		int);
	extern __m512d __ICL_INTRINCC _mm512_mask_roundscale_round_pd(__m512d,
		__mmask8,
		__m512d, int,
		int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_roundscale_round_pd(__mmask8,
		__m512d, int,
		int);
	extern __m512  __ICL_INTRINCC _mm512_roundscale_ps(__m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_roundscale_ps(__m512, __mmask16,
		__m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_roundscale_ps(__mmask16, __m512,
		int);
	extern __m512  __ICL_INTRINCC _mm512_roundscale_round_ps(__m512, int, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_roundscale_round_ps(__m512,
		__mmask16,
		__m512, int,
		int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_roundscale_round_ps(__mmask16,
		__m512, int,
		int);

	extern __m128d __ICL_INTRINCC _mm_roundscale_round_sd(__m128d, __m128d,
		const int, const int);
	extern __m128d __ICL_INTRINCC _mm_mask_roundscale_round_sd(__m128d, __mmask8,
		__m128d, __m128d,
		const int,
		const int);
	extern __m128d __ICL_INTRINCC _mm_maskz_roundscale_round_sd(__mmask8,
		__m128d, __m128d,
		const int,
		const int);

#define _mm_roundscale_sd(v1, v2, imm) \
    _mm_roundscale_round_sd((v1), (v2), (imm), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_roundscale_sd(v0, k, v1, v2, imm) \
    _mm_mask_roundscale_round_sd((v0), (k), (v1), (v2), (imm), \
                                 _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_roundscale_sd(k, v1, v2, imm) \
    _mm_maskz_roundscale_round_sd((k), (v1), (v2), (imm), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_roundscale_round_ss(__m128, __m128,
		const int, const int);
	extern __m128 __ICL_INTRINCC _mm_mask_roundscale_round_ss(__m128, __mmask8,
		__m128, __m128,
		const int,
		const int);
	extern __m128 __ICL_INTRINCC _mm_maskz_roundscale_round_ss(__mmask8,
		__m128, __m128,
		const int,
		const int);

#define _mm_roundscale_ss(v1, v2, imm) \
    _mm_roundscale_round_ss((v1), (v2), (imm), _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_roundscale_ss(v0, k, v1, v2, imm) \
    _mm_mask_roundscale_round_ss((v0), (k), (v1), (v2), (imm), \
                                 _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_roundscale_ss(k, v1, v2, imm) \
    _mm_maskz_roundscale_round_ss((k), (v1), (v2), (imm), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_rsqrt14_pd(__m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_rsqrt14_pd(__m512d, __mmask8,
		__m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_rsqrt14_pd(__mmask8, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_rsqrt14_ps(__m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_rsqrt14_ps(__m512, __mmask16,
		__m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_rsqrt14_ps(__mmask16, __m512);
	extern __m512d __ICL_INTRINCC _mm512_scalef_round_pd(__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_scalef_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_scalef_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_scalef_pd(v1, v2) \
    _mm512_scalef_round_pd((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_scalef_pd(v0, k1, v1, v2) \
    _mm512_mask_scalef_round_pd((v0), (k1), (v1), (v2), \
                                _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_scalef_pd(k1, v1, v2) \
    _mm512_maskz_scalef_round_pd((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_scalef_round_ps(__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_scalef_round_ps(__m512, __mmask16,
		__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_scalef_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_scalef_ps(v1, v2) \
    _mm512_scalef_round_ps((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_scalef_ps(v0, k1, v1, v2) \
    _mm512_mask_scalef_round_ps((v0), (k1), (v1), (v2), \
                                _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_scalef_ps(k1, v1, v2) \
    _mm512_maskz_scalef_round_ps((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_mask_compress_epi32(__m512i, __mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_compress_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_compress_epi64(__m512i, __mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_compress_epi64(__mmask8, __m512i);
	extern __m512d __ICL_INTRINCC _mm512_mask_compress_pd(__m512d, __mmask8,
		__m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_compress_pd(__mmask8, __m512d);
	extern __m512  __ICL_INTRINCC _mm512_mask_compress_ps(__m512, __mmask16,
		__m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_compress_ps(__mmask16, __m512);

	extern void    __ICL_INTRINCC _mm512_mask_compressstoreu_epi32(void*,
		__mmask16,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_compressstoreu_epi64(void*, __mmask8,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_compressstoreu_pd(void*, __mmask8,
		__m512d);
	extern void    __ICL_INTRINCC _mm512_mask_compressstoreu_ps(void*, __mmask16,
		__m512);

	extern __m512d __ICL_INTRINCC _mm512_fixupimm_pd(__m512d, __m512d, __m512i,
		int);
	extern __m512d __ICL_INTRINCC _mm512_mask_fixupimm_pd(__m512d, __mmask8,
		__m512d, __m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_fixupimm_pd(__mmask8, __m512d,
		__m512d, __m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_fixupimm_round_pd(__m512d, __m512d,
		__m512i, int, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_fixupimm_round_pd(__m512d, __mmask8,
		__m512d, __m512i,
		int, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_fixupimm_round_pd(__mmask8, __m512d,
		__m512d, __m512i,
		int, int);
	extern __m512  __ICL_INTRINCC _mm512_fixupimm_ps(__m512, __m512, __m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_fixupimm_ps(__m512, __mmask16,
		__m512, __m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_fixupimm_ps(__mmask16, __m512,
		__m512, __m512i, int);
	extern __m512  __ICL_INTRINCC _mm512_fixupimm_round_ps(__m512, __m512, __m512i,
		int, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_fixupimm_round_ps(__m512, __mmask16,
		__m512, __m512i,
		int, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_fixupimm_round_ps(__mmask16, __m512,
		__m512, __m512i,
		int, int);

	extern __m128d __ICL_INTRINCC _mm_fixupimm_round_sd(__m128d, __m128d,
		__m128i, int, int);
	extern __m128d __ICL_INTRINCC _mm_mask_fixupimm_round_sd(__m128d, __mmask8,
		__m128d, __m128i,
		int, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_fixupimm_round_sd(__mmask8, __m128d,
		__m128d, __m128i,
		int, int);
#define _mm_fixupimm_sd(v1, v2, v3, i1)                         \
    _mm_fixupimm_round_sd((v1), (v2), (v3), (i1),               \
                          _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_fixupimm_sd(v1, k1, v2, v3, i1)                \
    _mm_mask_fixupimm_round_sd((v1), (k1), (v2), (v3), (i1),    \
                               _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_fixupimm_sd(k1, v1, v2, v3, i1)               \
    _mm_maskz_fixupimm_round_sd((k1), (v1), (v2), (v3), (i1),   \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm_fixupimm_round_ss(__m128, __m128, __m128i,
		int, int);
	extern __m128  __ICL_INTRINCC _mm_mask_fixupimm_round_ss(__m128, __mmask8,
		__m128, __m128i,
		int, int);
	extern __m128  __ICL_INTRINCC _mm_maskz_fixupimm_round_ss(__mmask8, __m128,
		__m128, __m128i, int,
		int);

#define _mm_fixupimm_ss(v1, v2, v3, i1)                         \
    _mm_fixupimm_round_ss((v1), (v2), (v3), (i1),               \
                          _MM_FROUND_CUR_DIRECTION)
#define _mm_mask_fixupimm_ss(v1, k1, v2, v3, i1)                \
    _mm_mask_fixupimm_round_ss((v1), (k1), (v2), (v3), (i1),    \
                               _MM_FROUND_CUR_DIRECTION)
#define _mm_maskz_fixupimm_ss(k1, v1, v2, v3, i1)               \
    _mm_maskz_fixupimm_round_ss((k1), (v1), (v2), (v3), (i1),   \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_getmant_round_pd(__m512d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m512d __ICL_INTRINCC _mm512_mask_getmant_round_pd(__m512d, __mmask8,
		__m512d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_getmant_round_pd(__mmask8, __m512d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);

#define _mm512_maskz_getmant_pd(k1, v1, i1, i2)                         \
    _mm512_maskz_getmant_round_pd((k1), (v1), (i1), (i2),               \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_getmant_round_ps(__m512,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m512  __ICL_INTRINCC _mm512_mask_getmant_round_ps(__m512, __mmask16,
		__m512,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_getmant_round_ps(__mmask16, __m512,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
#define _mm512_maskz_getmant_ps(k1, v1, i1, i2)                         \
    _mm512_maskz_getmant_round_ps((k1), (v1), (i1), (i2),               \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_getmant_round_sd(__m128d, __m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m128d __ICL_INTRINCC _mm_mask_getmant_round_sd(__m128d, __mmask8,
		__m128d, __m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m128d __ICL_INTRINCC _mm_maskz_getmant_round_sd(__mmask8, __m128d,
		__m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
#define _mm_getmant_sd(v1, v2, i1, i2)                  \
    _mm_getmant_round_sd((v1), (v2), (i1), (i2),        \
                         _MM_FROUND_CUR_DIRECTION)

#define _mm_mask_getmant_sd(v1, k1, v2, v3, i1, i2)                     \
    _mm_mask_getmant_round_sd((v1), (k1), (v2), (v3), (i1), (i2),       \
                              _MM_FROUND_CUR_DIRECTION)

#define _mm_maskz_getmant_sd(k1, v1, v2, i1, i2)                        \
    _mm_maskz_getmant_round_sd((k1), (v1), (v2), (i1), (i2),            \
                               _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_getmant_round_ss(__m128, __m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m128 __ICL_INTRINCC _mm_mask_getmant_round_ss(__m128, __mmask8,
		__m128, __m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
	extern __m128 __ICL_INTRINCC _mm_maskz_getmant_round_ss(__mmask8, __m128,
		__m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM,
		int);
#define _mm_getmant_ss(v1, v2, i1, i2)                  \
    _mm_getmant_round_ss((v1), (v2), (i1), (i2),        \
                         _MM_FROUND_CUR_DIRECTION)

#define _mm_mask_getmant_ss(v1, k1, v2, v3, i1, i2)                     \
    _mm_mask_getmant_round_ss((v1), (k1), (v2), (v3), (i1), (i2),       \
                              _MM_FROUND_CUR_DIRECTION)

#define _mm_maskz_getmant_ss(k1, v1, v2, i1, i2)                        \
    _mm_maskz_getmant_round_ss((k1), (v1), (v2), (i1), (i2),            \
                               _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_ternarylogic_epi32(__m512i, __m512i,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_ternarylogic_epi32(__m512i,
		__mmask16,
		__m512i,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_ternarylogic_epi32(__mmask16,
		__m512i,
		__m512i,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_ternarylogic_epi64(__m512i, __m512i,
		__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_ternarylogic_epi64(__m512i, __mmask8,
		__m512i, __m512i,
		int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_ternarylogic_epi64(__mmask8,
		__m512i,
		__m512i,
		__m512i,
		int);

	extern __m512d __ICL_INTRINCC _mm512_maskz_fmadd_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);
#define _mm512_maskz_fmadd_pd(k1, v1, v2, v3) \
    _mm512_maskz_fmadd_round_pd((k1), (v1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_fmadd_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);
#define _mm512_maskz_fmadd_ps(k1, v1, v2, v3) \
    _mm512_maskz_fmadd_round_ps((k1), (v1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fmaddsub_round_pd(__m512d, __m512d,
		__m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_fmaddsub_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fmaddsub_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_fmaddsub_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);

#define _mm512_fmaddsub_pd(v1, v2, v3) \
    _mm512_fmaddsub_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmaddsub_pd(v1, k1, v2, v3) \
    _mm512_mask_fmaddsub_round_pd((v1), (k1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmaddsub_pd(v1, v2, v3, k3) \
    _mm512_mask3_fmaddsub_round_pd((v1), (v2), (v3), (k3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_fmaddsub_pd(k1, v1, v2, v3) \
    _mm512_maskz_fmaddsub_round_pd((k1), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m512 __ICL_INTRINCC _mm512_fmaddsub_round_ps(__m512, __m512, __m512,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_mask_fmaddsub_round_ps(__m512, __mmask16,
		__m512, __m512,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_mask3_fmaddsub_round_ps(__m512, __m512,
		__m512, __mmask16,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_maskz_fmaddsub_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);

#define _mm512_fmaddsub_ps(v1, v2, v3) \
    _mm512_fmaddsub_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmaddsub_ps(v1, k1, v2, v3) \
    _mm512_mask_fmaddsub_round_ps((v1), (k1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmaddsub_ps(v1, v2, v3, k3) \
    _mm512_mask3_fmaddsub_round_ps((v1), (v2), (v3), (k3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_fmaddsub_ps(k1, v1, v2, v3) \
    _mm512_maskz_fmaddsub_round_ps((k1), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_fmsub_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);
#define _mm512_maskz_fmsub_pd(k1, v1, v2, v3) \
    _mm512_maskz_fmsub_round_pd((k1), (v1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_fmsub_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);
#define _mm512_maskz_fmsub_ps(k1, v1, v2, v3) \
    _mm512_maskz_fmsub_round_ps((k1), (v1), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_fmsubadd_round_pd(__m512d, __m512d,
		__m512d, const int);
	extern __m512d __ICL_INTRINCC _mm512_mask_fmsubadd_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_mask3_fmsubadd_round_pd(__m512d, __m512d,
		__m512d, __mmask8,
		const int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_fmsubadd_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);

#define _mm512_fmsubadd_pd(v1, v2, v3) \
    _mm512_fmsubadd_round_pd((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmsubadd_pd(v1, k1, v2, v3) \
    _mm512_mask_fmsubadd_round_pd((v1), (k1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmsubadd_pd(v1, v2, v3, k3) \
    _mm512_mask3_fmsubadd_round_pd((v1), (v2), (v3), (k3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_fmsubadd_pd(k1, v1, v2, v3) \
    _mm512_maskz_fmsubadd_round_pd((k1), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m512 __ICL_INTRINCC _mm512_fmsubadd_round_ps(__m512, __m512, __m512,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_mask_fmsubadd_round_ps(__m512, __mmask16,
		__m512, __m512,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_mask3_fmsubadd_round_ps(__m512, __m512,
		__m512, __mmask16,
		const int);
	extern __m512 __ICL_INTRINCC _mm512_maskz_fmsubadd_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);

#define _mm512_fmsubadd_ps(v1, v2, v3) \
    _mm512_fmsubadd_round_ps((v1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask_fmsubadd_ps(v1, k1, v2, v3) \
    _mm512_mask_fmsubadd_round_ps((v1), (k1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)

#define _mm512_mask3_fmsubadd_ps(v1, v2, v3, k3) \
    _mm512_mask3_fmsubadd_round_ps((v1), (v2), (v3), (k3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_fmsubadd_ps(k1, v1, v2, v3) \
    _mm512_maskz_fmsubadd_round_ps((k1), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_fnmadd_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);
#define _mm512_maskz_fnmadd_pd(k1, v1, v2, v3) \
    _mm512_maskz_fnmadd_round_pd((k1), (v1), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_fnmadd_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);
#define _mm512_maskz_fnmadd_ps(k1, v1, v2, v3) \
    _mm512_maskz_fnmadd_round_ps((k1), (v1), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_fnmsub_round_pd(__mmask8, __m512d,
		__m512d, __m512d,
		const int);
#define _mm512_maskz_fnmsub_pd(k1, v1, v2, v3) \
    _mm512_maskz_fnmsub_round_pd((k1), (v1), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_fnmsub_round_ps(__mmask16, __m512,
		__m512, __m512,
		const int);
#define _mm512_maskz_fnmsub_ps(k1, v1, v2, v3) \
    _mm512_maskz_fnmsub_round_ps((k1), (v1), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC   _mm_mask_fmadd_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmadd_round_ss(__mmask8, __m128,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmadd_round_ss(__m128, __m128,
		__m128, __mmask8, int);
#define  _mm_mask_fmadd_ss(v1, k, v2, v3) \
         _mm_mask_fmadd_round_ss((v1), (k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fmadd_ss(k, v1, v2, v3) \
         _mm_maskz_fmadd_round_ss((k), (v1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fmadd_ss(v1, v2, v3, k) \
         _mm_mask3_fmadd_round_ss((v1), (v2), (v3), (k), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC   _mm_mask_fmadd_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmadd_round_sd(__mmask8, __m128d,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmadd_round_sd(__m128d, __m128d,
		__m128d, __mmask8,
		int);
#define  _mm_mask_fmadd_sd(v1, k, v2, v3) \
         _mm_mask_fmadd_round_sd((v1), (k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fmadd_sd(k, v1, v2, v3) \
         _mm_maskz_fmadd_round_sd((k), (v1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fmadd_sd(v1, v2, v3, k) \
         _mm_mask3_fmadd_round_sd((v1), (v2), (v3), (k), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC   _mm_mask_fmsub_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmsub_round_ss(__mmask8, __m128,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmsub_round_ss(__m128, __m128,
		__m128, __mmask8, int);
#define  _mm_mask_fmsub_ss(v1, k, v2, v3) \
         _mm_mask_fmsub_round_ss((v1), (k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fmsub_ss(k, v1, v2, v3) \
         _mm_maskz_fmsub_round_ss((k), (v1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fmsub_ss(v1, v2, v3, k) \
         _mm_mask3_fmsub_round_ss((v1), (v2), (v3), (k), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC   _mm_mask_fmsub_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmsub_round_sd(__mmask8, __m128d,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmsub_round_sd(__m128d, __m128d,
		__m128d, __mmask8,
		int);
#define  _mm_mask_fmsub_sd(v1, k, v2, v3) \
         _mm_mask_fmsub_round_sd((v1), (k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fmsub_sd(k, v1, v2, v3) \
         _mm_maskz_fmsub_round_sd((k), (v1), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fmsub_sd(v1, v2, v3, k) \
         _mm_mask3_fmsub_round_sd((v1), (v2), (v3), (k), \
                                  _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC   _mm_mask_fnmadd_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fnmadd_round_ss(__mmask8, __m128,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fnmadd_round_ss(__m128, __m128,
		__m128, __mmask8, int);
#define  _mm_mask_fnmadd_ss(v1, k, v2, v3) \
         _mm_mask_fnmadd_round_ss((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fnmadd_ss(k, v1, v2, v3) \
         _mm_maskz_fnmadd_round_ss((k), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fnmadd_ss(v1, v2, v3, k) \
         _mm_mask3_fnmadd_round_ss((v1), (v2), (v3), (k), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC   _mm_mask_fnmadd_round_sd(__m128d, __mmask8,
		__m128d, __m128d,
		int);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fnmadd_round_sd(__mmask8, __m128d,
		__m128d, __m128d,
		int);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fnmadd_round_sd(__m128d, __m128d,
		__m128d, __mmask8,
		int);
#define  _mm_mask_fnmadd_sd(v1, k, v2, v3) \
         _mm_mask_fnmadd_round_sd((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fnmadd_sd(k, v1, v2, v3) \
         _mm_maskz_fnmadd_round_sd((k), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fnmadd_sd(v1, v2, v3, k) \
         _mm_mask3_fnmadd_round_sd((v1), (v2), (v3), (k), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC   _mm_mask_fnmsub_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fnmsub_round_ss(__mmask8, __m128,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fnmsub_round_ss(__m128, __m128,
		__m128, __mmask8, int);
#define  _mm_mask_fnmsub_ss(v1, k, v2, v3) \
         _mm_mask_fnmsub_round_ss((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fnmsub_ss(k, v1, v2, v3) \
         _mm_maskz_fnmsub_round_ss((k), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fnmsub_ss(v1, v2, v3, k) \
         _mm_mask3_fnmsub_round_ss((v1), (v2), (v3), (k), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC   _mm_mask_fnmsub_round_sd(__m128d, __mmask8,
		__m128d, __m128d,
		int);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fnmsub_round_sd(__mmask8, __m128d,
		__m128d, __m128d,
		int);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fnmsub_round_sd(__m128d, __m128d,
		__m128d, __mmask8,
		int);
#define  _mm_mask_fnmsub_sd(v1, k, v2, v3) \
         _mm_mask_fnmsub_round_sd((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_fnmsub_sd(k, v1, v2, v3) \
         _mm_maskz_fnmsub_round_sd((k), (v1), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask3_fnmsub_sd(v1, v2, v3, k) \
         _mm_mask3_fnmsub_round_sd((v1), (v2), (v3), (k), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm512_extractf32x4_ps(__m512, int);
	extern __m256d __ICL_INTRINCC _mm512_extractf64x4_pd(__m512d, int);

	extern __m128i __ICL_INTRINCC _mm512_extracti32x4_epi32(__m512i, int);
	extern __m256i __ICL_INTRINCC _mm512_extracti64x4_epi64(__m512i, int);

	extern __m128  __ICL_INTRINCC _mm512_mask_extractf32x4_ps(__m128, __mmask8,
		__m512, int);
	extern __m128  __ICL_INTRINCC _mm512_maskz_extractf32x4_ps(__mmask8,
		__m512, int);
	extern __m256d __ICL_INTRINCC _mm512_mask_extractf64x4_pd(__m256d, __mmask8,
		__m512d, int);
	extern __m256d __ICL_INTRINCC _mm512_maskz_extractf64x4_pd(__mmask8,
		__m512d, int);

	extern __m128i __ICL_INTRINCC _mm512_mask_extracti32x4_epi32(__m128i, __mmask8,
		__m512i, int);
	extern __m128i __ICL_INTRINCC _mm512_maskz_extracti32x4_epi32(__mmask8,
		__m512i, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_extracti64x4_epi64(__m256i, __mmask8,
		__m512i, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_extracti64x4_epi64(__mmask8,
		__m512i, int);

#define _mm512_i32gather_epi64(index, addr, scale)  \
    _mm512_i32logather_epi64(_mm512_castsi256_si512(index), (addr), (scale))

#define _mm512_mask_i32gather_epi64(v1_old, k1, index, addr, scale) \
    _mm512_mask_i32logather_epi64((v1_old), (k1),                   \
                                  _mm512_castsi256_si512(index),    \
                                  (addr), (scale))

#define _mm512_i32gather_pd(index, addr, scale)  \
    _mm512_i32logather_pd(_mm512_castsi256_si512(index), (addr), (scale))

#define _mm512_mask_i32gather_pd(v1_old, k1, index, addr, scale)  \
    _mm512_mask_i32logather_pd((v1_old), (k1),                    \
                               _mm512_castsi256_si512(index),     \
                               (addr), (scale))

#define _mm512_i64gather_epi32(index, addr, scale)  \
    _mm512_castsi512_si256(_mm512_i64gather_epi32lo((index), (addr), (scale)))

#define _mm512_mask_i64gather_epi32(v1_old, k1, index, addr, scale)  \
    _mm512_castsi512_si256(_mm512_mask_i64gather_epi32lo(            \
                               _mm512_castsi256_si512(v1_old), (k1), \
                               (index), (addr), (scale)))

#define _mm512_i64gather_ps(index, addr, scale)  \
    _mm512_castps512_ps256(_mm512_i64gather_pslo((index), (addr), (scale)))

#define _mm512_mask_i64gather_ps(v1_old, k1, index, addr, scale)     \
    _mm512_castps512_ps256(_mm512_mask_i64gather_pslo(               \
                               _mm512_castps256_ps512(v1_old), (k1), \
                               (index), (addr), (scale)))

#define _mm512_i32scatter_epi64(addr, index, v1, scale)              \
    _mm512_i32loscatter_epi64((addr), _mm512_castsi256_si512(index), \
                              (v1), (scale))

#define _mm512_mask_i32scatter_epi64(addr, k1, index, v1, scale)  \
    _mm512_mask_i32loscatter_epi64((addr), (k1),                  \
                                   _mm512_castsi256_si512(index), \
                                   (v1), (scale))

#define _mm512_i32scatter_pd(addr, index, v1, scale)              \
    _mm512_i32loscatter_pd((addr), _mm512_castsi256_si512(index), \
                           (v1), (scale))

#define _mm512_mask_i32scatter_pd(addr, k1, index, v1, scale)  \
    _mm512_mask_i32loscatter_pd((addr), (k1),                  \
                                _mm512_castsi256_si512(index), \
                                (v1), (scale))

#define _mm512_i64scatter_epi32(addr, index, v1, scale) \
    _mm512_i64scatter_epi32lo((addr), (index),          \
                              _mm512_castsi256_si512(v1), (scale))

#define _mm512_mask_i64scatter_epi32(addr, k1, index, v1, scale)  \
    _mm512_mask_i64scatter_epi32lo((addr), (k1), (index),         \
                                   _mm512_castsi256_si512(v1), (scale))

#define _mm512_i64scatter_ps(addr, index, v1, scale) \
    _mm512_i64scatter_pslo((addr), (index),          \
                           _mm512_castps256_ps512(v1), (scale))

#define _mm512_mask_i64scatter_ps(addr, k1, index, v1, scale)  \
    _mm512_mask_i64scatter_pslo((addr), (k1), (index),         \
                                _mm512_castps256_ps512(v1), (scale))

	extern __m512  __ICL_INTRINCC _mm512_insertf32x4(__m512, __m128, int);
	extern __m512d __ICL_INTRINCC _mm512_insertf64x4(__m512d, __m256d, int);
	extern __m512i __ICL_INTRINCC _mm512_inserti32x4(__m512i, __m128i, int);
	extern __m512i __ICL_INTRINCC _mm512_inserti64x4(__m512i, __m256i, int);

	extern __m512  __ICL_INTRINCC _mm512_mask_insertf32x4(__m512, __mmask16,
		__m512, __m128, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_insertf32x4(__mmask16,
		__m512, __m128, int);

	extern __m512d __ICL_INTRINCC _mm512_mask_insertf64x4(__m512d, __mmask8,
		__m512d, __m256d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_insertf64x4(__mmask8,
		__m512d, __m256d, int);

	extern __m512i __ICL_INTRINCC _mm512_mask_inserti32x4(__m512i, __mmask16,
		__m512i, __m128i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_inserti32x4(__mmask16,
		__m512i, __m128i, int);

	extern __m512i __ICL_INTRINCC _mm512_mask_inserti64x4(__m512i, __mmask8,
		__m512i, __m256i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_inserti64x4(__mmask8,
		__m512i, __m256i, int);

	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epu32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_min_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_min_epu32(__mmask16, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_max_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_max_epu64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epu64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epu64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_min_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_min_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_min_epi64(__mmask8, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_min_epu64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_min_epu64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_min_epu64(__mmask8, __m512i,
		__m512i);

	extern __m512d __ICL_INTRINCC _mm512_max_round_pd(__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_max_round_pd(__m512d, __mmask8,
		__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_max_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_max_pd(k1, v2, v3) \
    _mm512_maskz_max_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_min_round_pd(__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_min_round_pd(__m512d, __mmask8,
		__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_min_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_min_pd(k1, v2, v3) \
    _mm512_maskz_min_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_max_round_ps(__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_max_round_ps(__m512, __mmask16,
		__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_max_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_max_ps(k1, v2, v3) \
    _mm512_maskz_max_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_min_round_ps(__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_min_round_ps(__m512, __mmask16,
		__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_min_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_min_ps(k1, v2, v3) \
    _mm512_maskz_min_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_add_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_add_pd(k1, v2, v3) \
    _mm512_maskz_add_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_maskz_add_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_add_ps(k1, v2, v3) \
    _mm512_maskz_add_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_div_round_pd(__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_div_round_pd(__m512d, __mmask8,
		__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_div_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_div_pd(k1, v2, v3) \
    _mm512_maskz_div_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_div_round_ps(__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_div_round_ps(__m512, __mmask16,
		__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_div_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_div_ps(k1, v2, v3) \
    _mm512_maskz_div_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_mul_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_mul_pd(k1, v2, v3) \
    _mm512_maskz_mul_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_mul_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_mul_ps(k1, v2, v3) \
    _mm512_maskz_mul_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_maskz_sub_round_pd(__mmask8, __m512d,
		__m512d, int);
#define _mm512_maskz_sub_pd(k1, v2, v3) \
    _mm512_maskz_sub_round_pd((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_maskz_sub_round_ps(__mmask16, __m512,
		__m512, int);
#define _mm512_maskz_sub_ps(k1, v2, v3) \
    _mm512_maskz_sub_round_ps((k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)

	extern __int64  __ICL_INTRINCC _mm512_reduce_add_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_add_epi64(__mmask8, __m512i);
	extern __int64  __ICL_INTRINCC _mm512_reduce_mul_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_mul_epi64(__mmask8, __m512i);
	extern __int64  __ICL_INTRINCC _mm512_reduce_min_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_min_epi64(__mmask8, __m512i);
	extern unsigned __int64 __ICL_INTRINCC _mm512_reduce_min_epu64(__m512i);
	extern unsigned __int64 __ICL_INTRINCC _mm512_mask_reduce_min_epu64(__mmask8,
		__m512i);
	extern __int64  __ICL_INTRINCC _mm512_reduce_max_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_max_epi64(__mmask8, __m512i);
	extern unsigned __int64 __ICL_INTRINCC _mm512_reduce_max_epu64(__m512i);
	extern unsigned __int64 __ICL_INTRINCC _mm512_mask_reduce_max_epu64(__mmask8,
		__m512i);
	extern __int64  __ICL_INTRINCC _mm512_reduce_or_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_or_epi64(__mmask8, __m512i);
	extern __int64  __ICL_INTRINCC _mm512_reduce_and_epi64(__m512i);
	extern __int64  __ICL_INTRINCC _mm512_mask_reduce_and_epi64(__mmask8, __m512i);

	extern __m128d __ICL_INTRINCC _mm_scalef_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_scalef_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_scalef_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_scalef_sd(v1, v2) \
         _mm_scalef_round_sd((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask_scalef_sd(v1, k, v2, v3) \
         _mm_mask_scalef_round_sd((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_scalef_sd(k, v2, v3) \
         _mm_maskz_scalef_round_sd((k), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_scalef_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_scalef_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_scalef_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_scalef_ss(v1, v2) \
         _mm_scalef_round_ss((v1), (v2), _MM_FROUND_CUR_DIRECTION)
#define  _mm_mask_scalef_ss(v1, k, v2, v3) \
         _mm_mask_scalef_round_ss((v1), (k), (v2), (v3), \
                                  _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_scalef_ss(k, v2, v3) \
         _mm_maskz_scalef_round_ss((k), (v2), (v3), \
                                   _MM_FROUND_CUR_DIRECTION)

	extern __m512i  __ICL_INTRINCC _mm512_set1_epi8(char);
	extern __m512i  __ICL_INTRINCC _mm512_set1_epi16(short);

	extern __m512i  __ICL_INTRINCC _mm512_mask_set1_epi32(__m512i, __mmask16, int);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_set1_epi32(__mmask16, int);
	extern __m512i  __ICL_INTRINCC _mm512_mask_set1_epi64(__m512i, __mmask8,
		__int64);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_set1_epi64(__mmask8, __int64);

	extern __m512d __ICL_INTRINCC _mm512_sqrt_round_pd(__m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_mask_sqrt_round_pd(__m512d, __mmask8,
		__m512d,
		int /* rounding */);
	extern __m512d __ICL_INTRINCC _mm512_maskz_sqrt_round_pd(__mmask8, __m512d,
		int /* rounding */);
#define _mm512_maskz_sqrt_pd(k1, v1) \
    _mm512_maskz_sqrt_round_pd((k1), (v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_sqrt_round_ps(__m512, int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_mask_sqrt_round_ps(__m512, __mmask16,
		__m512,
		int /* rounding */);
	extern __m512  __ICL_INTRINCC _mm512_maskz_sqrt_round_ps(__mmask16, __m512,
		int /* rounding */);
#define _mm512_maskz_sqrt_ps(k1, v1) \
    _mm512_maskz_sqrt_round_ps((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_sqrt_round_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_sqrt_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_sqrt_round_sd(__mmask8,
		__m128d, __m128d, int);
#define  _mm_mask_sqrt_sd(v1, k, v2, v3) \
         _mm_mask_sqrt_round_sd((v1), (k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_sqrt_sd(k, v2, v3) \
         _mm_maskz_sqrt_round_sd((k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_sqrt_round_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_sqrt_round_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_sqrt_round_ss(__mmask8,
		__m128, __m128, int);
#define  _mm_mask_sqrt_ss(v1, k, v2, v3) \
         _mm_mask_sqrt_round_ss((v1), (k), (v2), (v3), \
                                _MM_FROUND_CUR_DIRECTION)
#define  _mm_maskz_sqrt_ss(k, v2, v3) \
         _mm_maskz_sqrt_round_ss((k), (v2), (v3), \
                                 _MM_FROUND_CUR_DIRECTION)

	extern __m512i __ICL_INTRINCC _mm512_maskz_sub_epi32(__mmask16, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_sub_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sub_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sub_epi64(__mmask8, __m512i,
		__m512i);

	extern __m512i __ICL_INTRINCC _mm512_maskz_xor_epi32(__mmask16, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_xor_epi64(__mmask8, __m512i,
		__m512i);

	extern __mmask16 __ICL_INTRINCC _mm512_kunpackb(__mmask16, __mmask16);

	/*
	* Intel(R) AVX-512 Conflict Detection Instructions.
	*/

	extern __m512i __ICL_INTRINCC _mm512_broadcastmb_epi64(__mmask8);
	extern __m512i __ICL_INTRINCC _mm512_broadcastmw_epi32(__mmask16);

	extern __m512i __ICL_INTRINCC _mm512_conflict_epi32(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_conflict_epi32(__m512i, __mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_conflict_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_conflict_epi64(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_conflict_epi64(__m512i, __mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_conflict_epi64(__mmask8, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_lzcnt_epi32(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_lzcnt_epi32(__m512i, __mmask16,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_lzcnt_epi32(__mmask16, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_lzcnt_epi64(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_lzcnt_epi64(__m512i, __mmask8,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_lzcnt_epi64(__mmask8, __m512i);

	/*
	* Intel(R) AVX-512 Exponential and Reciprocal Instructions.
	*/

	extern __m512 __ICL_INTRINCC _mm512_exp2a23_round_ps(__m512, int);
#define _mm512_exp2a23_ps(v1) \
    _mm512_exp2a23_round_ps((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512 __ICL_INTRINCC _mm512_mask_exp2a23_round_ps(__m512, __mmask16,
		__m512, int);
#define _mm512_mask_exp2a23_ps(v1, k1, v2) \
    _mm512_mask_exp2a23_round_ps((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512 __ICL_INTRINCC _mm512_maskz_exp2a23_round_ps(__mmask16, __m512,
		int);
#define _mm512_maskz_exp2a23_ps(k1, v1) \
    _mm512_maskz_exp2a23_round_ps((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_exp2a23_round_pd(__m512d, int);
#define _mm512_exp2a23_pd(v1) \
    _mm512_exp2a23_round_pd((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_mask_exp2a23_round_pd(__m512d, __mmask8,
		__m512d, int);
#define _mm512_mask_exp2a23_pd(v1, k1, v2) \
    _mm512_mask_exp2a23_round_pd((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_maskz_exp2a23_round_pd(__mmask8, __m512d,
		int);
#define _mm512_maskz_exp2a23_pd(k1, v1) \
    _mm512_maskz_exp2a23_round_pd((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_rcp28_round_sd(__m128d, __m128d, int);
#define _mm_rcp28_sd(v1, v2) \
    _mm_rcp28_round_sd((v1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m128d __ICL_INTRINCC _mm_mask_rcp28_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
#define _mm_mask_rcp28_sd(v1, k1, v2, v3) \
    _mm_mask_rcp28_round_sd((v1), (k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
	extern __m128d __ICL_INTRINCC _mm_maskz_rcp28_round_sd(__mmask8, __m128d,
		__m128d, int);
#define _mm_maskz_rcp28_sd(k1, v1, v2) \
    _mm_maskz_rcp28_round_sd((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_rcp28_round_ss(__m128, __m128, int);
#define _mm_rcp28_ss(v1, v2) \
    _mm_rcp28_round_ss((v1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m128 __ICL_INTRINCC _mm_mask_rcp28_round_ss(__m128, __mmask8,
		__m128, __m128, int);
#define _mm_mask_rcp28_ss(v1, k1, v2, v3) \
    _mm_mask_rcp28_round_ss((v1), (k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
	extern __m128 __ICL_INTRINCC _mm_maskz_rcp28_round_ss(__mmask8, __m128,
		__m128, int);
#define _mm_maskz_rcp28_ss(k1, v1, v2) \
    _mm_maskz_rcp28_round_ss((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_rcp28_round_ps(__m512, int);
#define _mm512_rcp28_ps(v1) \
    _mm512_rcp28_round_ps((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_mask_rcp28_round_ps(__m512, __mmask16,
		__m512, int);
#define _mm512_mask_rcp28_ps(v1, k1, v2) \
    _mm512_mask_rcp28_round_ps((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_rcp28_round_ps(__mmask16, __m512,
		int);
#define _mm512_maskz_rcp28_ps(k1, v1) \
    _mm512_maskz_rcp28_round_ps((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_rcp28_round_pd(__m512d, int);
#define _mm512_rcp28_pd(v1) \
    _mm512_rcp28_round_pd((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_mask_rcp28_round_pd(__m512d, __mmask8,
		__m512d, int);
#define _mm512_mask_rcp28_pd(v1, k1, v2) \
    _mm512_mask_rcp28_round_pd((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_maskz_rcp28_round_pd(__mmask8, __m512d,
		int);
#define _mm512_maskz_rcp28_pd(k1, v1) \
    _mm512_maskz_rcp28_round_pd((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_rsqrt28_round_sd(__m128d, __m128d, int);
#define _mm_rsqrt28_sd(v1, v2) \
    _mm_rsqrt28_round_sd((v1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m128d __ICL_INTRINCC _mm_mask_rsqrt28_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
#define _mm_mask_rsqrt28_sd(v1, k1, v2, v3) \
    _mm_mask_rsqrt28_round_sd((v1), (k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
	extern __m128d __ICL_INTRINCC _mm_maskz_rsqrt28_round_sd(__mmask8, __m128d,
		__m128d, int);
#define _mm_maskz_rsqrt28_sd(k1, v1, v2) \
    _mm_maskz_rsqrt28_round_sd((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_rsqrt28_round_ss(__m128, __m128, int);
#define _mm_rsqrt28_ss(v1, v2) \
    _mm_rsqrt28_round_ss((v1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m128 __ICL_INTRINCC _mm_mask_rsqrt28_round_ss(__m128, __mmask8,
		__m128, __m128, int);
#define _mm_mask_rsqrt28_ss(v1, k1, v2, v3) \
    _mm_mask_rsqrt28_round_ss((v1), (k1), (v2), (v3), _MM_FROUND_CUR_DIRECTION)
	extern __m128 __ICL_INTRINCC _mm_maskz_rsqrt28_round_ss(__mmask8, __m128,
		__m128, int);
#define _mm_maskz_rsqrt28_ss(k1, v1, v2) \
    _mm_maskz_rsqrt28_round_ss((k1), (v1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m512  __ICL_INTRINCC _mm512_rsqrt28_round_ps(__m512, int);
#define _mm512_rsqrt28_ps(v1) \
    _mm512_rsqrt28_round_ps((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_mask_rsqrt28_round_ps(__m512, __mmask16,
		__m512, int);
#define _mm512_mask_rsqrt28_ps(v1, k1, v2) \
    _mm512_mask_rsqrt28_round_ps((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512  __ICL_INTRINCC _mm512_maskz_rsqrt28_round_ps(__mmask16, __m512,
		int);
#define _mm512_maskz_rsqrt28_ps(k1, v1) \
    _mm512_maskz_rsqrt28_round_ps((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	extern __m512d __ICL_INTRINCC _mm512_rsqrt28_round_pd(__m512d, int);
#define _mm512_rsqrt28_pd(v1) \
    _mm512_rsqrt28_round_pd((v1), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_mask_rsqrt28_round_pd(__m512d, __mmask8,
		__m512d, int);
#define _mm512_mask_rsqrt28_pd(v1, k1, v2) \
    _mm512_mask_rsqrt28_round_pd((v1), (k1), (v2), _MM_FROUND_CUR_DIRECTION)
	extern __m512d __ICL_INTRINCC _mm512_maskz_rsqrt28_round_pd(__mmask8, __m512d,
		int);
#define _mm512_maskz_rsqrt28_pd(k1, v1) \
    _mm512_maskz_rsqrt28_round_pd((k1), (v1), _MM_FROUND_CUR_DIRECTION)

	/*
	* Intel(R) AVX-512 Prefetch Instructions.
	*/

	extern void __ICL_INTRINCC _mm512_prefetch_i64gather_ps(__m512i, void const*,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i64gather_ps(__m512i /* idx */,
		__mmask8,
		void const*,
		int /* scale */,
		int /* hint */);
	extern void __ICL_INTRINCC _mm512_prefetch_i64scatter_ps(void*, __m512i,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i64scatter_ps(void*, __mmask8,
		__m512i,
		int /* scale */,
		int /* hint */);

	extern void __ICL_INTRINCC _mm512_prefetch_i32gather_pd(__m256i, void const*,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i32gather_pd(__m256i /* idx */,
		__mmask8,
		void const*,
		int /* scale */,
		int /* hint */);
	extern void __ICL_INTRINCC _mm512_prefetch_i32scatter_pd(void*, __m256i,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i32scatter_pd(void*, __mmask8,
		__m256i,
		int /* scale */,
		int /* hint */);

	extern void __ICL_INTRINCC _mm512_prefetch_i64gather_pd(__m512i, void const*,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i64gather_pd(__m512i /* idx */,
		__mmask8,
		void const*,
		int /* scale */,
		int /* hint */);
	extern void __ICL_INTRINCC _mm512_prefetch_i64scatter_pd(void*, __m512i,
		int /* scale */,
		int /* pf hint */);

	extern void __ICL_INTRINCC _mm512_mask_prefetch_i64scatter_pd(void*, __mmask8,
		__m512i,
		int /* scale */,
		int /* hint */);

	/*
	* Intel(R) AVX-512 Doubleword and Quadword Instructions,
	* Intel(R) AVX-512 Byte and Word Instructions and
	* Intel(R) AVX-512 Vector Length eXtensions.
	*/

	extern __m128i __ICL_INTRINCC _mm_mask_load_epi32(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_load_epi32(__mmask8, void const*);

	extern __m128i __ICL_INTRINCC _mm_mask_load_epi64(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_load_epi64(__mmask8, void const*);

	extern __m128d __ICL_INTRINCC _mm_mask_load_pd(__m128d, __mmask8, void const*);
	extern __m128d __ICL_INTRINCC _mm_maskz_load_pd(__mmask8, void const*);

	extern __m128  __ICL_INTRINCC _mm_mask_load_ps(__m128, __mmask8, void const*);
	extern __m128  __ICL_INTRINCC _mm_maskz_load_ps(__mmask8, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_load_epi32(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_load_epi32(__mmask8, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_load_epi64(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_load_epi64(__mmask8, void const*);

	extern __m256d __ICL_INTRINCC _mm256_mask_load_pd(__m256d, __mmask8,
		void const*);
	extern __m256d __ICL_INTRINCC _mm256_maskz_load_pd(__mmask8, void const*);

	extern __m256  __ICL_INTRINCC _mm256_mask_load_ps(__m256, __mmask8,
		void const*);
	extern __m256  __ICL_INTRINCC _mm256_maskz_load_ps(__mmask8, void const*);

	extern __m128i __ICL_INTRINCC _mm_mask_loadu_epi8(__m128i, __mmask16,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_loadu_epi8(__mmask16, void const*);

	extern __m128i __ICL_INTRINCC _mm_mask_loadu_epi16(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_loadu_epi16(__mmask8, void const*);

	extern __m128i __ICL_INTRINCC _mm_mask_loadu_epi32(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_loadu_epi32(__mmask8, void const*);

	extern __m128i __ICL_INTRINCC _mm_mask_loadu_epi64(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_loadu_epi64(__mmask8, void const*);

	extern __m128d __ICL_INTRINCC _mm_mask_loadu_pd(__m128d, __mmask8,
		void const*);
	extern __m128d __ICL_INTRINCC _mm_maskz_loadu_pd(__mmask8, void const*);

	extern __m128  __ICL_INTRINCC _mm_mask_loadu_ps(__m128, __mmask8,
		void const*);
	extern __m128  __ICL_INTRINCC _mm_maskz_loadu_ps(__mmask8, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_loadu_epi8(__m256i, __mmask32,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_loadu_epi8(__mmask32, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_loadu_epi16(__m256i, __mmask16,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_loadu_epi16(__mmask16, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_loadu_epi32(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_loadu_epi32(__mmask8, void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_loadu_epi64(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_loadu_epi64(__mmask8, void const*);

	extern __m256d __ICL_INTRINCC _mm256_mask_loadu_pd(__m256d, __mmask8,
		void const*);
	extern __m256d __ICL_INTRINCC _mm256_maskz_loadu_pd(__mmask8, void const*);

	extern __m256  __ICL_INTRINCC _mm256_mask_loadu_ps(__m256, __mmask8,
		void const*);
	extern __m256  __ICL_INTRINCC _mm256_maskz_loadu_ps(__mmask8, void const*);

	extern __m512i __ICL_INTRINCC _mm512_mask_loadu_epi8(__m512i, __mmask64,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_loadu_epi8(__mmask64, void const*);

	extern __m512i __ICL_INTRINCC _mm512_mask_loadu_epi16(__m512i, __mmask32,
		void const*);
	extern __m512i __ICL_INTRINCC _mm512_maskz_loadu_epi16(__mmask32, void const*);

	extern void __ICL_INTRINCC _mm_mask_store_epi32(void*, __mmask8, __m128i);
	extern void __ICL_INTRINCC _mm_mask_store_epi64(void*, __mmask8, __m128i);
	extern void __ICL_INTRINCC _mm_mask_store_ps(void*, __mmask8, __m128);
	extern void __ICL_INTRINCC _mm_mask_store_pd(void*, __mmask8, __m128d);

	extern void __ICL_INTRINCC _mm256_mask_store_epi32(void*, __mmask8, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_store_epi64(void*, __mmask8, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_store_ps(void*, __mmask8, __m256);
	extern void __ICL_INTRINCC _mm256_mask_store_pd(void*, __mmask8, __m256d);

	extern void __ICL_INTRINCC _mm_mask_storeu_epi8(void*, __mmask16, __m128i);
	extern void __ICL_INTRINCC _mm_mask_storeu_epi16(void*, __mmask8, __m128i);
	extern void __ICL_INTRINCC _mm_mask_storeu_epi32(void*, __mmask8, __m128i);
	extern void __ICL_INTRINCC _mm_mask_storeu_epi64(void*, __mmask8, __m128i);
	extern void __ICL_INTRINCC _mm_mask_storeu_pd(void*, __mmask8, __m128d);
	extern void __ICL_INTRINCC _mm_mask_storeu_ps(void*, __mmask8, __m128);

	extern void __ICL_INTRINCC _mm256_mask_storeu_epi8(void*, __mmask32, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_storeu_epi16(void*, __mmask16, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_storeu_epi32(void*, __mmask8, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_storeu_epi64(void*, __mmask8, __m256i);
	extern void __ICL_INTRINCC _mm256_mask_storeu_pd(void*, __mmask8, __m256d);
	extern void __ICL_INTRINCC _mm256_mask_storeu_ps(void*, __mmask8, __m256);

	extern void __ICL_INTRINCC _mm512_mask_storeu_epi8(void*, __mmask64, __m512i);
	extern void __ICL_INTRINCC _mm512_mask_storeu_epi16(void*, __mmask32, __m512i);

	extern __m256d  __ICL_INTRINCC _mm256_mask_broadcastsd_pd(__m256d,
		__mmask8, __m128d);
	extern __m256d  __ICL_INTRINCC _mm256_maskz_broadcastsd_pd(__mmask8, __m128d);

	extern __m256  __ICL_INTRINCC _mm256_mask_broadcastss_ps(__m256,
		__mmask8, __m128);
	extern __m256  __ICL_INTRINCC _mm256_maskz_broadcastss_ps(__mmask8, __m128);

	extern __m128  __ICL_INTRINCC _mm_mask_broadcastss_ps(__m128,
		__mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_broadcastss_ps(__mmask8, __m128);

	extern __m512  __ICL_INTRINCC _mm512_broadcast_f32x2(__m128);
	extern __m512  __ICL_INTRINCC _mm512_mask_broadcast_f32x2(__m512, __mmask16,
		__m128);
	extern __m512  __ICL_INTRINCC _mm512_maskz_broadcast_f32x2(__mmask16, __m128);

	extern __m256  __ICL_INTRINCC _mm256_broadcast_f32x2(__m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_broadcast_f32x2(__m256, __mmask8,
		__m128);
	extern __m256  __ICL_INTRINCC _mm256_maskz_broadcast_f32x2(__mmask8, __m128);

	extern __m512i  __ICL_INTRINCC _mm512_broadcast_i32x2(__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_broadcast_i32x2(__m512i, __mmask16,
		__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_broadcast_i32x2(__mmask16,
		__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_broadcast_i32x2(__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_mask_broadcast_i32x2(__m256i, __mmask8,
		__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_broadcast_i32x2(__mmask8, __m128i);
	extern __m128i  __ICL_INTRINCC _mm_broadcast_i32x2(__m128i);
	extern __m128i  __ICL_INTRINCC _mm_mask_broadcast_i32x2(__m128i, __mmask8,
		__m128i);
	extern __m128i  __ICL_INTRINCC _mm_maskz_broadcast_i32x2(__mmask8, __m128i);

	extern __m256  __ICL_INTRINCC _mm256_broadcast_f32x4(__m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_broadcast_f32x4(__m256,
		__mmask8,
		__m128);
	extern __m256  __ICL_INTRINCC _mm256_maskz_broadcast_f32x4(__mmask8,
		__m128);
	extern __m256i  __ICL_INTRINCC _mm256_broadcast_i32x4(__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_mask_broadcast_i32x4(__m256i,
		__mmask8,
		__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_broadcast_i32x4(__mmask8,
		__m128i);

	extern __m512  __ICL_INTRINCC _mm512_broadcast_f32x8(__m256);
	extern __m512  __ICL_INTRINCC _mm512_mask_broadcast_f32x8(__m512,
		__mmask16,
		__m256);
	extern __m512  __ICL_INTRINCC _mm512_maskz_broadcast_f32x8(__mmask16,
		__m256);

	extern __m512i  __ICL_INTRINCC _mm512_broadcast_i32x8(__m256i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_broadcast_i32x8(__m512i,
		__mmask16,
		__m256i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_broadcast_i32x8(__mmask16,
		__m256i);

	extern __m512d  __ICL_INTRINCC _mm512_broadcast_f64x2(__m128d);
	extern __m512d  __ICL_INTRINCC _mm512_mask_broadcast_f64x2(__m512d,
		__mmask8,
		__m128d);
	extern __m512d  __ICL_INTRINCC _mm512_maskz_broadcast_f64x2(__mmask8,
		__m128d);

	extern __m512i  __ICL_INTRINCC _mm512_broadcast_i64x2(__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_broadcast_i64x2(__m512i,
		__mmask8,
		__m128i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_broadcast_i64x2(__mmask8,
		__m128i);

	extern __m256d  __ICL_INTRINCC _mm256_broadcast_f64x2(__m128d);
	extern __m256d  __ICL_INTRINCC _mm256_mask_broadcast_f64x2(__m256d,
		__mmask8,
		__m128d);
	extern __m256d  __ICL_INTRINCC _mm256_maskz_broadcast_f64x2(__mmask8,
		__m128d);

	extern __m256i  __ICL_INTRINCC _mm256_broadcast_i64x2(__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_mask_broadcast_i64x2(__m256i,
		__mmask8,
		__m128i);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_broadcast_i64x2(__mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_broadcastb_epi8(__m128i, __mmask16,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_broadcastb_epi8(__mmask16, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_broadcastb_epi8(__m256i, __mmask32,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_broadcastb_epi8(__mmask32, __m128i);

	extern __m512i __ICL_INTRINCC _mm512_broadcastb_epi8(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_broadcastb_epi8(__m512i, __mmask64,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_broadcastb_epi8(__mmask64, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_broadcastd_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_broadcastd_epi32(__mmask8, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_broadcastd_epi32(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_broadcastd_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_broadcastq_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_broadcastq_epi64(__mmask8, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_broadcastq_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_broadcastq_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_broadcastw_epi16(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_broadcastw_epi16(__mmask8, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_broadcastw_epi16(__m256i, __mmask16,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_broadcastw_epi16(__mmask16, __m128i);

	extern __m512i __ICL_INTRINCC _mm512_broadcastw_epi16(__m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_broadcastw_epi16(__m512i, __mmask32,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_broadcastw_epi16(__mmask32,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_broadcastmb_epi64(__mmask8);
	extern __m128i __ICL_INTRINCC _mm_broadcastmw_epi32(__mmask16);
	extern __m256i __ICL_INTRINCC _mm256_broadcastmb_epi64(__mmask8);
	extern __m256i __ICL_INTRINCC _mm256_broadcastmw_epi32(__mmask16);

	extern __m128i __ICL_INTRINCC _mm_mask_abs_epi8(__m128i, __mmask16, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_abs_epi8(__mmask16, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_abs_epi8(__m256i, __mmask32,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_abs_epi8(__mmask32, __m256i);

	extern __m512i __ICL_INTRINCC _mm512_abs_epi8(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_abs_epi8(__m512i, __mmask64,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_abs_epi8(__mmask64, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_abs_epi16(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_abs_epi16(__mmask8, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_abs_epi16(__m256i, __mmask16,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_abs_epi16(__mmask16, __m256i);

	extern __m512i __ICL_INTRINCC _mm512_abs_epi16(__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_abs_epi16(__m512i, __mmask32,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_abs_epi16(__mmask32, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_abs_epi32(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_abs_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_abs_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_abs_epi32(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm_abs_epi64(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_abs_epi64(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_abs_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_abs_epi64(__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_abs_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_abs_epi64(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_add_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_add_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_add_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_add_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_add_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_add_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_add_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_add_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_add_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_add_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_add_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_add_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_add_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_add_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_add_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_add_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_add_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_add_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_add_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_add_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_add_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_add_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_add_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_add_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_add_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_add_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_add_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_add_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_add_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_add_ps(__mmask8, __m256, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_adds_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_adds_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_adds_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_adds_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_adds_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_adds_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_adds_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_adds_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_adds_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_adds_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_adds_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_adds_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_adds_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_adds_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_adds_epu8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_adds_epu8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_adds_epu8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_adds_epu8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_adds_epu8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_adds_epu8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_adds_epu8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_adds_epu16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_adds_epu16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_adds_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_adds_epu16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_adds_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_adds_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_adds_epu16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_alignr_epi8(__m128i, __mmask16,
		__m128i, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_alignr_epi8(__mmask16, __m128i,
		__m128i, const int);

	extern __m256i __ICL_INTRINCC _mm256_mask_alignr_epi8(__m256i, __mmask32,
		__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_alignr_epi8(__mmask32, __m256i,
		__m256i, const int);


	extern __m512i __ICL_INTRINCC _mm512_alignr_epi8(__m512i, __m512i, const int);
	extern __m512i __ICL_INTRINCC _mm512_mask_alignr_epi8(__m512i, __mmask64,
		__m512i, __m512i,
		const int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_alignr_epi8(__mmask64, __m512i,
		__m512i, const int);
	extern __m128i __ICL_INTRINCC _mm_alignr_epi32(__m128i, __m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_mask_alignr_epi32(__m128i, __mmask8,
		__m128i, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_alignr_epi32(__mmask8, __m128i,
		__m128i, const int);

	extern __m256i __ICL_INTRINCC _mm256_alignr_epi32(__m256i, __m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_alignr_epi32(__m256i, __mmask8,
		__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_alignr_epi32(__mmask8, __m256i,
		__m256i, const int);

	extern __m128i __ICL_INTRINCC _mm_alignr_epi64(__m128i, __m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_mask_alignr_epi64(__m128i, __mmask8,
		__m128i, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_alignr_epi64(__mmask8, __m128i,
		__m128i, const int);

	extern __m256i __ICL_INTRINCC _mm256_alignr_epi64(__m256i, __m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_alignr_epi64(__m256i, __mmask8,
		__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_alignr_epi64(__mmask8, __m256i,
		__m256i, const int);


	extern __m128i __ICL_INTRINCC _mm_mask_and_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_and_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_and_epi32(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_and_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_and_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_and_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_and_epi64(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_and_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_and_pd(__m128d, __mmask8, __m128d,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_and_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_and_pd(__m256d, __mmask8, __m256d,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_and_pd(__mmask8, __m256d, __m256d);
	extern __m512d __ICL_INTRINCC _mm512_and_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_and_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_and_pd(__mmask8, __m512d, __m512d);
	extern __m128  __ICL_INTRINCC _mm_mask_and_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_and_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_and_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_and_ps(__mmask8, __m256, __m256);
	extern __m512  __ICL_INTRINCC _mm512_and_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_and_ps(__m512, __mmask16,
		__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_and_ps(__mmask16, __m512, __m512);

	extern __m128i __ICL_INTRINCC _mm_mask_andnot_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_andnot_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_andnot_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_andnot_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_andnot_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_andnot_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_andnot_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_andnot_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_andnot_pd(__m128d, __mmask8, __m128d,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_andnot_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_andnot_pd(__m256d, __mmask8, __m256d,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_andnot_pd(__mmask8, __m256d,
		__m256d);
	extern __m512d __ICL_INTRINCC _mm512_andnot_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_andnot_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_andnot_pd(__mmask8, __m512d,
		__m512d);
	extern __m128  __ICL_INTRINCC _mm_mask_andnot_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_andnot_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_andnot_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_andnot_ps(__mmask8, __m256, __m256);
	extern __m512  __ICL_INTRINCC _mm512_andnot_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_andnot_ps(__m512, __mmask16,
		__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_andnot_ps(__mmask16, __m512,
		__m512);
	extern __m128i __ICL_INTRINCC _mm_mask_avg_epu8(__m128i, __mmask16, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_avg_epu8(__mmask16, __m128i, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_avg_epu8(__m256i, __mmask32, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_avg_epu8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_avg_epu8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_avg_epu8(__m512i, __mmask64, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_avg_epu8(__mmask64, __m512i,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm_mask_avg_epu16(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_avg_epu16(__mmask8, __m128i, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_avg_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_avg_epu16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_avg_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_avg_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_avg_epu16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_blend_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_blend_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_blend_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_blend_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_blend_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_blend_epi16(__mmask32, __m512i,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm_mask_blend_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_blend_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_blend_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_blend_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_blend_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_blend_pd(__mmask8, __m256d, __m256d);

	extern __m128 __ICL_INTRINCC _mm_mask_blend_ps(__mmask8, __m128, __m128);
	extern __m256 __ICL_INTRINCC _mm256_mask_blend_ps(__mmask8, __m256, __m256);

	extern __mmask8 __ICL_INTRINCC _mm_cmp_pd_mask(__m128d, __m128d, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_pd_mask(__mmask8, __m128d, __m128d,
		const int);
	extern __mmask8 __ICL_INTRINCC _mm_cmp_ps_mask(__m128, __m128, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_ps_mask(__mmask8, __m128, __m128,
		const int);

	extern __mmask8 __ICL_INTRINCC _mm256_cmp_pd_mask(__m256d, __m256d, const int);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_pd_mask(__mmask8, __m256d,
		__m256d, const int);
	extern __mmask8 __ICL_INTRINCC _mm256_cmp_ps_mask(__m256, __m256, const int);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_ps_mask(__mmask8, __m256,
		__m256, const int);

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epi32_mask(__m128i, __m128i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epi32_mask(__mmask8, __m128i,
		__m128i,
		const _MM_CMPINT_ENUM);

#define _mm_cmpeq_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epi32_mask(v1, v2) \
        _mm_cmp_epi32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epi32_mask(k1, v1, v2) \
        _mm_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm256_cmp_epi32_mask(__m256i, __m256i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_epi32_mask(__mmask8, __m256i,
		__m256i,
		const _MM_CMPINT_ENUM);

#define _mm256_cmpeq_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epi32_mask(v1, v2) \
        _mm256_cmp_epi32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epi32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi32_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epu32_mask(__m128i, __m128i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epu32_mask(__mmask8, __m128i,
		__m128i,
		const _MM_CMPINT_ENUM);

#define _mm_cmpeq_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epu32_mask(v1, v2) \
        _mm_cmp_epu32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epu32_mask(k1, v1, v2) \
        _mm_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm256_cmp_epu32_mask(__m256i, __m256i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_epu32_mask(__mmask8, __m256i,
		__m256i,
		const _MM_CMPINT_ENUM);

#define _mm256_cmpeq_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epu32_mask(v1, v2) \
        _mm256_cmp_epu32_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epu32_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu32_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epi64_mask(__m128i, __m128i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epi64_mask(__mmask8, __m128i,
		__m128i,
		const _MM_CMPINT_ENUM);

#define _mm_cmpeq_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epi64_mask(v1, v2) \
        _mm_cmp_epi64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epi64_mask(k1, v1, v2) \
        _mm_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm256_cmp_epi64_mask(__m256i, __m256i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_epi64_mask(__mmask8, __m256i,
		__m256i,
		const _MM_CMPINT_ENUM);

#define _mm256_cmpeq_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epi64_mask(v1, v2) \
        _mm256_cmp_epi64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epi64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epu64_mask(__m128i, __m128i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epu64_mask(__mmask8, __m128i,
		__m128i,
		const _MM_CMPINT_ENUM);

#define _mm_cmpeq_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epu64_mask(v1, v2) \
        _mm_cmp_epu64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epu64_mask(k1, v1, v2) \
        _mm_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm256_cmp_epu64_mask(__m256i, __m256i,
		const _MM_CMPINT_ENUM);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_cmp_epu64_mask(__mmask8, __m256i,
		__m256i,
		const _MM_CMPINT_ENUM);

	extern __m128i __ICL_INTRINCC _mm_mask_compress_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_compress_epi32(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_compress_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_compress_epi64(__mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_mask_compress_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_compress_pd(__mmask8, __m128d);
	extern __m128  __ICL_INTRINCC _mm_mask_compress_ps(__m128, __mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_compress_ps(__mmask8, __m128);

	extern void    __ICL_INTRINCC _mm_mask_compressstoreu_epi32(void*, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_compressstoreu_epi64(void*, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_compressstoreu_pd(void*, __mmask8,
		__m128d);
	extern void    __ICL_INTRINCC _mm_mask_compressstoreu_ps(void*, __mmask8,
		__m128);

	extern __m256i __ICL_INTRINCC _mm256_mask_compress_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_compress_epi32(__mmask8, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_compress_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_compress_epi64(__mmask8, __m256i);
	extern __m256d __ICL_INTRINCC _mm256_mask_compress_pd(__m256d, __mmask8,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_compress_pd(__mmask8, __m256d);
	extern __m256  __ICL_INTRINCC _mm256_mask_compress_ps(__m256, __mmask8,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_compress_ps(__mmask8, __m256);

	extern void    __ICL_INTRINCC _mm256_mask_compressstoreu_epi32(void*, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_compressstoreu_epi64(void*, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_compressstoreu_pd(void*, __mmask8,
		__m256d);
	extern void    __ICL_INTRINCC _mm256_mask_compressstoreu_ps(void*, __mmask8,
		__m256);

#define _mm256_cmpeq_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epu64_mask(v1, v2) \
        _mm256_cmp_epu64_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epu64_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu64_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask16 __ICL_INTRINCC _mm_cmp_epi8_mask(__m128i, __m128i, const int);
	extern __mmask16 __ICL_INTRINCC _mm_mask_cmp_epi8_mask(__mmask16, __m128i,
		__m128i, const int);

#define _mm_cmpeq_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epi8_mask(v1, v2) \
        _mm_cmp_epi8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epi8_mask(k1, v1, v2) \
        _mm_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask32 __ICL_INTRINCC _mm256_cmp_epi8_mask(__m256i, __m256i,
		const int);
	extern __mmask32 __ICL_INTRINCC _mm256_mask_cmp_epi8_mask(__mmask32, __m256i,
		__m256i, const int);

#define _mm256_cmpeq_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epi8_mask(v1, v2) \
        _mm256_cmp_epi8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epi8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask64 __ICL_INTRINCC _mm512_cmp_epi8_mask(__m512i, __m512i,
		const int);
	extern __mmask64 __ICL_INTRINCC _mm512_mask_cmp_epi8_mask(__mmask64, __m512i,
		__m512i, const int);

#define _mm512_cmpeq_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epi8_mask(v1, v2) \
        _mm512_cmp_epi8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epi8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask16 __ICL_INTRINCC _mm_cmp_epu8_mask(__m128i, __m128i, const int);
	extern __mmask16 __ICL_INTRINCC _mm_mask_cmp_epu8_mask(__mmask16, __m128i,
		__m128i, const int);

#define _mm_cmpeq_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epu8_mask(v1, v2) \
        _mm_cmp_epu8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epu8_mask(k1, v1, v2) \
        _mm_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask32 __ICL_INTRINCC _mm256_cmp_epu8_mask(__m256i, __m256i,
		const int);
	extern __mmask32 __ICL_INTRINCC _mm256_mask_cmp_epu8_mask(__mmask32, __m256i,
		__m256i, const int);

#define _mm256_cmpeq_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epu8_mask(v1, v2) \
        _mm256_cmp_epu8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epu8_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask64 __ICL_INTRINCC _mm512_cmp_epu8_mask(__m512i, __m512i,
		const int);
	extern __mmask64 __ICL_INTRINCC _mm512_mask_cmp_epu8_mask(__mmask64, __m512i,
		__m512i, const int);

#define _mm512_cmpeq_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epu8_mask(v1, v2) \
        _mm512_cmp_epu8_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epu8_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu8_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epi16_mask(__m128i, __m128i, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epi16_mask(__mmask8, __m128i,
		__m128i, const int);

#define _mm_cmpeq_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epi16_mask(v1, v2) \
        _mm_cmp_epi16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epi16_mask(k1, v1, v2) \
        _mm_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask16 __ICL_INTRINCC _mm256_cmp_epi16_mask(__m256i, __m256i,
		const int);
	extern __mmask16 __ICL_INTRINCC _mm256_mask_cmp_epi16_mask(__mmask16, __m256i,
		__m256i, const int);

#define _mm256_cmpeq_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epi16_mask(v1, v2) \
        _mm256_cmp_epi16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epi16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask32 __ICL_INTRINCC _mm512_cmp_epi16_mask(__m512i, __m512i,
		const int);
	extern __mmask32 __ICL_INTRINCC _mm512_mask_cmp_epi16_mask(__mmask32, __m512i,
		__m512i, const int);

#define _mm512_cmpeq_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epi16_mask(v1, v2) \
        _mm512_cmp_epi16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epi16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epi16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask8 __ICL_INTRINCC _mm_cmp_epu16_mask(__m128i, __m128i, const int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_cmp_epu16_mask(__mmask8, __m128i,
		__m128i, const int);

#define _mm_cmpeq_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm_mask_cmpeq_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm_cmplt_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm_mask_cmplt_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm_cmple_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm_mask_cmple_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm_cmpgt_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm_mask_cmpgt_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm_cmpge_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm_mask_cmpge_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm_cmpneq_epu16_mask(v1, v2) \
        _mm_cmp_epu16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm_mask_cmpneq_epu16_mask(k1, v1, v2) \
        _mm_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask16 __ICL_INTRINCC _mm256_cmp_epu16_mask(__m256i, __m256i,
		const int);
	extern __mmask16 __ICL_INTRINCC _mm256_mask_cmp_epu16_mask(__mmask16, __m256i,
		__m256i, const int);

#define _mm256_cmpeq_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm256_mask_cmpeq_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm256_cmplt_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm256_mask_cmplt_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm256_cmple_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm256_mask_cmple_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm256_cmpgt_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm256_mask_cmpgt_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm256_cmpge_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm256_mask_cmpge_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm256_cmpneq_epu16_mask(v1, v2) \
        _mm256_cmp_epu16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm256_mask_cmpneq_epu16_mask(k1, v1, v2) \
        _mm256_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __mmask32 __ICL_INTRINCC _mm512_cmp_epu16_mask(__m512i, __m512i,
		const int);
	extern __mmask32 __ICL_INTRINCC _mm512_mask_cmp_epu16_mask(__mmask32, __m512i,
		__m512i, const int);

#define _mm512_cmpeq_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_EQ)
#define _mm512_mask_cmpeq_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_EQ)
#define _mm512_cmplt_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LT)
#define _mm512_mask_cmplt_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LT)
#define _mm512_cmple_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_LE)
#define _mm512_mask_cmple_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_LE)
#define _mm512_cmpgt_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GT)
#define _mm512_mask_cmpgt_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GT)
#define _mm512_cmpge_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_GE)
#define _mm512_mask_cmpge_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_GE)
#define _mm512_cmpneq_epu16_mask(v1, v2) \
        _mm512_cmp_epu16_mask((v1), (v2), _MM_CMPINT_NE)
#define _mm512_mask_cmpneq_epu16_mask(k1, v1, v2) \
        _mm512_mask_cmp_epu16_mask((k1), (v1), (v2), _MM_CMPINT_NE)

	extern __m128i __ICL_INTRINCC _mm_conflict_epi32(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_conflict_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_conflict_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_conflict_epi32(__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_conflict_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_conflict_epi32(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm_conflict_epi64(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_conflict_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_conflict_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_conflict_epi64(__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_conflict_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_conflict_epi64(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi8_epi16(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi8_epi16(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi8_epi16(__m256i, __mmask16,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi8_epi16(__mmask16, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepi8_epi16(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepi8_epi16(__m512i, __mmask32,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepi8_epi16(__mmask32, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi8_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi8_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi8_epi32(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi8_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi8_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi8_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi8_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi8_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu8_epi16(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu8_epi16(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu8_epi16(__m256i, __mmask16,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu8_epi16(__mmask16, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_cvtepu8_epi16(__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtepu8_epi16(__m512i, __mmask32,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtepu8_epi16(__mmask32, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu8_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu8_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu8_epi32(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu8_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu8_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu8_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu8_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu8_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_cvtepi16_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi16_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi16_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi16_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi16_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi16_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi16_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi16_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi16_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi16_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi16_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi16_epi8(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_cvtepi32_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi32_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi32_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi32_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi32_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi32_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi32_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi32_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi32_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi32_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi32_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi32_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtepi32_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi32_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi32_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi32_epi16(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi32_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi32_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi32_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi32_epi16(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi32_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi32_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi32_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi32_epi16(__mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_mask_cvtepi32_pd(__m128d, __mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_maskz_cvtepi32_pd(__mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm_mask_cvtepi32_ps(__m128, __mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm_maskz_cvtepi32_ps(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_cvtepi64_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi64_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi64_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi64_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi64_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi64_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi64_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi64_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi64_epi8(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi64_epi8(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi64_storeu_epi8(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi64_epi8(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtepi64_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi64_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi64_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi64_epi16(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi64_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi64_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi64_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi64_epi16(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi64_epi16(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi64_epi16(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi64_storeu_epi16(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi64_epi16(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtepi64_epi32(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi64_epi32(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtepi64_storeu_epi32(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi64_epi32(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtsepi64_epi32(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtsepi64_epi32(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtsepi64_storeu_epi32(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtsepi64_epi32(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_cvtusepi64_epi32(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtusepi64_epi32(__m128i, __mmask8,
		__m128i);
	extern void    __ICL_INTRINCC _mm_mask_cvtusepi64_storeu_epi32(void*, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtusepi64_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm256_cvtepi16_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi16_epi8(__m128i, __mmask16,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi16_storeu_epi8(void*,
		__mmask16,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi16_epi8(__mmask16, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi16_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi16_epi8(__m128i, __mmask16,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi16_storeu_epi8(void*,
		__mmask16,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi16_epi8(__mmask16, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi16_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi16_epi8(__m128i, __mmask16,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi16_storeu_epi8(void*,
		__mmask16,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi16_epi8(__mmask16, __m256i);

	extern __m128i __ICL_INTRINCC _mm256_cvtepi32_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi32_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi32_storeu_epi8(void*, __mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi32_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi32_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi32_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi32_storeu_epi8(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi32_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi32_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi32_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi32_storeu_epi8(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi32_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtepi32_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi32_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi32_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi32_epi16(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi32_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi32_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi32_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi32_epi16(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi32_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi32_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi32_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi32_epi16(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm256_cvtepi64_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi64_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi64_storeu_epi8(void*, __mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi64_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi64_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi64_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi64_storeu_epi8(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi64_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi64_epi8(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi64_epi8(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi64_storeu_epi8(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi64_epi8(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtepi64_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi64_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi64_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi64_epi16(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi64_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi64_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi64_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi64_epi16(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi64_epi16(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi64_epi16(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi64_storeu_epi16(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi64_epi16(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtepi64_epi32(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtepi64_epi32(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtepi64_storeu_epi32(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtepi64_epi32(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtsepi64_epi32(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtsepi64_epi32(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtsepi64_storeu_epi32(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtsepi64_epi32(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm256_cvtusepi64_epi32(__m256i);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtusepi64_epi32(__m128i, __mmask8,
		__m256i);
	extern void    __ICL_INTRINCC _mm256_mask_cvtusepi64_storeu_epi32(void*,
		__mmask8,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtusepi64_epi32(__mmask8, __m256i);

	extern __m256i __ICL_INTRINCC _mm512_cvtepi16_epi8(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtepi16_epi8(__m256i, __mmask32,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtepi16_storeu_epi8(void*,
		__mmask32,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtepi16_epi8(__mmask32, __m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtsepi16_epi8(__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtsepi16_storeu_epi8(void*,
		__mmask32,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtsepi16_epi8(__m256i, __mmask32,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtsepi16_epi8(__mmask32, __m512i);
	extern __m256i __ICL_INTRINCC _mm512_cvtusepi16_epi8(__m512i);
	extern __m256i __ICL_INTRINCC _mm512_mask_cvtusepi16_epi8(__m256i, __mmask32,
		__m512i);
	extern void    __ICL_INTRINCC _mm512_mask_cvtusepi16_storeu_epi8(void*,
		__mmask32,
		__m512i);
	extern __m256i __ICL_INTRINCC _mm512_maskz_cvtusepi16_epi8(__mmask32, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi16_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi16_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi16_epi32(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi16_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi16_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi16_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi16_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi16_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu16_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu16_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu16_epi32(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu16_epi32(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu16_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu16_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu16_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu16_epi64(__mmask8, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepi32_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepi32_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepi32_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepi32_epi64(__mmask8, __m128i);

	extern __m256d __ICL_INTRINCC _mm256_mask_cvtepi32_pd(__m256d, __mmask8,
		__m128i);
	extern __m256d __ICL_INTRINCC _mm256_maskz_cvtepi32_pd(__mmask8, __m128i);
	extern __m256  __ICL_INTRINCC _mm256_mask_cvtepi32_ps(__m256, __mmask8,
		__m256i);
	extern __m256  __ICL_INTRINCC _mm256_maskz_cvtepi32_ps(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtepu32_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtepu32_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtepu32_epi64(__m256i, __mmask8,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtepu32_epi64(__mmask8, __m128i);

	extern __m128d __ICL_INTRINCC _mm_cvtepu32_pd(__m128i);
	extern __m128d __ICL_INTRINCC _mm_mask_cvtepu32_pd(__m128d, __mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_maskz_cvtepu32_pd(__mmask8, __m128i);
	extern __m256d __ICL_INTRINCC _mm256_cvtepu32_pd(__m128i);
	extern __m256d __ICL_INTRINCC _mm256_mask_cvtepu32_pd(__m256d, __mmask8,
		__m128i);
	extern __m256d __ICL_INTRINCC _mm256_maskz_cvtepu32_pd(__mmask8, __m128i);

	extern __m128d __ICL_INTRINCC _mm_cvtepi64_pd(__m128i);
	extern __m128d __ICL_INTRINCC _mm_mask_cvtepi64_pd(__m128d, __mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_maskz_cvtepi64_pd(__mmask8, __m128i);
	extern __m256d __ICL_INTRINCC _mm256_cvtepi64_pd(__m256i);
	extern __m256d __ICL_INTRINCC _mm256_mask_cvtepi64_pd(__m256d, __mmask8,
		__m256i);
	extern __m256d __ICL_INTRINCC _mm256_maskz_cvtepi64_pd(__mmask8, __m256i);
	extern __m512d __ICL_INTRINCC _mm512_cvt_roundepi64_pd(__m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvt_roundepi64_pd(__m512d, __mmask8,
		__m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_cvt_roundepi64_pd(__mmask8, __m512i,
		int);
#define _mm512_cvtepi64_pd(v) \
        _mm512_cvt_roundepi64_pd((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepi64_pd(v1, k1, v2) \
        _mm512_mask_cvt_roundepi64_pd((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepi64_pd(k1, v2) \
        _mm512_maskz_cvt_roundepi64_pd((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_cvtepu64_pd(__m128i);
	extern __m128d __ICL_INTRINCC _mm_mask_cvtepu64_pd(__m128d, __mmask8, __m128i);
	extern __m128d __ICL_INTRINCC _mm_maskz_cvtepu64_pd(__mmask8, __m128i);
	extern __m256d __ICL_INTRINCC _mm256_cvtepu64_pd(__m256i);
	extern __m256d __ICL_INTRINCC _mm256_mask_cvtepu64_pd(__m256d, __mmask8,
		__m256i);
	extern __m256d __ICL_INTRINCC _mm256_maskz_cvtepu64_pd(__mmask8, __m256i);
	extern __m512d __ICL_INTRINCC _mm512_cvt_roundepu64_pd(__m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_cvt_roundepu64_pd(__m512d, __mmask8,
		__m512i, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_cvt_roundepu64_pd(__mmask8, __m512i,
		int);
#define _mm512_cvtepu64_pd(v) \
        _mm512_cvt_roundepu64_pd((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepu64_pd(v1, k1, v2) \
        _mm512_mask_cvt_roundepu64_pd((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepu64_pd(k1, v2) \
        _mm512_maskz_cvt_roundepu64_pd((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_mask_cvtpd_epi32(__m128i, __mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtpd_epi32(__mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtpd_epi32(__m128i, __mmask8,
		__m256d);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtpd_epi32(__mmask8, __m256d);

	extern __m128i __ICL_INTRINCC _mm_mask_cvttpd_epi32(__m128i, __mmask8,
		__m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttpd_epi32(__mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvttpd_epi32(__m128i, __mmask8,
		__m256d);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvttpd_epi32(__mmask8, __m256d);

	extern __m128i __ICL_INTRINCC _mm_cvtpd_epu32(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtpd_epu32(__m128i, __mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtpd_epu32(__mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm256_cvtpd_epu32(__m256d);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvtpd_epu32(__m128i, __mmask8,
		__m256d);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvtpd_epu32(__mmask8, __m256d);

	extern __m128i __ICL_INTRINCC _mm_cvttpd_epu32(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttpd_epu32(__m128i, __mmask8,
		__m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttpd_epu32(__mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm256_cvttpd_epu32(__m256d);
	extern __m128i __ICL_INTRINCC _mm256_mask_cvttpd_epu32(__m128i, __mmask8,
		__m256d);
	extern __m128i __ICL_INTRINCC _mm256_maskz_cvttpd_epu32(__mmask8, __m256d);

	extern __m128i __ICL_INTRINCC _mm_cvtpd_epi64(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtpd_epi64(__m128i, __mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtpd_epi64(__mmask8, __m128d);
	extern __m256i __ICL_INTRINCC _mm256_cvtpd_epi64(__m256d);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtpd_epi64(__m256i, __mmask8,
		__m256d);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtpd_epi64(__mmask8, __m256d);
	extern __m512i __ICL_INTRINCC _mm512_cvt_roundpd_epi64(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundpd_epi64(__m512i, __mmask8,
		__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundpd_epi64(__mmask8, __m512d,
		int);
#define _mm512_cvtpd_epi64(v) \
        _mm512_cvt_roundpd_epi64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_epi64(v1, k1, v2) \
        _mm512_mask_cvt_roundpd_epi64((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtpd_epi64(k1, v2) \
        _mm512_maskz_cvt_roundpd_epi64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvtpd_epu64(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtpd_epu64(__m128i, __mmask8, __m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtpd_epu64(__mmask8, __m128d);
	extern __m256i __ICL_INTRINCC _mm256_cvtpd_epu64(__m256d);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtpd_epu64(__m256i, __mmask8,
		__m256d);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtpd_epu64(__mmask8, __m256d);
	extern __m512i __ICL_INTRINCC _mm512_cvt_roundpd_epu64(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundpd_epu64(__m512i, __mmask8,
		__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundpd_epu64(__mmask8, __m512d,
		int);
#define _mm512_cvtpd_epu64(v) \
        _mm512_cvt_roundpd_epu64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtpd_epu64(v1, k1, v2) \
        _mm512_mask_cvt_roundpd_epu64((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtpd_epu64(k1, v2) \
        _mm512_maskz_cvt_roundpd_epu64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvttpd_epi64(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttpd_epi64(__m128i, __mmask8,
		__m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttpd_epi64(__mmask8, __m128d);
	extern __m256i __ICL_INTRINCC _mm256_cvttpd_epi64(__m256d);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttpd_epi64(__m256i, __mmask8,
		__m256d);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttpd_epi64(__mmask8, __m256d);
	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundpd_epi64(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundpd_epi64(__m512i, __mmask8,
		__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundpd_epi64(__mmask8,
		__m512d,
		int);
#define _mm512_cvttpd_epi64(v) \
        _mm512_cvtt_roundpd_epi64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttpd_epi64(v1, k1, v2) \
        _mm512_mask_cvtt_roundpd_epi64((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttpd_epi64(k1, v2) \
        _mm512_maskz_cvtt_roundpd_epi64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvttpd_epu64(__m128d);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttpd_epu64(__m128i, __mmask8,
		__m128d);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttpd_epu64(__mmask8, __m128d);
	extern __m256i __ICL_INTRINCC _mm256_cvttpd_epu64(__m256d);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttpd_epu64(__m256i, __mmask8,
		__m256d);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttpd_epu64(__mmask8, __m256d);
	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundpd_epu64(__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundpd_epu64(__m512i, __mmask8,
		__m512d, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundpd_epu64(__mmask8,
		__m512d,
		int);
#define _mm512_cvttpd_epu64(v) \
        _mm512_cvtt_roundpd_epu64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttpd_epu64(v1, k1, v2) \
        _mm512_mask_cvtt_roundpd_epu64((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttpd_epu64(k1, v2) \
        _mm512_maskz_cvtt_roundpd_epu64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm_mask_cvtpd_ps(__m128, __mmask8, __m128d);
	extern __m128  __ICL_INTRINCC _mm_maskz_cvtpd_ps(__mmask8, __m128d);
	extern __m128  __ICL_INTRINCC _mm256_mask_cvtpd_ps(__m128, __mmask8, __m256d);
	extern __m128  __ICL_INTRINCC _mm256_maskz_cvtpd_ps(__mmask8, __m256d);

	extern __m128i __ICL_INTRINCC _mm_mask_cvtps_epi32(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtps_epi32(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtps_epi32(__m256i, __mmask8,
		__m256);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtps_epi32(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_cvttps_epi32(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttps_epi32(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttps_epi32(__m256i, __mmask8,
		__m256);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttps_epi32(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_cvtps_epu32(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtps_epu32(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtps_epu32(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvtps_epu32(__m256);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtps_epu32(__m256i, __mmask8,
		__m256);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtps_epu32(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_cvttps_epu32(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttps_epu32(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttps_epu32(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvttps_epu32(__m256);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttps_epu32(__m256i, __mmask8,
		__m256);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttps_epu32(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_cvtps_epi64(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtps_epi64(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtps_epi64(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvtps_epi64(__m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtps_epi64(__m256i, __mmask8,
		__m128);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtps_epi64(__mmask8, __m128);
	extern __m512i __ICL_INTRINCC _mm512_cvt_roundps_epi64(__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundps_epi64(__m512i, __mmask8,
		__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundps_epi64(__mmask8,
		__m256, int);
#define _mm512_cvtps_epi64(v) \
        _mm512_cvt_roundps_epi64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtps_epi64(v1, k1, v2) \
        _mm512_mask_cvt_roundps_epi64((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtps_epi64(k1, v2) \
        _mm512_maskz_cvt_roundps_epi64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvtps_epu64(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvtps_epu64(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvtps_epu64(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvtps_epu64(__m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvtps_epu64(__m256i, __mmask8,
		__m128);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvtps_epu64(__mmask8, __m128);
	extern __m512i __ICL_INTRINCC _mm512_cvt_roundps_epu64(__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvt_roundps_epu64(__m512i, __mmask8,
		__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvt_roundps_epu64(__mmask8, __m256,
		int);
#define _mm512_cvtps_epu64(v) \
        _mm512_cvt_roundps_epu64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtps_epu64(v1, k1, v2) \
        _mm512_mask_cvt_roundps_epu64((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtps_epu64(k1, v2) \
        _mm512_maskz_cvt_roundps_epu64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm_cvtepi64_ps(__m128i);
	extern __m128  __ICL_INTRINCC _mm_mask_cvtepi64_ps(__m128, __mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm_maskz_cvtepi64_ps(__mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm256_cvtepi64_ps(__m256i);
	extern __m128  __ICL_INTRINCC _mm256_mask_cvtepi64_ps(__m128, __mmask8,
		__m256i);
	extern __m128  __ICL_INTRINCC _mm256_maskz_cvtepi64_ps(__mmask8, __m256i);
	extern __m256  __ICL_INTRINCC _mm512_cvt_roundepi64_ps(__m512i, int);
	extern __m256  __ICL_INTRINCC _mm512_mask_cvt_roundepi64_ps(__m256, __mmask8,
		__m512i, int);
	extern __m256  __ICL_INTRINCC _mm512_maskz_cvt_roundepi64_ps(__mmask8, __m512i,
		int);
#define _mm512_cvtepi64_ps(v) \
        _mm512_cvt_roundepi64_ps((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepi64_ps(v1, k1, v2) \
        _mm512_mask_cvt_roundepi64_ps((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepi64_ps(k1, v2) \
        _mm512_maskz_cvt_roundepi64_ps((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128  __ICL_INTRINCC _mm_cvtepu64_ps(__m128i);
	extern __m128  __ICL_INTRINCC _mm_mask_cvtepu64_ps(__m128, __mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm_maskz_cvtepu64_ps(__mmask8, __m128i);
	extern __m128  __ICL_INTRINCC _mm256_cvtepu64_ps(__m256i);
	extern __m128  __ICL_INTRINCC _mm256_mask_cvtepu64_ps(__m128, __mmask8,
		__m256i);
	extern __m128  __ICL_INTRINCC _mm256_maskz_cvtepu64_ps(__mmask8, __m256i);
	extern __m256  __ICL_INTRINCC _mm512_cvt_roundepu64_ps(__m512i, int);
	extern __m256  __ICL_INTRINCC _mm512_mask_cvt_roundepu64_ps(__m256, __mmask8,
		__m512i, int);
	extern __m256  __ICL_INTRINCC _mm512_maskz_cvt_roundepu64_ps(__mmask8, __m512i,
		int);
#define _mm512_cvtepu64_ps(v) \
        _mm512_cvt_roundepu64_ps((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvtepu64_ps(v1, k1, v2) \
        _mm512_mask_cvt_roundepu64_ps((v1), (k1), (v2), \
                                      _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvtepu64_ps(k1, v2) \
        _mm512_maskz_cvt_roundepu64_ps((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvttps_epi64(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttps_epi64(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttps_epi64(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvttps_epi64(__m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttps_epi64(__m256i, __mmask8,
		__m128);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttps_epi64(__mmask8, __m128);
	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundps_epi64(__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundps_epi64(__m512i,
		__mmask8,
		__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundps_epi64(__mmask8,
		__m256,
		int);
#define _mm512_cvttps_epi64(v) \
        _mm512_cvtt_roundps_epi64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttps_epi64(v1, k1, v2) \
        _mm512_mask_cvtt_roundps_epi64((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttps_epi64(k1, v2) \
        _mm512_maskz_cvtt_roundps_epi64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128i __ICL_INTRINCC _mm_cvttps_epu64(__m128);
	extern __m128i __ICL_INTRINCC _mm_mask_cvttps_epu64(__m128i, __mmask8, __m128);
	extern __m128i __ICL_INTRINCC _mm_maskz_cvttps_epu64(__mmask8, __m128);
	extern __m256i __ICL_INTRINCC _mm256_cvttps_epu64(__m128);
	extern __m256i __ICL_INTRINCC _mm256_mask_cvttps_epu64(__m256i, __mmask8,
		__m128);
	extern __m256i __ICL_INTRINCC _mm256_maskz_cvttps_epu64(__mmask8, __m128);
	extern __m512i __ICL_INTRINCC _mm512_cvtt_roundps_epu64(__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_cvtt_roundps_epu64(__m512i, __mmask8,
		__m256, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_cvtt_roundps_epu64(__mmask8, __m256,
		int);
#define _mm512_cvttps_epu64(v) \
        _mm512_cvtt_roundps_epu64((v), _MM_FROUND_CUR_DIRECTION)
#define _mm512_mask_cvttps_epu64(v1, k1, v2) \
        _mm512_mask_cvtt_roundps_epu64((v1), (k1), (v2), \
                                       _MM_FROUND_CUR_DIRECTION)
#define _mm512_maskz_cvttps_epu64(k1, v2) \
        _mm512_maskz_cvtt_roundps_epu64((k1), (v2), _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC     _mm_mask_cvtph_ps(__m128, __mmask8, __m128i);
	extern __m256 __ICL_INTRINCC  _mm256_mask_cvtph_ps(__m256, __mmask8, __m128i);

	extern __m128 __ICL_INTRINCC     _mm_maskz_cvtph_ps(__mmask8, __m128i);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_cvtph_ps(__mmask8, __m128i);

	extern __m128i  __ICL_INTRINCC     _mm_mask_cvt_roundps_ph(__m128i, __mmask8,
		__m128, int);
	extern __m128i  __ICL_INTRINCC  _mm256_mask_cvt_roundps_ph(__m128i, __mmask8,
		__m256, int);

	extern __m128i  __ICL_INTRINCC     _mm_maskz_cvt_roundps_ph(__mmask8, __m128,
		int);
	extern __m128i  __ICL_INTRINCC  _mm256_maskz_cvt_roundps_ph(__mmask8, __m256,
		int);
#define _mm_mask_cvtps_ph     _mm_mask_cvt_roundps_ph
#define _mm_maskz_cvtps_ph    _mm_maskz_cvt_roundps_ph
#define _mm256_mask_cvtps_ph  _mm256_mask_cvt_roundps_ph
#define _mm256_maskz_cvtps_ph _mm256_maskz_cvt_roundps_ph

	extern __m128i __ICL_INTRINCC _mm_dbsad_epu8(__m128i, __m128i, int);
	extern __m128i __ICL_INTRINCC _mm_mask_dbsad_epu8(__m128i, __mmask8,
		__m128i, __m128i, int);
	extern __m128i __ICL_INTRINCC _mm_maskz_dbsad_epu8(__mmask8,
		__m128i, __m128i, int);

	extern __m256i __ICL_INTRINCC _mm256_dbsad_epu8(__m256i, __m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_mask_dbsad_epu8(__m256i, __mmask16,
		__m256i, __m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_dbsad_epu8(__mmask16,
		__m256i, __m256i, int);

	extern __m128d __ICL_INTRINCC _mm_mask_div_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_div_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_div_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_div_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_div_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_div_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_div_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_div_ps(__mmask8, __m256, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_expand_epi32(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_expand_epi32(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_expandloadu_epi32(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_expandloadu_epi32(__mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_mask_expand_epi64(__m128i, __mmask8,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_expand_epi64(__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_expandloadu_epi64(__m128i, __mmask8,
		void const*);
	extern __m128i __ICL_INTRINCC _mm_maskz_expandloadu_epi64(__mmask8,
		void const*);
	extern __m128d __ICL_INTRINCC _mm_mask_expand_pd(__m128d, __mmask8,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_expand_pd(__mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_expandloadu_pd(__m128d, __mmask8,
		void const*);
	extern __m128d __ICL_INTRINCC _mm_maskz_expandloadu_pd(__mmask8,
		void const*);
	extern __m128  __ICL_INTRINCC _mm_mask_expand_ps(__m128, __mmask8,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_expand_ps(__mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_mask_expandloadu_ps(__m128, __mmask8,
		void const*);
	extern __m128  __ICL_INTRINCC _mm_maskz_expandloadu_ps(__mmask8,
		void const*);

	extern __m256i __ICL_INTRINCC _mm256_mask_expand_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_expand_epi32(__mmask8, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_expandloadu_epi32(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_expandloadu_epi32(__mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_mask_expand_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_expand_epi64(__mmask8, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_expandloadu_epi64(__m256i, __mmask8,
		void const*);
	extern __m256i __ICL_INTRINCC _mm256_maskz_expandloadu_epi64(__mmask8,
		void const*);
	extern __m256d __ICL_INTRINCC _mm256_mask_expand_pd(__m256d, __mmask8,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_expand_pd(__mmask8, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_mask_expandloadu_pd(__m256d, __mmask8,
		void const*);
	extern __m256d __ICL_INTRINCC _mm256_maskz_expandloadu_pd(__mmask8,
		void const*);
	extern __m256  __ICL_INTRINCC _mm256_mask_expand_ps(__m256, __mmask8,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_expand_ps(__mmask8, __m256);
	extern __m256  __ICL_INTRINCC _mm256_mask_expandloadu_ps(__m256, __mmask8,
		void const*);
	extern __m256  __ICL_INTRINCC _mm256_maskz_expandloadu_ps(__mmask8,
		void const*);

	extern __m128i __ICL_INTRINCC _mm256_extracti32x4_epi32(__m256i, int);
	extern __m128i __ICL_INTRINCC _mm256_mask_extracti32x4_epi32(__m128i, __mmask8,
		__m256i, int);
	extern __m128i __ICL_INTRINCC _mm256_maskz_extracti32x4_epi32(__mmask8,
		__m256i, int);
	extern __m128  __ICL_INTRINCC _mm256_extractf32x4_ps(__m256, int);
	extern __m128  __ICL_INTRINCC _mm256_mask_extractf32x4_ps(__m128, __mmask8,
		__m256, int);
	extern __m128  __ICL_INTRINCC _mm256_maskz_extractf32x4_ps(__mmask8,
		__m256, int);

	extern __m128i __ICL_INTRINCC _mm256_extracti64x2_epi64(__m256i, int);
	extern __m128i __ICL_INTRINCC _mm256_mask_extracti64x2_epi64(__m128i, __mmask8,
		__m256i, int);
	extern __m128i __ICL_INTRINCC _mm256_maskz_extracti64x2_epi64(__mmask8,
		__m256i, int);
	extern __m128d __ICL_INTRINCC _mm256_extractf64x2_pd(__m256d, int);
	extern __m128d __ICL_INTRINCC _mm256_mask_extractf64x2_pd(__m128d, __mmask8,
		__m256d, int);
	extern __m128d __ICL_INTRINCC _mm256_maskz_extractf64x2_pd(__mmask8,
		__m256d, int);

	extern __m256i __ICL_INTRINCC _mm512_extracti32x8_epi32(__m512i, int);
	extern __m256i __ICL_INTRINCC _mm512_mask_extracti32x8_epi32(__m256i, __mmask8,
		__m512i, int);
	extern __m256i __ICL_INTRINCC _mm512_maskz_extracti32x8_epi32(__mmask8,
		__m512i, int);
	extern __m128i __ICL_INTRINCC _mm512_extracti64x2_epi64(__m512i, int);
	extern __m128i __ICL_INTRINCC _mm512_mask_extracti64x2_epi64(__m128i, __mmask8,
		__m512i, int);
	extern __m128i __ICL_INTRINCC _mm512_maskz_extracti64x2_epi64(__mmask8,
		__m512i, int);
	extern __m256  __ICL_INTRINCC _mm512_extractf32x8_ps(__m512, int);
	extern __m256  __ICL_INTRINCC _mm512_mask_extractf32x8_ps(__m256, __mmask8,
		__m512, int);
	extern __m256  __ICL_INTRINCC _mm512_maskz_extractf32x8_ps(__mmask8,
		__m512, int);
	extern __m128d __ICL_INTRINCC _mm512_extractf64x2_pd(__m512d, int);
	extern __m128d __ICL_INTRINCC _mm512_mask_extractf64x2_pd(__m128d, __mmask8,
		__m512d, int);
	extern __m128d __ICL_INTRINCC _mm512_maskz_extractf64x2_pd(__mmask8,
		__m512d, int);
	extern __m256  __ICL_INTRINCC _mm256_insertf32x4(__m256, __m128, int);
	extern __m256  __ICL_INTRINCC _mm256_mask_insertf32x4(__m256, __mmask8,
		__m256, __m128, int);
	extern __m256  __ICL_INTRINCC _mm256_maskz_insertf32x4(__mmask8,
		__m256, __m128, int);

	extern __m128d __ICL_INTRINCC _mm_fixupimm_pd(__m128d, __m128d, __m128i, int);
	extern __m128d __ICL_INTRINCC _mm_mask_fixupimm_pd(__m128d, __mmask8, __m128d,
		__m128i, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_fixupimm_pd(__mmask8, __m128d, __m128d,
		__m128i, int);
	extern __m256d __ICL_INTRINCC _mm256_fixupimm_pd(__m256d, __m256d, __m256i,
		int);
	extern __m256d __ICL_INTRINCC _mm256_mask_fixupimm_pd(__m256d, __mmask8,
		__m256d, __m256i, int);

	extern __m256d __ICL_INTRINCC _mm256_maskz_fixupimm_pd(__mmask8, __m256d,
		__m256d, __m256i, int);
	extern __m128  __ICL_INTRINCC _mm_fixupimm_ps(__m128, __m128, __m128i, int);
	extern __m128  __ICL_INTRINCC _mm_mask_fixupimm_ps(__m128, __mmask8, __m128,
		__m128i, int);
	extern __m128  __ICL_INTRINCC _mm_maskz_fixupimm_ps(__mmask8, __m128, __m128,
		__m128i, int);
	extern __m256  __ICL_INTRINCC _mm256_fixupimm_ps(__m256, __m256, __m256i, int);
	extern __m256  __ICL_INTRINCC _mm256_mask_fixupimm_ps(__m256, __mmask8, __m256,
		__m256i, int);
	extern __m256  __ICL_INTRINCC _mm256_maskz_fixupimm_ps(__mmask8, __m256,
		__m256, __m256i, int);

	extern __mmask8 __ICL_INTRINCC _mm_fpclass_pd_mask(__m128d, int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_fpclass_pd_mask(__mmask8, __m128d,
		int);
	extern __mmask8 __ICL_INTRINCC _mm256_fpclass_pd_mask(__m256d, int);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_fpclass_pd_mask(__mmask8, __m256d,
		int);
	extern __mmask8 __ICL_INTRINCC _mm_fpclass_ps_mask(__m128, int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_fpclass_ps_mask(__mmask8, __m128, int);
	extern __mmask8 __ICL_INTRINCC _mm256_fpclass_ps_mask(__m256, int);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_fpclass_ps_mask(__mmask8, __m256,
		int);
	extern __mmask8 __ICL_INTRINCC _mm_fpclass_sd_mask(__m128d, int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_fpclass_sd_mask(__mmask8, __m128d,
		int);

	extern __mmask8 __ICL_INTRINCC _mm_fpclass_ss_mask(__m128, int);
	extern __mmask8 __ICL_INTRINCC _mm_mask_fpclass_ss_mask(__mmask8, __m128, int);

	extern __m128 __ICL_INTRINCC _mm_getmant_ps(__m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m128 __ICL_INTRINCC _mm_mask_getmant_ps(__m128, __mmask8,
		__m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m128 __ICL_INTRINCC _mm_maskz_getmant_ps(__mmask8, __m128,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	extern __m256 __ICL_INTRINCC _mm256_getmant_ps(__m256,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m256 __ICL_INTRINCC _mm256_mask_getmant_ps(__m256, __mmask8,
		__m256,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m256 __ICL_INTRINCC _mm256_maskz_getmant_ps(__mmask8, __m256,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	extern __m128d __ICL_INTRINCC _mm_getmant_pd(__m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m128d __ICL_INTRINCC _mm_mask_getmant_pd(__m128d, __mmask8,
		__m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m128d __ICL_INTRINCC _mm_maskz_getmant_pd(__mmask8, __m128d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	extern __m256d __ICL_INTRINCC _mm256_getmant_pd(__m256d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m256d __ICL_INTRINCC _mm256_mask_getmant_pd(__m256d, __mmask8,
		__m256d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);
	extern __m256d __ICL_INTRINCC _mm256_maskz_getmant_pd(__mmask8, __m256d,
		_MM_MANTISSA_NORM_ENUM,
		_MM_MANTISSA_SIGN_ENUM);

	extern __m256d  __ICL_INTRINCC _mm256_insertf64x2(__m256d, __m128d, int);
	extern __m256d  __ICL_INTRINCC _mm256_mask_insertf64x2(__m256d, __mmask8,
		__m256d, __m128d, int);
	extern __m256d  __ICL_INTRINCC _mm256_maskz_insertf64x2(__mmask8,
		__m256d, __m128d, int);

	extern __m512  __ICL_INTRINCC _mm512_insertf32x8(__m512, __m256, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_insertf32x8(__m512, __mmask16,
		__m512, __m256, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_insertf32x8(__mmask16,
		__m512, __m256, int);

	extern __m512d __ICL_INTRINCC _mm512_insertf64x2(__m512d, __m128d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_insertf64x2(__m512d, __mmask8,
		__m512d, __m128d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_insertf64x2(__mmask8,
		__m512d, __m128d, int);

	extern __m256i  __ICL_INTRINCC _mm256_inserti32x4(__m256i, __m128i, int);
	extern __m256i  __ICL_INTRINCC _mm256_mask_inserti32x4(__m256i, __mmask8,
		__m256i, __m128i, int);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_inserti32x4(__mmask8,
		__m256i, __m128i, int);

	extern __m256i  __ICL_INTRINCC _mm256_inserti64x2(__m256i, __m128i, int);
	extern __m256i  __ICL_INTRINCC _mm256_mask_inserti64x2(__m256i, __mmask8,
		__m256i, __m128i, int);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_inserti64x2(__mmask8,
		__m256i, __m128i, int);

	extern __m512i __ICL_INTRINCC _mm512_inserti32x8(__m512i, __m256i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_inserti32x8(__m512i, __mmask16,
		__m512i, __m256i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_inserti32x8(__mmask16,
		__m512i, __m256i, int);

	extern __m512i __ICL_INTRINCC _mm512_inserti64x2(__m512i, __m128i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_inserti64x2(__m512i, __mmask8,
		__m512i, __m128i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_inserti64x2(__mmask8,
		__m512i, __m128i, int);

	extern __mmask16 __ICL_INTRINCC _mm512_fpclass_ps_mask(__m512, int);
	extern __mmask16 __ICL_INTRINCC _mm512_mask_fpclass_ps_mask(__mmask16, __m512,
		int);
	extern __mmask8 __ICL_INTRINCC _mm512_fpclass_pd_mask(__m512d, int);
	extern __mmask8 __ICL_INTRINCC _mm512_mask_fpclass_pd_mask(__mmask8, __m512d,
		int);

	extern __m128d __ICL_INTRINCC _mm_getexp_pd(__m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_getexp_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_getexp_pd(__mmask8, __m128d);

	extern __m256d __ICL_INTRINCC _mm256_getexp_pd(__m256d);
	extern __m256d __ICL_INTRINCC _mm256_mask_getexp_pd(__m256d, __mmask8,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_getexp_pd(__mmask8, __m256d);

	extern __m128 __ICL_INTRINCC _mm_getexp_ps(__m128);
	extern __m128 __ICL_INTRINCC _mm_mask_getexp_ps(__m128, __mmask8, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_getexp_ps(__mmask8, __m128);

	extern __m256 __ICL_INTRINCC _mm256_getexp_ps(__m256);
	extern __m256 __ICL_INTRINCC _mm256_mask_getexp_ps(__m256, __mmask8, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_getexp_ps(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_lzcnt_epi32(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_lzcnt_epi32(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_lzcnt_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_lzcnt_epi32(__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_lzcnt_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_lzcnt_epi32(__mmask8, __m256i);
	extern __m128i __ICL_INTRINCC _mm_lzcnt_epi64(__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_lzcnt_epi64(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_lzcnt_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_lzcnt_epi64(__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_lzcnt_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_lzcnt_epi64(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_madd_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_madd_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_madd_epi16(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_madd_epi16(__mmask8,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_madd_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_madd_epi16(__m512i, __mmask16,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_madd_epi16(__mmask16,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_maddubs_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_maddubs_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_maddubs_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_maddubs_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_maddubs_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_maddubs_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_maddubs_epi16(__mmask32,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epi8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epi8(__mmask32,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_max_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_max_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_max_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_max_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_max_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_max_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_max_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epu8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epu8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epu8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epu8(__mmask32,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_max_epu8(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_max_epu8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_max_epu8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epu16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epu16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epu16(__mmask16,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_max_epu16(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_max_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_max_epu16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_max_epu32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epu32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epu32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epu32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_max_epu64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_max_epu64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_max_epu64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_max_epu64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_max_epu64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_max_epu64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_max_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_max_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_max_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_max_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_max_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_max_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_max_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_max_ps(__mmask8, __m256, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epi8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epi8(__mmask32,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_min_epi8(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_min_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_min_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_min_epi16(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_min_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_min_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_min_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_min_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_min_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epu8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epu8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epu8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epu8(__mmask32,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_min_epu8(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_min_epu8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_min_epu8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epu16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epu16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epu16(__mmask16,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_min_epu16(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_min_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_min_epu16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_min_epu32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epu32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epu32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epu32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_min_epu64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_min_epu64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_min_epu64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_min_epu64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_min_epu64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_min_epu64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_min_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_min_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_min_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_min_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_min_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_min_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_min_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_min_ps(__mmask8, __m256, __m256);

	extern __mmask16 __ICL_INTRINCC    _mm_movepi8_mask(__m128i);
	extern __mmask32 __ICL_INTRINCC _mm256_movepi8_mask(__m256i);
	extern __mmask64 __ICL_INTRINCC _mm512_movepi8_mask(__m512i);
	extern __mmask8  __ICL_INTRINCC    _mm_movepi16_mask(__m128i);
	extern __mmask16 __ICL_INTRINCC _mm256_movepi16_mask(__m256i);
	extern __mmask32 __ICL_INTRINCC _mm512_movepi16_mask(__m512i);
	extern __mmask8  __ICL_INTRINCC    _mm_movepi32_mask(__m128i);
	extern __mmask8  __ICL_INTRINCC _mm256_movepi32_mask(__m256i);
	extern __mmask16 __ICL_INTRINCC _mm512_movepi32_mask(__m512i);
	extern __mmask8  __ICL_INTRINCC    _mm_movepi64_mask(__m128i);
	extern __mmask8  __ICL_INTRINCC _mm256_movepi64_mask(__m256i);
	extern __mmask8  __ICL_INTRINCC _mm512_movepi64_mask(__m512i);

	extern __m128i   __ICL_INTRINCC    _mm_movm_epi8(__mmask16);
	extern __m256i   __ICL_INTRINCC _mm256_movm_epi8(__mmask32);
	extern __m512i   __ICL_INTRINCC _mm512_movm_epi8(__mmask64);
	extern __m128i   __ICL_INTRINCC    _mm_movm_epi16(__mmask8);
	extern __m256i   __ICL_INTRINCC _mm256_movm_epi16(__mmask16);
	extern __m512i   __ICL_INTRINCC _mm512_movm_epi16(__mmask32);
	extern __m128i   __ICL_INTRINCC    _mm_movm_epi32(__mmask8);
	extern __m256i   __ICL_INTRINCC _mm256_movm_epi32(__mmask8);
	extern __m512i   __ICL_INTRINCC _mm512_movm_epi32(__mmask16);
	extern __m128i   __ICL_INTRINCC    _mm_movm_epi64(__mmask8);
	extern __m256i   __ICL_INTRINCC _mm256_movm_epi64(__mmask8);
	extern __m512i   __ICL_INTRINCC _mm512_movm_epi64(__mmask8);

	extern __m128i __ICL_INTRINCC _mm_mask_mov_epi8(__m128i, __mmask16, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mov_epi8(__mmask16, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mov_epi8(__m256i, __mmask32,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mov_epi8(__mmask32, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mov_epi8(__m512i, __mmask64,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mov_epi8(__mmask64, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_mov_epi16(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mov_epi16(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mov_epi16(__m256i, __mmask16,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mov_epi16(__mmask16, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mov_epi16(__m512i, __mmask32,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mov_epi16(__mmask32, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_mov_epi32(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mov_epi32(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mov_epi32(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mov_epi32(__mmask8, __m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_mov_epi64(__m128i, __mmask8, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mov_epi64(__mmask8, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mov_epi64(__m256i, __mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mov_epi64(__mmask8, __m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_mov_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_mov_pd(__mmask8, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_mov_pd(__m256d, __mmask8, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_mov_pd(__mmask8, __m256d);

	extern __m128  __ICL_INTRINCC _mm_mask_mov_ps(__m128, __mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_mov_ps(__mmask8, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_mov_ps(__m256, __mmask8, __m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_mov_ps(__mmask8, __m256);

	extern __m128d   __ICL_INTRINCC _mm_mask_movedup_pd(__m128d, __mmask8,
		__m128d);
	extern __m128d   __ICL_INTRINCC _mm_maskz_movedup_pd(__mmask8, __m128d);
	extern __m256d   __ICL_INTRINCC _mm256_mask_movedup_pd(__m256d, __mmask8,
		__m256d);
	extern __m256d   __ICL_INTRINCC _mm256_maskz_movedup_pd(__mmask8, __m256d);

	extern __m128    __ICL_INTRINCC _mm_mask_movehdup_ps(__m128, __mmask8,
		__m128);
	extern __m128    __ICL_INTRINCC _mm_maskz_movehdup_ps(__mmask8, __m128);
	extern __m128    __ICL_INTRINCC _mm_mask_moveldup_ps(__m128, __mmask8,
		__m128);
	extern __m128    __ICL_INTRINCC _mm_maskz_moveldup_ps(__mmask8, __m128);
	extern __m256    __ICL_INTRINCC _mm256_mask_movehdup_ps(__m256, __mmask8,
		__m256);
	extern __m256    __ICL_INTRINCC _mm256_maskz_movehdup_ps(__mmask8, __m256);
	extern __m256    __ICL_INTRINCC _mm256_mask_moveldup_ps(__m256, __mmask8,
		__m256);
	extern __m256    __ICL_INTRINCC _mm256_maskz_moveldup_ps(__mmask8, __m256);

	extern __m128d __ICL_INTRINCC _mm_mask_mul_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_mul_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_mul_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_mul_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_mul_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_mul_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_mul_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_mul_ps(__mmask8, __m256, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_mulhi_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mulhi_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mulhi_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mulhi_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mulhi_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mulhi_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mulhi_epi16(__mmask32, __m512i,
		__m512i);
	extern __m128i __ICL_INTRINCC _mm_mask_mulhi_epu16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mulhi_epu16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mulhi_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mulhi_epu16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mulhi_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mulhi_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mulhi_epu16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_mullo_epi16(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mullo_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mullo_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mullo_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mullo_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mullo_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mullo_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_mul_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mul_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mul_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mul_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_mul_epu32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mul_epu32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mul_epu32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mul_epu32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_mullo_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mullo_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mullo_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mullo_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mullo_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_mullo_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mullo_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mullo_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mullo_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mullo_epi64(__mmask8, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mullo_epi64(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mullo_epi64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mullo_epi64(__mmask8, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_mulhrs_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_mulhrs_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_mulhrs_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_mulhrs_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_mulhrs_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_mulhrs_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_mulhrs_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_or_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_or_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_or_epi32(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_or_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_or_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_or_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_or_epi64(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_or_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_or_pd(__m128d, __mmask8, __m128d,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_or_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_or_pd(__m256d, __mmask8, __m256d,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_or_pd(__mmask8, __m256d, __m256d);
	extern __m512d __ICL_INTRINCC _mm512_or_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_or_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_or_pd(__mmask8, __m512d, __m512d);
	extern __m128  __ICL_INTRINCC _mm_mask_or_ps(__m128, __mmask8, __m128, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_or_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_or_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_or_ps(__mmask8, __m256, __m256);
	extern __m512  __ICL_INTRINCC _mm512_or_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_or_ps(__m512, __mmask16,
		__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_or_ps(__mmask16, __m512, __m512);

	extern __m128i __ICL_INTRINCC _mm_mask_packs_epi16(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_packs_epi16(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_packs_epi16(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_packs_epi16(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_packs_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_packs_epi16(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_packs_epi16(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_packs_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_packs_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_packs_epi32(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_packs_epi32(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_packs_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_packs_epi32(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_packs_epi32(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_packus_epi16(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_packus_epi16(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_packus_epi16(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_packus_epi16(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_packus_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_packus_epi16(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_packus_epi16(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_packus_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_packus_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_packus_epi32(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_packus_epi32(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_packus_epi32(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_packus_epi32(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_packus_epi32(__mmask32, __m512i,
		__m512i);

	extern __m256d __ICL_INTRINCC _mm256_permutex_pd(__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_mask_permutex_pd(__m256d, __mmask8,
		__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_permutex_pd(__mmask8, __m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_permutexvar_pd(__m256i, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_mask_permutexvar_pd(__m256d, __mmask8,
		__m256i, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_permutexvar_pd(__mmask8, __m256i,
		__m256d);

	extern __m512i __ICL_INTRINCC _mm512_permutex2var_epi16(__m512i,
		__m512i /* index */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutex2var_epi16(__m512i,
		__mmask32,
		__m512i /* idx */,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask2_permutex2var_epi16(__m512i,
		__m512i /* idx */,
		__mmask32,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutex2var_epi16(__mmask32,
		__m512i,
		__m512i /* idx */,
		__m512i);

	extern __m128i __ICL_INTRINCC        _mm_permutex2var_epi16(__m128i, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC   _mm_mask_permutex2var_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_mask2_permutex2var_epi16(__m128i, __m128i,
		__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_maskz_permutex2var_epi16(__mmask8, __m128i,
		__m128i, __m128i);

	extern __m128i __ICL_INTRINCC        _mm_permutex2var_epi32(__m128i, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC   _mm_mask_permutex2var_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_mask2_permutex2var_epi32(__m128i, __m128i,
		__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_maskz_permutex2var_epi32(__mmask8, __m128i,
		__m128i, __m128i);

	extern __m128i __ICL_INTRINCC        _mm_permutex2var_epi64(__m128i, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC   _mm_mask_permutex2var_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_mask2_permutex2var_epi64(__m128i, __m128i,
		__mmask8, __m128i);
	extern __m128i __ICL_INTRINCC  _mm_maskz_permutex2var_epi64(__mmask8, __m128i,
		__m128i, __m128i);

	extern __m128 __ICL_INTRINCC        _mm_permutex2var_ps(__m128, __m128i,
		__m128);
	extern __m128 __ICL_INTRINCC   _mm_mask_permutex2var_ps(__m128, __mmask8,
		__m128i, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask2_permutex2var_ps(__m128, __m128i,
		__mmask8, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_permutex2var_ps(__mmask8, __m128,
		__m128i, __m128);

	extern __m128d __ICL_INTRINCC        _mm_permutex2var_pd(__m128d, __m128i,
		__m128d);
	extern __m128d __ICL_INTRINCC   _mm_mask_permutex2var_pd(__m128d, __mmask8,
		__m128i, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask2_permutex2var_pd(__m128d, __m128i,
		__mmask8, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_permutex2var_pd(__mmask8, __m128d,
		__m128i, __m128d);

	extern __m256i __ICL_INTRINCC        _mm256_permutex2var_epi16(__m256i,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC   _mm256_mask_permutex2var_epi16(__m256i,
		__mmask16,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_mask2_permutex2var_epi16(__m256i,
		__m256i,
		__mmask16,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_maskz_permutex2var_epi16(__mmask16,
		__m256i,
		__m256i,
		__m256i);

	extern __m256i __ICL_INTRINCC        _mm256_permutex2var_epi32(__m256i,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC   _mm256_mask_permutex2var_epi32(__m256i,
		__mmask8,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_mask2_permutex2var_epi32(__m256i,
		__m256i,
		__mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_maskz_permutex2var_epi32(__mmask8,
		__m256i,
		__m256i,
		__m256i);

	extern __m256i __ICL_INTRINCC        _mm256_permutex2var_epi64(__m256i,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC   _mm256_mask_permutex2var_epi64(__m256i,
		__mmask8,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_mask2_permutex2var_epi64(__m256i,
		__m256i,
		__mmask8,
		__m256i);
	extern __m256i __ICL_INTRINCC  _mm256_maskz_permutex2var_epi64(__mmask8,
		__m256i,
		__m256i,
		__m256i);

	extern __m256 __ICL_INTRINCC        _mm256_permutex2var_ps(__m256, __m256i,
		__m256);
	extern __m256 __ICL_INTRINCC   _mm256_mask_permutex2var_ps(__m256, __mmask8,
		__m256i, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask2_permutex2var_ps(__m256, __m256i,
		__mmask8, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_permutex2var_ps(__mmask8, __m256,
		__m256i, __m256);

	extern __m256d __ICL_INTRINCC        _mm256_permutex2var_pd(__m256d, __m256i,
		__m256d);
	extern __m256d __ICL_INTRINCC   _mm256_mask_permutex2var_pd(__m256d, __mmask8,
		__m256i, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask2_permutex2var_pd(__m256d, __m256i,
		__mmask8, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_permutex2var_pd(__mmask8, __m256d,
		__m256i, __m256d);

#define _mm256_permutex_epi64(src, sel) \
    _mm256_permute4x64_epi64((src), (sel))

	extern __m256i __ICL_INTRINCC _mm256_mask_permutex_epi64(__m256i, __mmask8,
		__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutex_epi64(__mmask8,
		__m256i, const int);

	extern __m128d __ICL_INTRINCC _mm_mask_permute_pd(__m128d, __mmask8,
		__m128d, const int);
	extern __m128d __ICL_INTRINCC _mm_maskz_permute_pd(__mmask8,
		__m128d, const int);
	extern __m256d __ICL_INTRINCC _mm256_mask_permute_pd(__m256d, __mmask8,
		__m256d, const int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_permute_pd(__mmask8,
		__m256d, const int);

	extern __m128 __ICL_INTRINCC _mm_mask_permute_ps(__m128, __mmask8,
		__m128, const int);
	extern __m128 __ICL_INTRINCC _mm_maskz_permute_ps(__mmask8,
		__m128, const int);
	extern __m256 __ICL_INTRINCC _mm256_mask_permute_ps(__m256, __mmask8,
		__m256, const int);
	extern __m256 __ICL_INTRINCC _mm256_maskz_permute_ps(__mmask8,
		__m256, const int);

	extern __m128d __ICL_INTRINCC _mm_mask_permutevar_pd(__m128d, __mmask8,
		__m128d, __m128i);
	extern __m128d __ICL_INTRINCC _mm_maskz_permutevar_pd(__mmask8,
		__m128d, __m128i);
	extern __m256d __ICL_INTRINCC _mm256_mask_permutevar_pd(__m256d, __mmask8,
		__m256d, __m256i);
	extern __m256d __ICL_INTRINCC _mm256_maskz_permutevar_pd(__mmask8,
		__m256d, __m256i);

	extern __m128 __ICL_INTRINCC _mm_mask_permutevar_ps(__m128, __mmask8,
		__m128, __m128i);
	extern __m128 __ICL_INTRINCC _mm_maskz_permutevar_ps(__mmask8,
		__m128, __m128i);
	extern __m256 __ICL_INTRINCC _mm256_mask_permutevar_ps(__m256, __mmask8,
		__m256, __m256i);
	extern __m256 __ICL_INTRINCC _mm256_maskz_permutevar_ps(__mmask8,
		__m256, __m256i);

	extern __m128i __ICL_INTRINCC _mm_permutexvar_epi16(__m128i, __m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_permutexvar_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_permutexvar_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_permutexvar_epi16(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_permutexvar_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutexvar_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_permutexvar_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutexvar_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutexvar_epi16(__mmask32,
		__m512i, __m512i);

#define _mm256_permutexvar_epi32(index, src) \
    _mm256_permutevar8x32_epi32((src), (index))

	extern __m256i __ICL_INTRINCC _mm256_mask_permutexvar_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutexvar_epi32(__mmask8,
		__m256i, __m256i);

	extern __m256i __ICL_INTRINCC _mm256_permutexvar_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_permutexvar_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutexvar_epi64(__mmask8,
		__m256i, __m256i);

#define _mm256_permutexvar_ps(index, src) \
    _mm256_permutevar8x32_ps((src), (index))

	extern __m256 __ICL_INTRINCC _mm256_mask_permutexvar_ps(__m256, __mmask8,
		__m256i, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_permutexvar_ps(__mmask8,
		__m256i, __m256);

	extern __m128d __ICL_INTRINCC _mm_range_pd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_range_pd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_range_pd(__mmask8,
		__m128d, __m128d, int);

	extern __m256d __ICL_INTRINCC _mm256_range_pd(__m256d, __m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_mask_range_pd(__m256d, __mmask8,
		__m256d, __m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_range_pd(__mmask8,
		__m256d, __m256d, int);

	extern __m512d __ICL_INTRINCC _mm512_range_pd(__m512d, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_range_pd(__m512d, __mmask8, __m512d,
		__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_range_pd(__mmask8, __m512d,
		__m512d, int);

	extern __m512d __ICL_INTRINCC _mm512_range_round_pd(__m512d, __m512d,
		int, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_range_round_pd(__m512d, __mmask8,
		__m512d, __m512d,
		int, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_range_round_pd(__mmask8,
		__m512d, __m512d,
		int, int);
	extern __m128 __ICL_INTRINCC _mm_range_ps(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_range_ps(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_range_ps(__mmask8,
		__m128, __m128, int);

	extern __m256 __ICL_INTRINCC _mm256_range_ps(__m256, __m256, int);
	extern __m256 __ICL_INTRINCC _mm256_mask_range_ps(__m256, __mmask8,
		__m256, __m256, int);
	extern __m256 __ICL_INTRINCC _mm256_maskz_range_ps(__mmask8,
		__m256, __m256, int);

	extern __m512  __ICL_INTRINCC _mm512_range_ps(__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_range_ps(__m512, __mmask16,
		__m512, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_range_ps(__mmask16, __m512,
		__m512, int);

	extern __m512 __ICL_INTRINCC _mm512_range_round_ps(__m512, __m512,
		int, int);
	extern __m512 __ICL_INTRINCC _mm512_mask_range_round_ps(__m512, __mmask16,
		__m512, __m512,
		int, int);
	extern __m512 __ICL_INTRINCC _mm512_maskz_range_round_ps(__mmask16,
		__m512, __m512,
		int, int);

	extern __m128d __ICL_INTRINCC _mm_range_round_sd(__m128d, __m128d, int, int);
	extern __m128d __ICL_INTRINCC _mm_mask_range_round_sd(__m128d, __mmask8,
		__m128d, __m128d,
		int, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_range_round_sd(__mmask8,
		__m128d, __m128d,
		int, int);
#define _mm_mask_range_sd(v1, k, v2, v3, imm) \
    _mm_mask_range_round_sd((v1), (k), (v2), (v3), (imm), \
                            _MM_FROUND_CUR_DIRECTION)

#define _mm_maskz_range_sd(k, v2, v3, imm) \
    _mm_maskz_range_round_sd((k), (v2), (v3), (imm), \
                             _MM_FROUND_CUR_DIRECTION)

	extern __m128 __ICL_INTRINCC _mm_range_round_ss(__m128, __m128, int, int);
	extern __m128 __ICL_INTRINCC _mm_mask_range_round_ss(__m128, __mmask8,
		__m128, __m128,
		int, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_range_round_ss(__mmask8,
		__m128, __m128,
		int, int);
#define _mm_mask_range_ss(v1, k, v2, v3, imm) \
    _mm_mask_range_round_ss((v1), (k), (v2), (v3), (imm), \
                            _MM_FROUND_CUR_DIRECTION)

#define _mm_maskz_range_ss(k, v2, v3, imm) \
    _mm_maskz_range_round_ss((k), (v2), (v3), (imm), \
                             _MM_FROUND_CUR_DIRECTION)

	extern __m128d __ICL_INTRINCC _mm_rcp14_pd(__m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_rcp14_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_rcp14_pd(__mmask8, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_rcp14_pd(__m256d);
	extern __m256d __ICL_INTRINCC _mm256_mask_rcp14_pd(__m256d, __mmask8, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_rcp14_pd(__mmask8, __m256d);

	extern __m128 __ICL_INTRINCC _mm_rcp14_ps(__m128);
	extern __m128 __ICL_INTRINCC _mm_mask_rcp14_ps(__m128, __mmask8, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_rcp14_ps(__mmask8, __m128);
	extern __m256 __ICL_INTRINCC _mm256_rcp14_ps(__m256);
	extern __m256 __ICL_INTRINCC _mm256_mask_rcp14_ps(__m256, __mmask8, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_rcp14_ps(__mmask8, __m256);

	extern __m128d  __ICL_INTRINCC _mm_reduce_pd(__m128d, int);
	extern __m128d  __ICL_INTRINCC _mm_mask_reduce_pd(__m128d, __mmask8,
		__m128d, int);
	extern __m128d  __ICL_INTRINCC _mm_maskz_reduce_pd(__mmask8, __m128d, int);
	extern __m256d __ICL_INTRINCC _mm256_reduce_pd(__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_mask_reduce_pd(__m256d, __mmask8,
		__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_reduce_pd(__mmask8, __m256d, int);
	extern __m512d __ICL_INTRINCC _mm512_reduce_pd(__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_reduce_pd(__m512d, __mmask8,
		__m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_reduce_pd(__mmask8, __m512d, int);
	extern __m512d __ICL_INTRINCC _mm512_reduce_round_pd(__m512d, int, int);
	extern __m512d __ICL_INTRINCC _mm512_mask_reduce_round_pd(__m512d, __mmask8,
		__m512d, int, int);
	extern __m512d __ICL_INTRINCC _mm512_maskz_reduce_round_pd(__mmask8, __m512d,
		int, int);

	extern __m128  __ICL_INTRINCC _mm_reduce_ps(__m128, int);
	extern __m128  __ICL_INTRINCC _mm_mask_reduce_ps(__m128, __mmask8,
		__m128, int);
	extern __m128  __ICL_INTRINCC _mm_maskz_reduce_ps(__mmask8, __m128, int);
	extern __m256  __ICL_INTRINCC _mm256_reduce_ps(__m256, int);
	extern __m256  __ICL_INTRINCC _mm256_mask_reduce_ps(__m256, __mmask8,
		__m256, int);
	extern __m256  __ICL_INTRINCC _mm256_maskz_reduce_ps(__mmask8, __m256, int);
	extern __m512  __ICL_INTRINCC _mm512_reduce_ps(__m512, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_reduce_ps(__m512, __mmask16,
		__m512, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_reduce_ps(__mmask16, __m512, int);
	extern __m512  __ICL_INTRINCC _mm512_reduce_round_ps(__m512, int, int);
	extern __m512  __ICL_INTRINCC _mm512_mask_reduce_round_ps(__m512, __mmask16,
		__m512, int, int);
	extern __m512  __ICL_INTRINCC _mm512_maskz_reduce_round_ps(__mmask16, __m512,
		int, int);

	extern __m128d __ICL_INTRINCC _mm_reduce_sd(__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_reduce_sd(__m128d, __mmask8,
		__m128d, __m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_reduce_sd(__mmask8, __m128d,
		__m128d, int);
	extern __m128d __ICL_INTRINCC _mm_reduce_round_sd(__m128d, __m128d, int, int);
	extern __m128d __ICL_INTRINCC _mm_mask_reduce_round_sd(__m128d, __mmask8,
		__m128d, __m128d, int,
		int);
	extern __m128d __ICL_INTRINCC _mm_maskz_reduce_round_sd(__mmask8, __m128d,
		__m128d, int, int);

	extern __m128 __ICL_INTRINCC _mm_reduce_ss(__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_reduce_ss(__m128, __mmask8,
		__m128, __m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_reduce_ss(__mmask8, __m128,
		__m128, int);
	extern __m128 __ICL_INTRINCC _mm_reduce_round_ss(__m128, __m128, int, int);
	extern __m128 __ICL_INTRINCC _mm_mask_reduce_round_ss(__m128, __mmask8,
		__m128, __m128, int,
		int);
	extern __m128 __ICL_INTRINCC _mm_maskz_reduce_round_ss(__mmask8, __m128,
		__m128, int, int);

	extern __m128i __ICL_INTRINCC _mm_rol_epi32(__m128i, int);
	extern __m128i __ICL_INTRINCC _mm_mask_rol_epi32(__m128i, __mmask8, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_rol_epi32(__mmask8, __m128i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_rol_epi32(__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_rol_epi32(__m256i, __mmask8,
		__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rol_epi32(__mmask8, __m256i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_rol_epi64(__m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_mask_rol_epi64(__m128i, __mmask8, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_rol_epi64(__mmask8, __m128i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_rol_epi64(__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_rol_epi64(__m256i, __mmask8,
		__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rol_epi64(__mmask8, __m256i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_ror_epi32(__m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_mask_ror_epi32(__m128i, __mmask8, __m128i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_ror_epi32(__mmask8, __m128i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_ror_epi32(__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_ror_epi32(__m256i, __mmask8,
		__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_ror_epi32(__mmask8, __m256i,
		const int);
	extern __m128i __ICL_INTRINCC _mm_ror_epi64(__m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_mask_ror_epi64(__m128i, __mmask8,
		__m128i, const int);
	extern __m128i __ICL_INTRINCC _mm_maskz_ror_epi64(__mmask8, __m128i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_ror_epi64(__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_ror_epi64(__m256i, __mmask8,
		__m256i, const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_ror_epi64(__mmask8, __m256i,
		const int);

	extern __m128i __ICL_INTRINCC _mm_rolv_epi32(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_rolv_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_rolv_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_rolv_epi32(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_rolv_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rolv_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_rolv_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_rolv_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_rolv_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_rolv_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_rolv_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rolv_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_rorv_epi32(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_rorv_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_rorv_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_rorv_epi32(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_rorv_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rorv_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_rorv_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_rorv_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_rorv_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_rorv_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_rorv_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_rorv_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_roundscale_pd(__m128d, int);
	extern __m128d __ICL_INTRINCC _mm_mask_roundscale_pd(__m128d, __mmask8,
		__m128d, int);
	extern __m128d __ICL_INTRINCC _mm_maskz_roundscale_pd(__mmask8, __m128d, int);
	extern __m256d __ICL_INTRINCC _mm256_roundscale_pd(__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_mask_roundscale_pd(__m256d, __mmask8,
		__m256d, int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_roundscale_pd(__mmask8, __m256d,
		int);
	extern __m128 __ICL_INTRINCC _mm_roundscale_ps(__m128, int);
	extern __m128 __ICL_INTRINCC _mm_mask_roundscale_ps(__m128, __mmask8,
		__m128, int);
	extern __m128 __ICL_INTRINCC _mm_maskz_roundscale_ps(__mmask8, __m128, int);
	extern __m256 __ICL_INTRINCC _mm256_roundscale_ps(__m256, int);
	extern __m256 __ICL_INTRINCC _mm256_mask_roundscale_ps(__m256, __mmask8,
		__m256, int);
	extern __m256 __ICL_INTRINCC _mm256_maskz_roundscale_ps(__mmask8, __m256, int);
	extern __m128d __ICL_INTRINCC _mm_mask_rsqrt14_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_rsqrt14_pd(__mmask8, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_rsqrt14_pd(__m256d, __mmask8,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_rsqrt14_pd(__mmask8, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_rsqrt14_ps(__m128, __mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_rsqrt14_ps(__mmask8, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_rsqrt14_ps(__m256, __mmask8, __m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_rsqrt14_ps(__mmask8, __m256);

	extern __m512i __ICL_INTRINCC _mm512_sad_epu8(__m512i, __m512i);

	extern __m512i __ICL_INTRINCC _mm512_dbsad_epu8(__m512i, __m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_mask_dbsad_epu8(__m512i, __mmask32,
		__m512i, __m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_dbsad_epu8(__mmask32,
		__m512i, __m512i, int);

	extern __m128d __ICL_INTRINCC _mm_scalef_pd(__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_mask_scalef_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_scalef_pd(__mmask8, __m128d,
		__m128d);
	extern __m256d __ICL_INTRINCC _mm256_scalef_pd(__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_mask_scalef_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_scalef_pd(__mmask8, __m256d,
		__m256d);

	extern __m128 __ICL_INTRINCC _mm_scalef_ps(__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_mask_scalef_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_scalef_ps(__mmask8, __m128,
		__m128);
	extern __m256 __ICL_INTRINCC _mm256_scalef_ps(__m256, __m256);
	extern __m256 __ICL_INTRINCC _mm256_mask_scalef_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_scalef_ps(__mmask8, __m256,
		__m256);
	extern __m128i  __ICL_INTRINCC _mm_mask_set1_epi8(__m128i, __mmask16, char);
	extern __m128i  __ICL_INTRINCC _mm_maskz_set1_epi8(__mmask16, char);

	extern __m128i  __ICL_INTRINCC _mm_mask_set1_epi16(__m128i, __mmask8, short);
	extern __m128i  __ICL_INTRINCC _mm_maskz_set1_epi16(__mmask8, short);

	extern __m128i  __ICL_INTRINCC _mm_mask_set1_epi32(__m128i, __mmask8, int);
	extern __m128i  __ICL_INTRINCC _mm_maskz_set1_epi32(__mmask8, int);

	extern __m128i  __ICL_INTRINCC _mm_mask_set1_epi64(__m128i, __mmask8, __int64);
	extern __m128i  __ICL_INTRINCC _mm_maskz_set1_epi64(__mmask8, __int64);

	extern __m256i  __ICL_INTRINCC _mm256_mask_set1_epi8(__m256i, __mmask32, char);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_set1_epi8(__mmask32, char);

	extern __m256i  __ICL_INTRINCC _mm256_mask_set1_epi16(__m256i, __mmask16,
		short);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_set1_epi16(__mmask16, short);

	extern __m256i  __ICL_INTRINCC _mm256_mask_set1_epi32(__m256i, __mmask8, int);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_set1_epi32(__mmask8, int);

	extern __m256i  __ICL_INTRINCC _mm256_mask_set1_epi64(__m256i, __mmask8,
		__int64);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_set1_epi64(__mmask8, __int64);

	extern __m512i  __ICL_INTRINCC _mm512_mask_set1_epi8(__m512i, __mmask64, char);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_set1_epi8(__mmask64, char);
	extern __m512i  __ICL_INTRINCC _mm512_mask_set1_epi16(__m512i, __mmask32,
		short);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_set1_epi16(__mmask32, short);

	extern __m128i  __ICL_INTRINCC _mm_mask_shufflehi_epi16(__m128i, __mmask8,
		__m128i, int);
	extern __m128i  __ICL_INTRINCC _mm_maskz_shufflehi_epi16(__mmask8, __m128i,
		int);
	extern __m256i  __ICL_INTRINCC _mm256_mask_shufflehi_epi16(__m256i, __mmask16,
		__m256i, int);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_shufflehi_epi16(__mmask16, __m256i,
		int);
	extern __m512i  __ICL_INTRINCC _mm512_shufflehi_epi16(__m512i, int);
	extern __m512i  __ICL_INTRINCC _mm512_mask_shufflehi_epi16(__m512i, __mmask32,
		__m512i, int);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_shufflehi_epi16(__mmask32, __m512i,
		int);
	extern __m128i  __ICL_INTRINCC _mm_mask_shufflelo_epi16(__m128i, __mmask8,
		__m128i, int);
	extern __m128i  __ICL_INTRINCC _mm_maskz_shufflelo_epi16(__mmask8, __m128i,
		int);
	extern __m256i  __ICL_INTRINCC _mm256_mask_shufflelo_epi16(__m256i, __mmask16,
		__m256i, int);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_shufflelo_epi16(__mmask16, __m256i,
		int);
	extern __m512i  __ICL_INTRINCC _mm512_shufflelo_epi16(__m512i, int);
	extern __m512i  __ICL_INTRINCC _mm512_mask_shufflelo_epi16(__m512i, __mmask32,
		__m512i, int);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_shufflelo_epi16(__mmask32, __m512i,
		int);

	extern __m128i  __ICL_INTRINCC _mm_mask_shuffle_epi32(__m128i, __mmask8,
		__m128i, _MM_PERM_ENUM);
	extern __m128i  __ICL_INTRINCC _mm_maskz_shuffle_epi32(__mmask8, __m128i,
		_MM_PERM_ENUM);
	extern __m256i  __ICL_INTRINCC _mm256_mask_shuffle_epi32(__m256i, __mmask8,
		__m256i,
		_MM_PERM_ENUM);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_shuffle_epi32(__mmask8, __m256i,
		_MM_PERM_ENUM);

	extern __m128i  __ICL_INTRINCC _mm_mask_shuffle_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i  __ICL_INTRINCC _mm_maskz_shuffle_epi8(__mmask16,
		__m128i, __m128i);
	extern __m256i  __ICL_INTRINCC _mm256_mask_shuffle_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i  __ICL_INTRINCC _mm256_maskz_shuffle_epi8(__mmask32,
		__m256i, __m256i);
	extern __m512i  __ICL_INTRINCC _mm512_shuffle_epi8(__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_mask_shuffle_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i  __ICL_INTRINCC _mm512_maskz_shuffle_epi8(__mmask64,
		__m512i, __m512i);

	extern __m256  __ICL_INTRINCC _mm256_shuffle_f32x4(__m256, __m256,
		const int);
	extern __m256  __ICL_INTRINCC _mm256_mask_shuffle_f32x4(__m256, __mmask8,
		__m256, __m256,
		const int);
	extern __m256  __ICL_INTRINCC _mm256_maskz_shuffle_f32x4(__mmask8,
		__m256, __m256,
		const int);

	extern __m256d __ICL_INTRINCC _mm256_shuffle_f64x2(__m256d, __m256d,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_mask_shuffle_f64x2(__m256d, __mmask8,
		__m256d, __m256d,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_shuffle_f64x2(__mmask8,
		__m256d, __m256d,
		const int);

	extern __m256i __ICL_INTRINCC _mm256_shuffle_i32x4(__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_shuffle_i32x4(__m256i, __mmask8,
		__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_shuffle_i32x4(__mmask8,
		__m256i, __m256i,
		const int);

	extern __m256i __ICL_INTRINCC _mm256_shuffle_i64x2(__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_mask_shuffle_i64x2(__m256i, __mmask8,
		__m256i, __m256i,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_shuffle_i64x2(__mmask8,
		__m256i, __m256i,
		const int);
	extern __m128d __ICL_INTRINCC _mm_mask_shuffle_pd(__m128d, __mmask8,
		__m128d, __m128d,
		const int);
	extern __m128d __ICL_INTRINCC _mm_maskz_shuffle_pd(__mmask8,
		__m128d, __m128d,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_mask_shuffle_pd(__m256d, __mmask8,
		__m256d, __m256d,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_maskz_shuffle_pd(__mmask8,
		__m256d, __m256d,
		const int);
	extern __m128 __ICL_INTRINCC _mm_mask_shuffle_ps(__m128, __mmask8,
		__m128, __m128,
		const int);
	extern __m128 __ICL_INTRINCC _mm_maskz_shuffle_ps(__mmask8,
		__m128, __m128,
		const int);
	extern __m256 __ICL_INTRINCC _mm256_mask_shuffle_ps(__m256, __mmask8,
		__m256, __m256,
		const int);
	extern __m256 __ICL_INTRINCC _mm256_maskz_shuffle_ps(__mmask8,
		__m256, __m256,
		const int);

	extern __m512i __ICL_INTRINCC _mm512_bslli_epi128(__m512i, int);
	extern __m512i __ICL_INTRINCC _mm512_bsrli_epi128(__m512i, int);

	extern __m128i __ICL_INTRINCC _mm_mask_sll_epi16(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sll_epi16(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sll_epi16(__m256i, __mmask16,
		__m256i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sll_epi16(__mmask16, __m256i,
		__m128i);

	extern __m512i __ICL_INTRINCC _mm512_sll_epi16(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sll_epi16(__m512i, __mmask32,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sll_epi16(__mmask32, __m512i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_slli_epi16(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_slli_epi16(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_slli_epi16(__m256i, __mmask16,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_slli_epi16(__mmask16, __m256i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_slli_epi16(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_slli_epi16(__m512i, __mmask32,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_slli_epi16(__mmask32, __m512i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_mask_sra_epi16(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sra_epi16(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sra_epi16(__m256i, __mmask16,
		__m256i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sra_epi16(__mmask16, __m256i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_sra_epi16(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sra_epi16(__m512i, __mmask32,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sra_epi16(__mmask32, __m512i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_srai_epi16(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srai_epi16(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srai_epi16(__m256i, __mmask16,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srai_epi16(__mmask16, __m256i,
		unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_srai_epi16(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srai_epi16(__m512i, __mmask32,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srai_epi16(__mmask32, __m512i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_mask_srl_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srl_epi16(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srl_epi16(__m256i, __mmask16,
		__m256i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srl_epi16(__mmask16, __m256i,
		__m128i);
	extern __m512i __ICL_INTRINCC _mm512_srl_epi16(__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srl_epi16(__m512i, __mmask32,
		__m512i, __m128i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srl_epi16(__mmask32, __m512i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_srli_epi16(__m128i, __mmask8,
		__m128i, int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srli_epi16(__mmask8, __m128i, int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srli_epi16(__m256i, __mmask16,
		__m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srli_epi16(__mmask16, __m256i, int);
	extern __m512i __ICL_INTRINCC _mm512_srli_epi16(__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_mask_srli_epi16(__m512i, __mmask32,
		__m512i, unsigned int);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srli_epi16(__mmask32, __m512i, int);

	extern __m128i __ICL_INTRINCC _mm_mask_sll_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sll_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sll_epi32(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sll_epi32(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_sll_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sll_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sll_epi64(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sll_epi64(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_slli_epi32(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_slli_epi32(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_slli_epi32(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_slli_epi32(__mmask8, __m256i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_mask_slli_epi64(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_slli_epi64(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_slli_epi64(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_slli_epi64(__mmask8, __m256i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_sllv_epi16(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_sllv_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sllv_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_sllv_epi16(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sllv_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sllv_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_sllv_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sllv_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sllv_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_sllv_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sllv_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sllv_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sllv_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_sllv_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sllv_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sllv_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sllv_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_sra_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sra_epi32(__mmask8, __m128i, __m128i);

	extern __m256i __ICL_INTRINCC _mm256_mask_sra_epi32(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sra_epi32(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_sra_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_sra_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sra_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_sra_epi64(__m256i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sra_epi64(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sra_epi64(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_srai_epi32(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srai_epi32(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srai_epi32(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srai_epi32(__mmask8, __m256i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_srai_epi64(__m128i, unsigned int);
	extern __m128i __ICL_INTRINCC _mm_mask_srai_epi64(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srai_epi64(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_srai_epi64(__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srai_epi64(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srai_epi64(__mmask8, __m256i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_srav_epi16(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_srav_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srav_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_srav_epi16(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srav_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srav_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_srav_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srav_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srav_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_srav_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srav_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srav_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srav_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_srav_epi64(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_srav_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srav_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_srav_epi64(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srav_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srav_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_srl_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srl_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srl_epi32(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srl_epi32(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_srl_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srl_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srl_epi64(__m256i, __mmask8, __m256i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srl_epi64(__mmask8, __m256i,
		__m128i);

	extern __m128i __ICL_INTRINCC _mm_mask_srli_epi32(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srli_epi32(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srli_epi32(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srli_epi32(__mmask8, __m256i,
		unsigned int);

	extern __m128i __ICL_INTRINCC _mm_mask_srli_epi64(__m128i, __mmask8, __m128i,
		unsigned int);
	extern __m128i __ICL_INTRINCC _mm_maskz_srli_epi64(__mmask8, __m128i,
		unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_mask_srli_epi64(__m256i, __mmask8,
		__m256i, unsigned int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srli_epi64(__mmask8, __m256i,
		unsigned int);


	extern __m128i __ICL_INTRINCC _mm_srlv_epi16(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_srlv_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srlv_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_srlv_epi16(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srlv_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srlv_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_srlv_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_srlv_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_srlv_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_srlv_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srlv_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srlv_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srlv_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_srlv_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_srlv_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_srlv_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_srlv_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_sqrt_pd(__m128d, __mmask8, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_sqrt_pd(__mmask8, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_sqrt_pd(__m256d, __mmask8, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_sqrt_pd(__mmask8, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_sqrt_ps(__m128, __mmask8, __m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_sqrt_ps(__mmask8, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_sqrt_ps(__m256, __mmask8, __m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_sqrt_ps(__mmask8, __m256);

	extern __m128i __ICL_INTRINCC _mm_mask_sub_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sub_epi8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sub_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sub_epi8(__mmask32,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_sub_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sub_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sub_epi8(__mmask64,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_sub_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sub_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sub_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sub_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_sub_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_sub_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_sub_epi16(__mmask32,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_subs_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_subs_epi8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_subs_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_subs_epi8(__mmask32,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_subs_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_subs_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_subs_epi8(__mmask64,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_subs_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_subs_epi16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_subs_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_subs_epi16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_subs_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_subs_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_subs_epi16(__mmask32,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_subs_epu8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_subs_epu8(__mmask16,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_subs_epu8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_subs_epu8(__mmask32,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_subs_epu8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_subs_epu8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_subs_epu8(__mmask64,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_subs_epu16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_subs_epu16(__mmask8,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_subs_epu16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_subs_epu16(__mmask16,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_subs_epu16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_subs_epu16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_subs_epu16(__mmask32,
		__m512i, __m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_sub_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sub_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sub_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sub_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_sub_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_sub_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_sub_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_sub_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_sub_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_sub_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_sub_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_sub_pd(__mmask8, __m256d, __m256d);
	extern __m128  __ICL_INTRINCC _mm_mask_sub_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_sub_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_sub_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_sub_ps(__mmask8, __m256, __m256);

	extern __m128i __ICL_INTRINCC _mm_ternarylogic_epi32(__m128i, __m128i,
		__m128i, int);
	extern __m128i __ICL_INTRINCC _mm_mask_ternarylogic_epi32(__m128i, __mmask8,
		__m128i, __m128i,
		int);
	extern __m128i __ICL_INTRINCC _mm_maskz_ternarylogic_epi32(__mmask8, __m128i,
		__m128i, __m128i,
		int);
	extern __m128i __ICL_INTRINCC _mm_ternarylogic_epi64(__m128i, __m128i,
		__m128i, int);
	extern __m128i __ICL_INTRINCC _mm_mask_ternarylogic_epi64(__m128i, __mmask8,
		__m128i, __m128i,
		int);
	extern __m128i __ICL_INTRINCC _mm_maskz_ternarylogic_epi64(__mmask8, __m128i,
		__m128i, __m128i,
		int);
	extern __m256i __ICL_INTRINCC _mm256_ternarylogic_epi32(__m256i, __m256i,
		__m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_mask_ternarylogic_epi32(__m256i, __mmask8,
		__m256i, __m256i,
		int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_ternarylogic_epi32(__mmask8,
		__m256i,
		__m256i,
		__m256i,
		int);
	extern __m256i __ICL_INTRINCC _mm256_ternarylogic_epi64(__m256i, __m256i,
		__m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_mask_ternarylogic_epi64(__m256i, __mmask8,
		__m256i, __m256i, int);
	extern __m256i __ICL_INTRINCC _mm256_maskz_ternarylogic_epi64(__mmask8,
		__m256i,
		__m256i,
		__m256i,
		int);

	extern __mmask16 __ICL_INTRINCC _mm_test_epi8_mask(__m128i, __m128i);
	extern __mmask16 __ICL_INTRINCC _mm_mask_test_epi8_mask(__mmask16, __m128i,
		__m128i);
	extern __mmask32 __ICL_INTRINCC _mm256_test_epi8_mask(__m256i, __m256i);
	extern __mmask32 __ICL_INTRINCC _mm256_mask_test_epi8_mask(__mmask32, __m256i,
		__m256i);
	extern __mmask64 __ICL_INTRINCC _mm512_test_epi8_mask(__m512i, __m512i);
	extern __mmask64 __ICL_INTRINCC _mm512_mask_test_epi8_mask(__mmask64, __m512i,
		__m512i);
	extern __mmask8  __ICL_INTRINCC _mm_test_epi16_mask(__m128i, __m128i);
	extern __mmask8  __ICL_INTRINCC _mm_mask_test_epi16_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask16 __ICL_INTRINCC _mm256_test_epi16_mask(__m256i, __m256i);
	extern __mmask16 __ICL_INTRINCC _mm256_mask_test_epi16_mask(__mmask16, __m256i,
		__m256i);
	extern __mmask32 __ICL_INTRINCC _mm512_test_epi16_mask(__m512i, __m512i);
	extern __mmask32 __ICL_INTRINCC _mm512_mask_test_epi16_mask(__mmask32, __m512i,
		__m512i);
	extern __mmask8 __ICL_INTRINCC _mm_test_epi32_mask(__m128i, __m128i);
	extern __mmask8 __ICL_INTRINCC _mm_mask_test_epi32_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask8 __ICL_INTRINCC _mm256_test_epi32_mask(__m256i, __m256i);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_test_epi32_mask(__mmask8, __m256i,
		__m256i);
	extern __mmask8 __ICL_INTRINCC _mm_test_epi64_mask(__m128i, __m128i);
	extern __mmask8 __ICL_INTRINCC _mm_mask_test_epi64_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask8 __ICL_INTRINCC _mm256_test_epi64_mask(__m256i, __m256i);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_test_epi64_mask(__mmask8, __m256i,
		__m256i);

	extern __mmask16 __ICL_INTRINCC _mm_testn_epi8_mask(__m128i, __m128i);
	extern __mmask16 __ICL_INTRINCC _mm_mask_testn_epi8_mask(__mmask16, __m128i,
		__m128i);
	extern __mmask32 __ICL_INTRINCC _mm256_testn_epi8_mask(__m256i, __m256i);
	extern __mmask32 __ICL_INTRINCC _mm256_mask_testn_epi8_mask(__mmask32, __m256i,
		__m256i);
	extern __mmask64 __ICL_INTRINCC _mm512_testn_epi8_mask(__m512i, __m512i);
	extern __mmask64 __ICL_INTRINCC _mm512_mask_testn_epi8_mask(__mmask64, __m512i,
		__m512i);
	extern __mmask8  __ICL_INTRINCC _mm_testn_epi16_mask(__m128i, __m128i);
	extern __mmask8  __ICL_INTRINCC _mm_mask_testn_epi16_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask16 __ICL_INTRINCC _mm256_testn_epi16_mask(__m256i, __m256i);
	extern __mmask16 __ICL_INTRINCC _mm256_mask_testn_epi16_mask(__mmask16,
		__m256i, __m256i);
	extern __mmask32 __ICL_INTRINCC _mm512_testn_epi16_mask(__m512i, __m512i);
	extern __mmask32 __ICL_INTRINCC _mm512_mask_testn_epi16_mask(__mmask32,
		__m512i, __m512i);
	extern __mmask8 __ICL_INTRINCC _mm_testn_epi32_mask(__m128i, __m128i);
	extern __mmask8 __ICL_INTRINCC _mm_mask_testn_epi32_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask8 __ICL_INTRINCC _mm256_testn_epi32_mask(__m256i, __m256i);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_testn_epi32_mask(__mmask8, __m256i,
		__m256i);
	extern __mmask8 __ICL_INTRINCC _mm_testn_epi64_mask(__m128i, __m128i);
	extern __mmask8 __ICL_INTRINCC _mm_mask_testn_epi64_mask(__mmask8, __m128i,
		__m128i);
	extern __mmask8 __ICL_INTRINCC _mm256_testn_epi64_mask(__m256i, __m256i);
	extern __mmask8 __ICL_INTRINCC _mm256_mask_testn_epi64_mask(__mmask8, __m256i,
		__m256i);

	extern __mmask32 __ICL_INTRINCC _mm512_kunpackw(__mmask32, __mmask32);
	extern __mmask64 __ICL_INTRINCC _mm512_kunpackd(__mmask64, __mmask64);

	extern __m128i __ICL_INTRINCC _mm_mask_unpackhi_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpackhi_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpackhi_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpackhi_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_unpackhi_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpackhi_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpackhi_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpackhi_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpackhi_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpackhi_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpackhi_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_unpackhi_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpackhi_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpackhi_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpackhi_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpackhi_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpackhi_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpackhi_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpackhi_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpackhi_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpackhi_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpackhi_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_unpackhi_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_unpackhi_pd(__mmask8, __m128d,
		__m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_unpackhi_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_unpackhi_pd(__mmask8, __m256d,
		__m256d);

	extern __m128 __ICL_INTRINCC _mm_mask_unpackhi_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_unpackhi_ps(__mmask8, __m128,
		__m128);
	extern __m256 __ICL_INTRINCC _mm256_mask_unpackhi_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_unpackhi_ps(__mmask8, __m256,
		__m256);

	extern __m128i __ICL_INTRINCC _mm_mask_unpacklo_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpacklo_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpacklo_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpacklo_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_unpacklo_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpacklo_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpacklo_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpacklo_epi16(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpacklo_epi16(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpacklo_epi16(__m256i, __mmask16,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpacklo_epi16(__mmask16, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_unpacklo_epi16(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_unpacklo_epi16(__m512i, __mmask32,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_unpacklo_epi16(__mmask32, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpacklo_epi32(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpacklo_epi32(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpacklo_epi32(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpacklo_epi32(__mmask8, __m256i,
		__m256i);

	extern __m128i __ICL_INTRINCC _mm_mask_unpacklo_epi64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_unpacklo_epi64(__mmask8, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_unpacklo_epi64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_unpacklo_epi64(__mmask8, __m256i,
		__m256i);

	extern __m128d __ICL_INTRINCC _mm_mask_unpacklo_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_unpacklo_pd(__mmask8, __m128d,
		__m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_unpacklo_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_unpacklo_pd(__mmask8, __m256d,
		__m256d);

	extern __m128 __ICL_INTRINCC _mm_mask_unpacklo_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC _mm_maskz_unpacklo_ps(__mmask8, __m128,
		__m128);
	extern __m256 __ICL_INTRINCC _mm256_mask_unpacklo_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC _mm256_maskz_unpacklo_ps(__mmask8, __m256,
		__m256);

	extern __m128i __ICL_INTRINCC _mm_mask_xor_epi32(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_xor_epi32(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_xor_epi32(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_xor_epi32(__mmask8, __m256i,
		__m256i);
	extern __m128i __ICL_INTRINCC _mm_mask_xor_epi64(__m128i, __mmask8, __m128i,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_xor_epi64(__mmask8, __m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_mask_xor_epi64(__m256i, __mmask8, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_xor_epi64(__mmask8, __m256i,
		__m256i);
	extern __m128d __ICL_INTRINCC _mm_mask_xor_pd(__m128d, __mmask8, __m128d,
		__m128d);
	extern __m128d __ICL_INTRINCC _mm_maskz_xor_pd(__mmask8, __m128d, __m128d);
	extern __m256d __ICL_INTRINCC _mm256_mask_xor_pd(__m256d, __mmask8, __m256d,
		__m256d);
	extern __m256d __ICL_INTRINCC _mm256_maskz_xor_pd(__mmask8, __m256d, __m256d);
	extern __m512d __ICL_INTRINCC _mm512_xor_pd(__m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_maskz_xor_pd(__mmask8, __m512d, __m512d);
	extern __m512d __ICL_INTRINCC _mm512_mask_xor_pd(__m512d, __mmask8,
		__m512d, __m512d);
	extern __m128  __ICL_INTRINCC _mm_mask_xor_ps(__m128, __mmask8, __m128,
		__m128);
	extern __m128  __ICL_INTRINCC _mm_maskz_xor_ps(__mmask8, __m128, __m128);
	extern __m256  __ICL_INTRINCC _mm256_mask_xor_ps(__m256, __mmask8, __m256,
		__m256);
	extern __m256  __ICL_INTRINCC _mm256_maskz_xor_ps(__mmask8, __m256, __m256);
	extern __m512  __ICL_INTRINCC _mm512_xor_ps(__m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_maskz_xor_ps(__mmask16, __m512, __m512);
	extern __m512  __ICL_INTRINCC _mm512_mask_xor_ps(__m512, __mmask16,
		__m512, __m512);

	extern __m128 __ICL_INTRINCC   _mm_mask_fmadd_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmadd_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmadd_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fmadd_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fmadd_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fmadd_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fmadd_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmadd_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmadd_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fmadd_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fmadd_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fmadd_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128 __ICL_INTRINCC   _mm_mask_fmaddsub_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmaddsub_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmaddsub_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fmaddsub_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fmaddsub_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fmaddsub_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fmaddsub_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmaddsub_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmaddsub_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fmaddsub_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fmaddsub_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fmaddsub_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128 __ICL_INTRINCC   _mm_mask_fmsub_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmsub_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmsub_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fmsub_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fmsub_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fmsub_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fmsub_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmsub_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmsub_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fmsub_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fmsub_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fmsub_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128 __ICL_INTRINCC   _mm_mask_fmsubadd_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fmsubadd_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fmsubadd_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fmsubadd_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fmsubadd_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fmsubadd_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fmsubadd_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fmsubadd_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fmsubadd_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fmsubadd_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fmsubadd_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fmsubadd_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128 __ICL_INTRINCC   _mm_mask_fnmadd_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fnmadd_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fnmadd_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fnmadd_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fnmadd_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fnmadd_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fnmadd_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fnmadd_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fnmadd_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fnmadd_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fnmadd_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fnmadd_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128 __ICL_INTRINCC   _mm_mask_fnmsub_ps(__m128, __mmask8,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_maskz_fnmsub_ps(__mmask8, __m128,
		__m128, __m128);
	extern __m128 __ICL_INTRINCC  _mm_mask3_fnmsub_ps(__m128, __m128,
		__m128, __mmask8);
	extern __m256 __ICL_INTRINCC   _mm256_mask_fnmsub_ps(__m256, __mmask8,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_maskz_fnmsub_ps(__mmask8, __m256,
		__m256, __m256);
	extern __m256 __ICL_INTRINCC  _mm256_mask3_fnmsub_ps(__m256, __m256,
		__m256, __mmask8);

	extern __m128d __ICL_INTRINCC   _mm_mask_fnmsub_pd(__m128d, __mmask8,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_maskz_fnmsub_pd(__mmask8, __m128d,
		__m128d, __m128d);
	extern __m128d __ICL_INTRINCC  _mm_mask3_fnmsub_pd(__m128d, __m128d,
		__m128d, __mmask8);
	extern __m256d __ICL_INTRINCC   _mm256_mask_fnmsub_pd(__m256d, __mmask8,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_maskz_fnmsub_pd(__mmask8, __m256d,
		__m256d, __m256d);
	extern __m256d __ICL_INTRINCC  _mm256_mask3_fnmsub_pd(__m256d, __m256d,
		__m256d, __mmask8);

	extern __m128i __ICL_INTRINCC _mm_mmask_i32gather_epi32(__m128i,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_mmask_i32gather_epi32(__m256i,
		__mmask8,
		__m256i,
		void const*,
		const int);
	extern __m128i __ICL_INTRINCC _mm_mmask_i64gather_epi32(__m128i,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m128i __ICL_INTRINCC _mm256_mmask_i64gather_epi32(__m128i,
		__mmask8,
		__m256i,
		void const*,
		const int);

	extern __m128i __ICL_INTRINCC _mm_mmask_i64gather_epi64(__m128i,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_mmask_i64gather_epi64(__m256i,
		__mmask8,
		__m256i,
		void const*,
		const int);
	extern __m128i __ICL_INTRINCC _mm_mmask_i32gather_epi64(__m128i,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256i __ICL_INTRINCC _mm256_mmask_i32gather_epi64(__m256i,
		__mmask8,
		__m128i,
		void const*,
		const int);

	extern __m128 __ICL_INTRINCC _mm_mmask_i32gather_ps(__m128,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256 __ICL_INTRINCC _mm256_mmask_i32gather_ps(__m256,
		__mmask8,
		__m256i,
		void const*,
		const int);
	extern __m128 __ICL_INTRINCC _mm_mmask_i64gather_ps(__m128,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m128 __ICL_INTRINCC _mm256_mmask_i64gather_ps(__m128,
		__mmask8,
		__m256i,
		void const*,
		const int);

	extern __m128d __ICL_INTRINCC _mm_mmask_i64gather_pd(__m128d,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_mmask_i64gather_pd(__m256d,
		__mmask8,
		__m256i,
		void const*,
		const int);
	extern __m128d __ICL_INTRINCC _mm_mmask_i32gather_pd(__m128d,
		__mmask8,
		__m128i,
		void const*,
		const int);
	extern __m256d __ICL_INTRINCC _mm256_mmask_i32gather_pd(__m256d,
		__mmask8,
		__m128i,
		void const*,
		const int);

	extern void __ICL_INTRINCC _mm_i32scatter_epi32(void*,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_i32scatter_epi32(void*,
		__m256i,
		__m256i,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i32scatter_epi32(void*,
		__mmask8,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i32scatter_epi32(void*,
		__mmask8,
		__m256i,
		__m256i,
		const int);

	extern void __ICL_INTRINCC _mm_i64scatter_epi32(void*,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_i64scatter_epi32(void*,
		__m256i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i64scatter_epi32(void*,
		__mmask8,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i64scatter_epi32(void*,
		__mmask8,
		__m256i,
		__m128i,
		const int);

	extern void __ICL_INTRINCC _mm_i64scatter_epi64(void*,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_i64scatter_epi64(void*,
		__m256i,
		__m256i,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i64scatter_epi64(void*,
		__mmask8,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i64scatter_epi64(void*,
		__mmask8,
		__m256i,
		__m256i,
		const int);

	extern void __ICL_INTRINCC _mm_i32scatter_epi64(void*,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_i32scatter_epi64(void*,
		__m128i,
		__m256i,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i32scatter_epi64(void*,
		__mmask8,
		__m128i,
		__m128i,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i32scatter_epi64(void*,
		__mmask8,
		__m128i,
		__m256i,
		const int);

	extern void __ICL_INTRINCC _mm_i32scatter_ps(void*,
		__m128i,
		__m128,
		const int);
	extern void __ICL_INTRINCC _mm256_i32scatter_ps(void*,
		__m256i,
		__m256,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i32scatter_ps(void*,
		__mmask8,
		__m128i,
		__m128,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i32scatter_ps(void*,
		__mmask8,
		__m256i,
		__m256,
		const int);

	extern void __ICL_INTRINCC _mm_i64scatter_ps(void*,
		__m128i,
		__m128,
		const int);
	extern void __ICL_INTRINCC _mm256_i64scatter_ps(void*,
		__m256i,
		__m128,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i64scatter_ps(void*,
		__mmask8,
		__m128i,
		__m128,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i64scatter_ps(void*,
		__mmask8,
		__m256i,
		__m128,
		const int);

	extern void __ICL_INTRINCC _mm_i64scatter_pd(void*,
		__m128i,
		__m128d,
		const int);
	extern void __ICL_INTRINCC _mm256_i64scatter_pd(void*,
		__m256i,
		__m256d,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i64scatter_pd(void*,
		__mmask8,
		__m128i,
		__m128d,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i64scatter_pd(void*,
		__mmask8,
		__m256i,
		__m256d,
		const int);

	extern void __ICL_INTRINCC _mm_i32scatter_pd(void*,
		__m128i,
		__m128d,
		const int);
	extern void __ICL_INTRINCC _mm256_i32scatter_pd(void*,
		__m128i,
		__m256d,
		const int);
	extern void __ICL_INTRINCC _mm_mask_i32scatter_pd(void*,
		__mmask8,
		__m128i,
		__m128d,
		const int);
	extern void __ICL_INTRINCC _mm256_mask_i32scatter_pd(void*,
		__mmask8,
		__m128i,
		__m256d,
		const int);

	/*
	* Intrinsics related to the AVX512IFMA52 instructions.
	*/

	extern __m128i __ICL_INTRINCC _mm_madd52hi_epu64(__m128i, __m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_madd52hi_epu64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_madd52hi_epu64(__mmask8, __m128i,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_madd52hi_epu64(__m256i, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_madd52hi_epu64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_madd52hi_epu64(__mmask8, __m256i,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_madd52hi_epu64(__m512i, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_madd52hi_epu64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_madd52hi_epu64(__mmask8, __m512i,
		__m512i, __m512i);
	extern __m128i __ICL_INTRINCC _mm_madd52lo_epu64(__m128i, __m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_madd52lo_epu64(__m128i, __mmask8,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_madd52lo_epu64(__mmask8, __m128i,
		__m128i, __m128i);
	extern __m256i __ICL_INTRINCC _mm256_madd52lo_epu64(__m256i, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_madd52lo_epu64(__m256i, __mmask8,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_madd52lo_epu64(__mmask8, __m256i,
		__m256i, __m256i);
	extern __m512i __ICL_INTRINCC _mm512_madd52lo_epu64(__m512i, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_madd52lo_epu64(__m512i, __mmask8,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_madd52lo_epu64(__mmask8, __m512i,
		__m512i, __m512i);
	/*
	* Intrinsics related to the AVX512VBMI instructions.
	*/

	extern __m128i __ICL_INTRINCC _mm_permutexvar_epi8(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_permutexvar_epi8(__m128i, __mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_permutexvar_epi8(__mmask16, __m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_permutexvar_epi8(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_permutexvar_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutexvar_epi8(__mmask32, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_permutexvar_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutexvar_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutexvar_epi8(__mmask64, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_permutex2var_epi8(__m128i, __m128i /* idx */,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_permutex2var_epi8(__m128i, __mmask16,
		__m128i /* idx */,
		__m128i);
	extern __m128i __ICL_INTRINCC _mm_mask2_permutex2var_epi8(__m128i,
		__m128i /* idx */,
		__mmask16, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_permutex2var_epi8(__mmask16, __m128i,
		__m128i /* idx */,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_permutex2var_epi8(__m256i, __m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_permutex2var_epi8(__m256i, __mmask32,
		__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask2_permutex2var_epi8(__m256i, __m256i,
		__mmask32,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_permutex2var_epi8(__mmask32,
		__m256i, __m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_permutex2var_epi8(__m512i, __m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_permutex2var_epi8(__m512i, __mmask64,
		__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask2_permutex2var_epi8(__m512i, __m512i,
		__mmask64,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_permutex2var_epi8(__mmask64,
		__m512i, __m512i,
		__m512i);

	extern __m128i __ICL_INTRINCC _mm_multishift_epi64_epi8(__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_mask_multishift_epi64_epi8(__m128i,
		__mmask16,
		__m128i, __m128i);
	extern __m128i __ICL_INTRINCC _mm_maskz_multishift_epi64_epi8(__mmask16,
		__m128i,
		__m128i);
	extern __m256i __ICL_INTRINCC _mm256_multishift_epi64_epi8(__m256i, __m256i);
	extern __m256i __ICL_INTRINCC _mm256_mask_multishift_epi64_epi8(__m256i,
		__mmask32,
		__m256i,
		__m256i);
	extern __m256i __ICL_INTRINCC _mm256_maskz_multishift_epi64_epi8(__mmask32,
		__m256i,
		__m256i);
	extern __m512i __ICL_INTRINCC _mm512_multishift_epi64_epi8(__m512i, __m512i);
	extern __m512i __ICL_INTRINCC _mm512_mask_multishift_epi64_epi8(__m512i,
		__mmask64,
		__m512i,
		__m512i);
	extern __m512i __ICL_INTRINCC _mm512_maskz_multishift_epi64_epi8(__mmask64,
		__m512i,
		__m512i);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* _ZMMINTRIN_H_INCLUDED */