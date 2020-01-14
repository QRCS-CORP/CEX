#ifndef CEX_RAINBOWCORE_H
#define CEX_RAINBOWCORE_H

#include "CexConfig.h"
#include "BCG.h"
#include "IDrbg.h"
#include "IPrng.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "RainbowParameters.h"
#include "SHA2.h"

NAMESPACE_RAINBOW

using Cipher::SymmetricKey;
using Drbg::BCG;
using Drbg::IDrbg;
using Utility::IntegerTools;
using Prng::IPrng;
using Utility::MemoryTools;
using Enumeration::RainbowParameters;
using Digest::SHA2;

/// <summary>
/// The Rainbow support class
/// </summary>
class RainbowCore
{
private:

	// params.h

	/*!
\def RAINBOW_ALGNAME
* Read Only: The formal algorithm name
*/
#define RAINBOW_ALGNAME "RAINBOW"

/* the defined parameter */
#if !defined(RAINBOW_PARAM_S3) && !defined(RAINBOW_PARAM_S5)
#	define RAINBOW_PARAM_S1
//#	define RAINBOW_PARAM_S3
//#	define RAINBOW_PARAM_S5
#endif

/*!
\def RAINBOW_SEED_SIZE
* Read Only: The internal seed size in bytes
*/
#define RAINBOW_SEED_SIZE 48

/*!
\def RAINBOW_SIGNATURE_SIZE
* Read Only: The signature size in bytes
*/
#if defined(RAINBOW_PARAM_S1)
#	define RAINBOW_SIGNATURE_SIZE 97
#elif defined(RAINBOW_PARAM_S3)
#	define RAINBOW_SIGNATURE_SIZE 156
#elif defined(RAINBOW_PARAM_S5)
#	define RAINBOW_SIGNATURE_SIZE 204
#else
#	error The parameter set is invalid
#endif

	// rainbow_keypair.h

#if defined(RAINBOW_PARAM_S1) // dump this?
#	define RAINBOW_GFSIZE 256
#	define RAINBOW_V1 48
#	define RAINBOW_O1 32
#	define RAINBOW_O2 32
#	define RAINBOW_HASH_LEN 32
#elif defined(RAINBOW_PARAM_S3)
#	define RAINBOW_GFSIZE 256
#	define RAINBOW_V1 68
#	define RAINBOW_O1 36
#	define RAINBOW_O2 36
#	define RAINBOW_HASH_LEN 48
#elif defined(RAINBOW_PARAM_S5)
#	define RAINBOW_GFSIZE 256
#	define RAINBOW_V1 92
#	define RAINBOW_O1 48
#	define RAINBOW_O2 48
#	define RAINBOW_HASH_LEN 64
#else
#	error The parameter set is invalid
#endif

#define RAINBOW_V2 ((RAINBOW_V1) + (RAINBOW_O1))

/* size of N, in # of gf elements */
#define RAINBOW_PUB_N (RAINBOW_V1 + RAINBOW_O1 + RAINBOW_O2)

/* size of M, in # gf elements */
#define RAINBOW_PUB_M (RAINBOW_O1 + RAINBOW_O2)

/* size of variables, in # bytes */

/* GF256 */
#define RAINBOW_V1_BYTE (RAINBOW_V1)
#define RAINBOW_V2_BYTE (RAINBOW_V2)
#define RAINBOW_O1_BYTE (RAINBOW_O1)
#define RAINBOW_O2_BYTE (RAINBOW_O2)
#define RAINBOW_PUB_N_BYTE (RAINBOW_PUB_N)
#define RAINBOW_PUB_M_BYTE (RAINBOW_PUB_M)

/* length of seed for public key, in bytes */
#define RAINBOW_LEN_PKSEED 32

/* length of seed for secret key, in bytes */
#define RAINBOW_LEN_SKSEED 32

/* length of salt for a signature, in bytes */
#define RAINBOW_SALT_BYTE 16

/* length of a signature */
#define RAINBOW_SIGNATURE_BYTE (RAINBOW_PUB_N_BYTE + RAINBOW_SALT_BYTE )

#define RAINBOW_N_TRIANGLE_TERMS(n_var) (n_var*(n_var+1)/2)

/**
* \brief public key for classic rainbow
*
*  public key for classic rainbow
*/
	typedef struct rainbow_publickey
	{
		uint8_t pk[RAINBOW_PUB_M_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_PUB_N)];
	} pk_t;

	// TODO: public/private keys are too large! change to pointers and malloc in place..

	/**
	* \brief secret key for classic rainbow
	*
	* secret key for classic rainbow
	*/
	typedef struct rainbow_secretkey
	{
		/* seed for generating secret key.
		* Generating S, T, and F for classic rainbow.
		* Generating S and T only for cyclic rainbow. */
		uint8_t sk_seed[RAINBOW_LEN_SKSEED];
		/* part of S map */
		uint8_t s1[RAINBOW_O1_BYTE * RAINBOW_O2];
		/* part of T map */
		uint8_t t1[RAINBOW_V1_BYTE * RAINBOW_O1];
		/* part of T map */
		uint8_t t4[RAINBOW_V1_BYTE * RAINBOW_O2];
		/* part of T map */
		uint8_t t3[RAINBOW_O1_BYTE * RAINBOW_O2];
		/* part of C-map, F1, layer1 */
		uint8_t l1_F1[RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)];
		/* part of C-map, F2, layer1 */
		uint8_t l1_F2[RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1];
		/* part of C-map, F1, layer2 */
		uint8_t l2_F1[RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)];
		/* part of C-map, F2, layer2 */
		uint8_t l2_F2[RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1];
		/* part of C-map, F3, layer2 */
		uint8_t l2_F3[RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O2];
		/* part of C-map, F5, layer2 */
		uint8_t l2_F5[RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1)];
		/* part of C-map, F6, layer2 */
		uint8_t l2_F6[RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2];
	} sk_t;

	// rainbow_keypair_computation.h

/**
* \brief The (internal use) public key for rainbow
*
* The (internal use) public key for rainbow. The public
* polynomials are divided into l1_Q1, l1_Q2, ... l1_Q9,
* l2_Q1, .... , l2_Q9.
*/
	typedef struct rainbow_extend_publickey
	{
		uint8_t l1_Q1[RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)];
		uint8_t l1_Q2[RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1];
		uint8_t l1_Q3[RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O2];
		uint8_t l1_Q5[RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1)];
		uint8_t l1_Q6[RAINBOW_O1_BYTE * RAINBOW_O1 * RAINBOW_O2];
		uint8_t l1_Q9[RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O2)];

		uint8_t l2_Q1[RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)];
		uint8_t l2_Q2[RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1];
		uint8_t l2_Q3[RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O2];
		uint8_t l2_Q5[RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1)];
		uint8_t l2_Q6[RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2];
		uint8_t l2_Q9[RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O2)];
	} ext_cpk_t;


	/*!
	\def RAINBOW_PUBLICKEY_SIZE
	* Read Only: The public key size in bytes
	*/
#if defined(RAINBOW_PARAM_S1)
#	define RAINBOW_PUBLICKEY_SIZE sizeof(pk_t) //pk=404992, sk=277536
#elif defined(RAINBOW_PARAM_S3)
#	define RAINBOW_PUBLICKEY_SIZE 710640
#elif defined(RAINBOW_PARAM_S5)
#	define RAINBOW_PUBLICKEY_SIZE 1705536
#else
#	error The parameter set is invalid
#endif

	/*!
	\def RAINBOW_SECRETKEY_SIZE
	* Read Only: The private key size in bytes
	*/
#if defined(RAINBOW_PARAM_S1)
#	define RAINBOW_SECRETKEY_SIZE sizeof(sk_t)
#elif defined(RAINBOW_PARAM_S3)
#	define RAINBOW_SECRETKEY_SIZE 511448
#elif defined(RAINBOW_PARAM_S5)
#	define RAINBOW_SECRETKEY_SIZE 1227104
#else
#	error The parameter set is invalid
#endif


	// blas.h

	static inline uint8_t gf16v_get_ele(const uint8_t* a, uint32_t i)
	{
		/* get an element from GF(16) vector */

		uint8_t r;
		uint8_t r0;
		uint8_t r1;
		uint8_t m;

		r = a[i >> 1];
		r0 = r & 0x0F;
		r1 = r >> 4;
		m = (uint8_t)(~(i & 1) + 1);

		return (r1 & m) | ((~m) & r0);
	}

	static inline uint8_t gf16v_set_ele(uint8_t* a, uint32_t i, uint8_t v)
	{
		/* set an element for a GF(16) vector */

		uint8_t m;
		uint8_t airem;

		/* 1--> 0xf0 , 0--> 0x0f */
		m = 0x0F ^ (~(i & 1) + 1);
		/* erase */
		airem = a[i >> 1] & (~m);
		/* set */
		a[i >> 1] = airem | (m & (v << 4)) | (m & v & 0xf);

		return v;
	}

	static inline uint8_t gf256v_get_ele(const uint8_t* a, uint32_t i)
	{
		/* get an element from GF(256) vector */

		return a[i];
	}

	static inline uint8_t gf256v_set_ele(uint8_t* a, uint32_t i, uint8_t v)
	{
		/* set an element for a GF(256) vector */

		a[i] = v;

		return v;
	}

#ifdef CEX_ARCH_64

	static void gf256v_add_u32(uint8_t* accub, const uint8_t* a, size_t length)
	{
		uint32_t au32;
		uint32_t bu32;
		size_t i;
		size_t nu32;
		size_t rem;

		au32 = 0;
		bu32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			bu32 = le8to32(accub + i * sizeof(uint32_t));
			bu32 ^= au32;
			le32to8(accub + i * sizeof(uint32_t), bu32);
		}

		a += (nu32 << 2);
		accub += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			accub[i] ^= a[i];
		}
	}

	static void gf16v_madd_u32(uint8_t* accuc, const uint8_t* a, uint8_t gf16b, size_t length)
	{
		uint32_t au32;
		uint32_t cu32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			cu32 = le8to32(accuc + i * sizeof(uint32_t));
			cu32 ^= gf16v_mul_u32(au32, gf16b);
			le32to8(accuc + i * sizeof(uint32_t), cu32);
		}

		accuc += (nu32 << 2);
		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf16v_mul_u32(tmp32, gf16b);

		for (i = 0; i < rem; ++i)
		{
			accuc[i] ^= (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_madd_u32(uint8_t* accuc, const uint8_t* a, uint8_t gf256b, size_t length)
	{
		uint32_t au32;
		uint32_t cu32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			cu32 = le8to32(accuc + i * sizeof(uint32_t));
			cu32 ^= gf256v_mul_u32(au32, gf256b);
			le32to8(accuc + i * sizeof(uint32_t), cu32);
		}

		accuc += (nu32 << 2);
		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf256v_mul_u32(tmp32, gf256b);

		for (i = 0; i < rem; ++i)
		{
			accuc[i] ^= (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf16v_mul_scalar_u32(uint8_t* a, uint8_t gf16b, size_t length)
	{
		uint32_t au32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		nu32 = length >> 2;
		tmp32 = 0;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			au32 = gf16v_mul_u32(au32, gf16b);
			le32to8(a + i * sizeof(uint32_t), au32);
		}

		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf16v_mul_u32(tmp32, gf16b);

		for (i = 0; i < rem; ++i)
		{
			a[i] = (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_mul_scalar_u32(uint8_t* a, uint8_t b, size_t length)
	{
		uint32_t au32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			au32 = gf256v_mul_u32(au32, b);
			le32to8(a + i * sizeof(uint32_t), au32);
		}

		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf256v_mul_u32(tmp32, b);

		for (i = 0; i < rem; ++i)
		{
			a[i] = (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_predicated_add_u32(uint8_t* accub, uint8_t predicate, const uint8_t* a, size_t length)
	{
		uint32_t au32;
		uint32_t bu32;
		uint32_t pru32;
		uint32_t rem;
		uint8_t pru8;
		size_t i;
		size_t nu32;

		pru32 = 0UL - ((uint32_t)predicate);
		pru8 = pru32 & 0xff;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			bu32 = le8to32(accub + i * sizeof(uint32_t));
			bu32 ^= (au32 & pru32);
			le32to8(accub + i * sizeof(uint32_t), bu32);
		}

		a += (nu32 << 2);
		accub += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			accub[i] ^= (a[i] & pru8);
		}
	}

	static void gf256v_add(uint8_t* accub, const uint8_t* a, size_t length)
	{
		uint64_t au64;
		uint64_t bu64;
		size_t i;
		size_t nu64;
		size_t rem;

		au64 = 0;
		bu64 = 0;
		nu64 = length >> 3;

		for (i = 0; i < nu64; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			bu64 = le8to64(accub + i * sizeof(uint64_t));
			bu64 ^= au64;
			le64to8(accub + i * sizeof(uint64_t), bu64);
		}

		a += (nu64 << 3);
		accub += (nu64 << 3);
		rem = length & 7;

		if (rem)
		{
			gf256v_add_u32(accub, a, rem);
		}
	}

	static uint8_t gf16v_dot(const uint8_t* a, const uint8_t* b, size_t length)
	{
		uint64_t au64;
		uint64_t bu64;
		uint64_t r;
		size_t i;
		size_t nu64;
		size_t rem;

		au64 = 0;
		bu64 = 0;
		nu64 = length >> 3;
		r = 0;

		for (i = 0; i < nu64; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			bu64 = le8to64(b + i * sizeof(uint64_t));
			r ^= gf16v_mul_u64_u64(au64, bu64);
		}

		rem = length & 7;

		if (rem)
		{
			au64 = 0;
			bu64 = 0;

			for (i = 0; i < rem; ++i)
			{
				au64 |= ((uint64_t)a[(nu64 << 3) + i] << (i * 8));
			}

			for (i = 0; i < rem; ++i)
			{
				bu64 |= ((uint64_t)b[(nu64 << 3) + i] << (i * 8));
			}

			r ^= gf16v_mul_u64_u64(au64, bu64);
		}

		return gf16v_reduce_u64(r);
	}

	static void gf16v_madd(uint8_t* accuc, const uint8_t* a, uint8_t b, size_t length)
	{
		uint64_t au64;
		uint64_t cu64;
		size_t i;
		size_t num;
		size_t numb;
		size_t st;

		au64 = 0;
		cu64 = 0;
		num = length >> 3;

		for (i = 0; i < num; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			cu64 = le8to64(accuc + i * sizeof(uint64_t));
			cu64 ^= gf16v_mul_u64(au64, b);
			le64to8(accuc + i * sizeof(uint64_t), cu64);
		}

		numb = length & 0x7;
		st = num << 3;

		if (numb)
		{
			gf16v_madd_u32(accuc + st, a + st, b, numb);
		}
	}

	static void gf256v_madd(uint8_t* accuc, const uint8_t* a, uint8_t b, size_t length)
	{
		uint64_t au64;
		uint64_t cu64;
		size_t i;
		size_t num;
		size_t numb;
		size_t st;

		au64 = 0;
		cu64 = 0;
		num = length >> 3;

		for (i = 0; i < num; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			cu64 = le8to64(accuc + i * sizeof(uint64_t));
			cu64 ^= gf256v_mul_u64(au64, b);
			le64to8(accuc + i * sizeof(uint64_t), cu64);
		}

		numb = length & 0x7;
		st = num << 3;

		if (numb)
		{
			gf256v_madd_u32(accuc + st, a + st, b, numb);
		}
	}

	static void gf16v_mul_scalar(uint8_t* a, uint8_t b, size_t length)
	{
		uint64_t au64;
		size_t i;
		size_t num;
		size_t numb;
		size_t st;

		au64 = 0;
		num = length >> 3;

		for (i = 0; i < num; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			au64 = gf16v_mul_u64(au64, b);
			le64to8(a + i * sizeof(uint64_t), au64);
		}

		numb = length & 0x7;
		st = num << 3;
		a += st;

		if (numb)
		{
			gf16v_mul_scalar_u32(a, b, numb);
		}
	}

	static void gf256v_mul_scalar(uint8_t* a, uint8_t b, size_t length)
	{
		uint64_t au64;
		size_t i;
		size_t num;
		size_t numb;
		size_t st;

		au64 = 0;
		num = length >> 3;

		for (i = 0; i < num; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			au64 = gf256v_mul_u64(au64, b);
			le64to8(a + i * sizeof(uint64_t), au64);
		}

		numb = length & 0x7;
		st = num << 3;

		if (numb)
		{
			gf256v_mul_scalar_u32(a + st, b, numb);
		}
	}

	static void gf256v_predicated_add(uint8_t* accub, uint8_t predicate, const uint8_t* a, size_t length)
	{
		uint64_t au64;
		uint64_t bu64;
		uint64_t pr64 = (0ULL - (uint64_t)predicate);
		size_t i;
		size_t nu64;
		size_t rem;

		au64 = 0;
		bu64 = 0;
		nu64 = length >> 3;

		for (i = 0; i < nu64; ++i)
		{
			au64 = le8to64(a + i * sizeof(uint64_t));
			bu64 = le8to64(accub + i * sizeof(uint64_t));
			bu64 ^= (au64 & pr64);
			le64to8(accub + i * sizeof(uint64_t), bu64);
		}

		a += (nu64 << 3);
		accub += (nu64 << 3);
		rem = length & 7;

		if (rem)
		{
			gf256v_predicated_add_u32(accub, predicate, a, rem);
		}
	}

#else

	static void gf256v_add(uint8_t* accub, const uint8_t* a, size_t length)
	{
		uint32_t au32;
		uint32_t bu32;
		size_t i;
		size_t nu32;
		size_t rem;

		au32 = 0;
		bu32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			bu32 = le8to32(accub + i * sizeof(uint32_t));
			bu32 ^= au32;
			le32to8(accub + i * sizeof(uint32_t), bu32);
		}

		a += (nu32 << 2);
		accub += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			accub[i] ^= a[i];
		}
	}

	static uint8_t gf16v_dot(const uint8_t* a, const uint8_t* b, size_t length)
	{
		uint32_t au32;
		uint32_t bu32;
		size_t i;
		size_t nu32;
		uint32_t r;
		uint32_t rem;

		au32 = 0;
		bu32 = 0;
		nu32 = length >> 2;
		r = 0;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			bu32 = le8to32(b + i * sizeof(uint32_t));
			r ^= gf16v_mul_u32_u32(au32, bu32);
		}

		rem = length & 3;

		if (rem != 0)
		{
			for (i = 0; i < rem; ++i)
			{
				au32 |= ((uint32_t)a[(nu32 << 2) + i] << (i * 8));
			}

			for (i = 0; i < rem; ++i)
			{
				bu32 |= ((uint32_t)a[(nu32 << 2) + i] << (i * 8));
			}

			r ^= gf16v_mul_u32_u32(au32, bu32);
		}

		return gf16v_reduce_u32(r);
	}

	static void gf16v_madd(uint8_t* accuc, const uint8_t* a, uint8_t gf16b, size_t length)
	{
		uint32_t au32;
		uint32_t cu32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			cu32 = le8to32(accuc + i * sizeof(uint32_t));
			cu32 ^= gf16v_mul_u32(au32, gf16b);
			le32to8(accuc + i * sizeof(uint32_t), cu32);
		}

		accuc += (nu32 << 2);
		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf16v_mul_u32(tmp32, gf16b);

		for (i = 0; i < rem; ++i)
		{
			accuc[i] ^= (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_madd(uint8_t* accuc, const uint8_t* a, uint8_t gf256b, size_t length)
	{
		uint32_t au32;
		uint32_t cu32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			cu32 = le8to32(accuc + i * sizeof(uint32_t));
			cu32 ^= gf256v_mul_u32(au32, gf256b);
			le32to8(accuc + i * sizeof(uint32_t), cu32);
		}

		accuc += (nu32 << 2);
		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf256v_mul_u32(tmp32, gf256b);

		for (i = 0; i < rem; ++i)
		{
			accuc[i] ^= (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf16v_mul_scalar(uint8_t* a, uint8_t gf16b, size_t length)
	{
		uint32_t au32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		nu32 = length >> 2;
		tmp32 = 0;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			au32 = gf16v_mul_u32(au32, gf16b);
			le32to8(a + i * sizeof(uint32_t), au32);
		}

		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf16v_mul_u32(tmp32, gf16b);

		for (i = 0; i < rem; ++i)
		{
			a[i] = (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_mul_scalar(uint8_t* a, uint8_t b, size_t length)
	{
		uint32_t au32;
		uint32_t rem;
		uint32_t tmp32;
		size_t i;
		size_t nu32;

		tmp32 = 0;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			au32 = gf256v_mul_u32(au32, b);
			le32to8(a + i * sizeof(uint32_t), au32);
		}

		a += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			tmp32 |= ((uint32_t)a[i] << (i * 8));
		}

		tmp32 = gf256v_mul_u32(tmp32, b);

		for (i = 0; i < rem; ++i)
		{
			a[i] = (tmp32 >> (i * 8)) & 0xFF;
		}
	}

	static void gf256v_predicated_add(uint8_t* accub, uint8_t predicate, const uint8_t* a, size_t length)
	{
		uint32_t au32;
		uint32_t bu32;
		uint32_t pru32;
		uint32_t rem;
		uint8_t pru8;
		size_t i;
		size_t nu32;

		pru32 = 0UL - ((uint32_t)predicate);
		pru8 = pru32 & 0xff;
		nu32 = length >> 2;

		for (i = 0; i < nu32; ++i)
		{
			au32 = le8to32(a + i * sizeof(uint32_t));
			bu32 = le8to32(accub + i * sizeof(uint32_t));
			bu32 ^= (au32 & pru32);
			le32to8(accub + i * sizeof(uint32_t), bu32);
		}

		a += (nu32 << 2);
		accub += (nu32 << 2);
		rem = length & 3;

		for (i = 0; i < rem; ++i)
		{
			accub[i] ^= (a[i] & pru8);
		}
	}

#endif

	// blas.c

	static void gf256v_set_zero(uint8_t* b, uint32_t count)
	{
		gf256v_add(b, b, count);
	}

	static uint32_t gf256v_is_zero(const uint8_t* a, uint32_t count)
	{
		uint8_t r;

		r = 0;

		while (count != 0)
		{
			--count;
			r |= a[0];
			++a;
		}

		return (r == 0);
	}

	static void gf256v_polymul(uint8_t* c, const uint8_t* a, const uint8_t* b, uint32_t count)
	{
		size_t i;

		gf256v_set_zero(c, (count * 2) - 1);

		for (i = 0; i < count; ++i)
		{
			gf256v_madd(c + i, a, b[i], count);
		}
	}

	static void gf16mat_prod_ref(uint8_t* c, const uint8_t* mata, uint32_t na, uint32_t nawidth, const uint8_t* b)
	{
		uint8_t bb;
		size_t i;

		gf256v_set_zero(c, na);

		for (i = 0; i < nawidth; ++i)
		{
			bb = gf16v_get_ele(b, (uint32_t)i);
			gf16v_madd(c, mata, bb, na);
			mata += na;
		}
	}

	static void gf256mat_prod_ref(uint8_t* c, const uint8_t* mata, uint32_t na, uint32_t nawidth, const uint8_t* b)
	{
		size_t i;

		gf256v_set_zero(c, na);

		for (i = 0; i < nawidth; ++i)
		{
			gf256v_madd(c, mata, b[i], na);
			mata += na;
		}
	}

	static void gf16mat_mul(uint8_t* c, const uint8_t* a, const uint8_t* b, size_t length)
	{
		uint8_t bb;
		size_t i;
		size_t k;
		uint32_t nvec;

		nvec = (uint32_t)(length + 1) / 2;

		for (k = 0; k < length; ++k)
		{
			gf256v_set_zero(c, nvec);
			const uint8_t *bk = b + (nvec * k);

			for (i = 0; i < length; i++)
			{
				bb = gf16v_get_ele(bk, (uint32_t)i);
				gf16v_madd(c, a + nvec * i, bb, nvec);
			}

			c += nvec;
		}
	}

	static void gf256mat_mul(uint8_t* c, const uint8_t* a, const uint8_t* b, size_t length)
	{
		size_t i;
		size_t k;
		size_t nvec;

		nvec = length;

		for (k = 0; k < length; ++k)
		{
			gf256v_set_zero(c, (uint32_t)nvec);
			const uint8_t *bk = b + nvec * k;

			for (i = 0; i < length; ++i)
			{
				gf256v_madd(c, a + nvec * i, bk[i], nvec);
			}

			c += nvec;
		}
	}

	static uint32_t gf16mat_gauss_elim_ref(uint8_t* mat, uint32_t h, uint32_t w)
	{
		uint32_t r8;
		size_t offset;
		size_t i;
		size_t j;
		size_t nw;
		uint8_t pivot;

		nw = (w + 1) / 2;
		r8 = 1;

		for (i = 0; i < h; ++i)
		{
			offset = i >> 1;
			uint8_t *ai = mat + nw * i;

			for (j = i + 1; j < h; ++j)
			{
				uint8_t *aj = mat + (nw * j);
				gf256v_predicated_add(ai + offset, !gf16_is_nonzero(gf16v_get_ele(ai, (uint32_t)i)), aj + offset, nw - offset);
			}

			pivot = gf16v_get_ele(ai, (uint32_t)i);
			r8 &= gf16_is_nonzero(pivot);
			pivot = gf16_inv(pivot);
			offset = (i + 1) >> 1;
			gf16v_mul_scalar(ai + offset, pivot, nw - offset);

			for (j = 0; j < h; ++j)
			{
				if (i == j)
				{
					continue;
				}

				uint8_t *aj = mat + (nw * j);
				gf16v_madd(aj + offset, ai + offset, gf16v_get_ele(aj, (uint32_t)i), nw - offset);
			}
		}

		return r8;
	}

	static uint32_t gf16mat_solve_linear_eq_ref(uint8_t* sol, const uint8_t* inpmat, const uint8_t* cterms, uint32_t n)
	{
		uint8_t mat[64 * 33];
		size_t i;
		size_t nbyte;
		uint32_t r8;

		nbyte = (n + 1) >> 1;

		for (i = 0; i < n; ++i)
		{
			memcpy(mat + i * (nbyte + 1), inpmat + i * nbyte, nbyte);
			mat[i * (nbyte + 1) + nbyte] = gf16v_get_ele(cterms, (uint32_t)i);
		}

		r8 = gf16mat_gauss_elim(mat, n, n + 2);

		for (i = 0; i < n; ++i)
		{
			gf16v_set_ele(sol, (uint32_t)i, mat[i * (nbyte + 1) + nbyte]);
		}

		return r8;
	}

	static inline void gf16mat_submat(uint8_t* mat2, uint32_t w2, uint32_t st, const uint8_t* mat, uint32_t w, uint32_t h)
	{
		size_t i;
		size_t j;
		uint32_t nbytew1;
		uint32_t nbytew2;
		uint32_t st2;

		nbytew1 = (w + 1) / 2;
		nbytew2 = (w2 + 1) / 2;
		st2 = st / 2;

		for (i = 0; i < h; ++i)
		{
			for (j = 0; j < nbytew2; ++j)
			{
				mat2[(i * nbytew2) + j] = mat[(i * nbytew1) + st2 + j];
			}
		}
	}

	static uint32_t gf16mat_inv(uint8_t* inva, const uint8_t* a, uint32_t h, uint8_t* buffer)
	{
		uint8_t *aa = buffer;
		size_t i;
		size_t nw;
		uint8_t r8;

		nw = (h + 1) / 2;

		for (i = 0; i < h; ++i)
		{
			uint8_t *ai = aa + i * 2 * nw;
			gf256v_set_zero(ai, 2 * (uint32_t)nw);
			gf256v_add(ai, a + i * nw, nw);
			gf16v_set_ele(ai + nw, (uint32_t)i, 1);
		}

		r8 = gf16mat_gauss_elim(aa, h, 2 * h);
		gf16mat_submat(inva, h, h, aa, 2 * h, h);

		return r8;
	}

	static uint32_t gf256mat_gauss_elim_ref(uint8_t* mat, uint32_t h, uint32_t w)
	{
		size_t i;
		size_t j;
		uint32_t align4;
		uint32_t r8;
		uint8_t pivot;

		r8 = 1;

		for (i = 0; i < h; ++i)
		{
			uint8_t* ai = mat + i * w;
			align4 = i & (~0x3);

			for (j = i + 1; j < h; ++j)
			{
				uint8_t* aj = mat + j * w;
				gf256v_predicated_add(ai + align4, !gf256_is_nonzero(ai[i]), aj + align4, w - align4);
			}

			r8 &= gf256_is_nonzero(ai[i]);
			pivot = ai[i];
			pivot = gf256_inv(pivot);
			gf256v_mul_scalar(ai + align4, pivot, w - align4);

			for (j = 0; j < h; ++j)
			{
				if (i == j)
				{
					continue;
				}

				uint8_t* aj = mat + j * w;
				gf256v_madd(aj + align4, ai + align4, aj[i], w - align4);
			}
		}

		return r8;
	}

	static uint32_t gf256mat_solve_linear_eq_ref(uint8_t* sol, const uint8_t* inpmat, const uint8_t* cterms, uint32_t n)
	{
		uint8_t mat[64 * 64];
		size_t i;
		uint32_t r8;

		for (i = 0; i < n; ++i)
		{
			memcpy(mat + i * (n + 1), inpmat + i * n, n);
			mat[i * (n + 1) + n] = cterms[i];
		}

		r8 = gf256mat_gauss_elim(mat, n, n + 1);

		for (i = 0; i < n; ++i)
		{
			sol[i] = mat[i * (n + 1) + n];
		}

		return r8;
	}

	static inline void gf256mat_submat(uint8_t* mat2, uint32_t w2, uint32_t st, const uint8_t* mat, uint32_t w, uint32_t h)
	{
		size_t i;
		size_t j;

		for (i = 0; i < h; ++i)
		{
			for (j = 0; j < w2; ++j)
			{
				mat2[(i * w2) + j] = mat[(i * w) + st + j];
			}
		}
	}

	static uint32_t gf256mat_inv(uint8_t* inva, const uint8_t* a, uint32_t h, uint8_t* buffer)
	{
		uint8_t* aa = buffer;
		size_t i;
		uint8_t r8;

		for (i = 0; i < h; ++i)
		{
			uint8_t* ai = aa + i * 2 * h;
			gf256v_set_zero(ai, 2 * h);
			gf256v_add(ai, a + i * h, h);
			ai[h + i] = 1;
		}

		r8 = gf256mat_gauss_elim(aa, h, 2 * h);
		gf256mat_submat(inva, h, h, aa, 2 * h, h);

		return r8;
	}

	static void gf16mat_prod(uint8_t* c, const uint8_t* mata, uint32_t na, uint32_t nawidth, const uint8_t* b)
	{
		gf16mat_prod_ref(c, mata, na, nawidth, b);
	}

	static unsigned gf16mat_gauss_elim(uint8_t* mat, uint32_t h, uint32_t w)
	{
		return gf16mat_gauss_elim_ref(mat, h, w);
	}

	static unsigned gf16mat_solve_linear_eq(uint8_t* sol, const uint8_t* inpmat, const uint8_t* cterms, uint32_t n)
	{
		return gf16mat_solve_linear_eq_ref(sol, inpmat, cterms, n);
	}

	static void gf256mat_prod(uint8_t* c, const uint8_t* mata, uint32_t na, uint32_t nawidth, const uint8_t* b)
	{
		gf256mat_prod_ref(c, mata, na, nawidth, b);
	}

	static unsigned gf256mat_gauss_elim(uint8_t* mat, uint32_t h, uint32_t w)
	{
		return gf256mat_gauss_elim_ref(mat, h, w);
	}

	static unsigned gf256mat_solve_linear_eq(uint8_t* sol, const uint8_t* inpmat, const uint8_t* cterms, uint32_t n)
	{
		return gf256mat_solve_linear_eq_ref(sol, inpmat, cterms, n);
	}

	// gf16.h

	static inline uint8_t gf4_mul_2(uint8_t a)
	{
		/* gf4 := gf2[x]/x^2+x+1 */
		uint8_t r;

		r = a << 1;
		r ^= (a >> 1) * 7;

		return r;
	}

	static inline uint8_t gf4_mul_3(uint8_t a)
	{
		uint8_t msk;

		msk = (a - 2) >> 1;

		return (msk & (a * 3)) | ((~msk) & (a - 1));
	}

	static inline uint8_t gf4_mul(uint8_t a, uint8_t b)
	{
		uint8_t r;

		r = a * (b & 1);

		return r ^ (gf4_mul_2(a) * (b >> 1));
	}

	static inline uint8_t gf4_squ(uint8_t a)
	{
		return a ^ (a >> 1);
	}

	static inline uint8_t gf4_inv(uint8_t a)
	{
		return a ^ (a >> 1);
	}

	static inline uint32_t gf4v_mul_2_u32(uint32_t a)
	{
		uint32_t bit0;
		uint32_t bit1;

		bit0 = a & 0x55555555UL;
		bit1 = a & 0xAAAAAAAAUL;

		return (bit0 << 1) ^ bit1 ^ (bit1 >> 1);
	}

	static inline uint32_t gf4v_mul_3_u32(uint32_t a)
	{
		uint32_t bit0;
		uint32_t bit1;

		bit0 = a & 0x55555555UL;
		bit1 = a & 0xAAAAAAAAUL;

		return (bit0 << 1) ^ bit0 ^ (bit1 >> 1);
	}

	static inline uint32_t gf4v_mul_u32(uint32_t a, uint8_t b)
	{
		uint32_t bitb0;
		uint32_t bitb1;

		bitb0 = 0UL - ((uint32_t)(b & 1));
		bitb1 = 0UL - ((uint32_t)((b >> 1) & 1));

		return (a & bitb0) ^ (bitb1 & gf4v_mul_2_u32(a));
	}

	static inline uint32_t gf4v_mulh_u32_u32(uint32_t a0, uint32_t a1, uint32_t b0, uint32_t b1)
	{
		uint32_t c0;
		uint32_t c1;
		uint32_t c2;

		c0 = a0 & b0;
		c2 = a1 & b1;
		c1 = (a0 ^ a1) & (b0 ^ b1);

		return ((c1 ^ c0) << 1) ^ c0 ^ c2;
	}

	static inline uint32_t gf4v_mul_u32_u32(uint32_t a, uint32_t b)
	{
		uint32_t a0;
		uint32_t a1;
		uint32_t b0;
		uint32_t b1;

		a0 = a & 0x55555555UL;
		a1 = (a >> 1) & 0x55555555UL;
		b0 = b & 0x55555555UL;
		b1 = (b >> 1) & 0x55555555UL;

		return gf4v_mulh_u32_u32(a0, a1, b0, b1);
	}

	static inline uint32_t gf4v_squ_u32(uint32_t a)
	{
		uint32_t bit1;

		bit1 = a & 0xAAAAAAAAUL;

		return a ^ (bit1 >> 1);
	}

	static inline uint8_t gf16_is_nonzero(uint8_t a)
	{
		uint32_t a4;
		uint32_t r;

		a4 = a & 0x0F;
		r = 0UL - a4;
		r >>= 4;

		return r & 1;
	}

	static inline uint8_t gf16_mul(uint8_t a, uint8_t b)
	{
		/* gf16 := gf4[y]/y^2+y+x */

		uint8_t a0;
		uint8_t a1;
		uint8_t b0;
		uint8_t b1;
		uint8_t a0b0;
		uint8_t a1b1;
		uint8_t a0b1a1b0;
		uint8_t a1b1x2;

		a0 = a & 3;
		a1 = (a >> 2);
		b0 = b & 3;
		b1 = (b >> 2);
		a0b0 = gf4_mul(a0, b0);
		a1b1 = gf4_mul(a1, b1);
		a0b1a1b0 = gf4_mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1;
		a1b1x2 = gf4_mul_2(a1b1);

		return ((a0b1a1b0 ^ a1b1) << 2) ^ a0b0 ^ a1b1x2;
	}

	static inline uint8_t gf16_squ(uint8_t a)
	{
		uint8_t a0;
		uint8_t a1;
		uint8_t a1squx2;

		a0 = a & 3;
		a1 = (a >> 2);
		a1 = gf4_squ(a1);
		a1squx2 = gf4_mul_2(a1);

		return (a1 << 2) ^ a1squx2 ^ gf4_squ(a0);
	}

	static inline uint8_t gf16_inv(uint8_t a)
	{
		uint8_t a2;
		uint8_t a4;
		uint8_t a8;
		uint8_t a6;

		a2 = gf16_squ(a);
		a4 = gf16_squ(a2);
		a8 = gf16_squ(a4);
		a6 = gf16_mul(a4, a2);

		return gf16_mul(a8, a6);
	}

	static inline uint8_t gf16_mul_4(uint8_t a)
	{
		return (((a << 2) ^ a) & (8 + 4)) ^ gf4_mul_2(a >> 2);
	}

	static inline uint8_t gf16_mul_8(uint8_t a)
	{
		uint8_t a0;
		uint8_t a1;

		a0 = a & 3;
		a1 = a >> 2;

		return (gf4_mul_2(a0 ^ a1) << 2) | gf4_mul_3(a1);
	}

	static inline uint32_t gf16v_mul_u32(uint32_t a, uint8_t b)
	{
		/* gf16 := gf4[y]/y^2+y+x */

		uint32_t axb0;
		uint32_t axb1;
		uint32_t a0b1;
		uint32_t a1b1;
		uint32_t a1b12;

		axb0 = gf4v_mul_u32(a, b);
		axb1 = gf4v_mul_u32(a, b >> 2);
		a0b1 = (axb1 << 2) & 0xCCCCCCCCUL;
		a1b1 = axb1 & 0xCCCCCCCCUL;
		a1b12 = a1b1 >> 2;

		return axb0 ^ a0b1 ^ a1b1 ^ gf4v_mul_2_u32(a1b12);
	}

	static inline uint32_t gf16v_mulh_u32_u32(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t b0, uint32_t b1, uint32_t b2, uint32_t b3)
	{
		/* GF(4) x2: (bit0<<1)^bit1^(bit1>>1); */

		uint32_t c0;
		uint32_t c1;
		uint32_t c2x0;
		uint32_t c2x2;
		uint32_t c2x1;
		uint32_t c2r0;
		uint32_t c2r1;

		c0 = gf4v_mulh_u32_u32(a0, a1, b0, b1);
		c1 = gf4v_mulh_u32_u32(a0 ^ a2, a1 ^ a3, b0 ^ b2, b1 ^ b3);
		c2x0 = a2 & b2;
		c2x2 = a3 & b3;
		c2x1 = (a2 ^ a3) & (b2 ^ b3);
		c2r0 = c2x0 ^ c2x2;
		c2r1 = c2x0 ^ c2x1;

		return ((c1 ^ c0) << 2) ^ c0 ^ (c2r0 << 1) ^ c2r1 ^ (c2r1 << 1);
	}

	static inline uint32_t gf16v_mul_u32_u32(uint32_t a, uint32_t b)
	{
		uint32_t a0;
		uint32_t a1;
		uint32_t a2;
		uint32_t a3;
		uint32_t b0;
		uint32_t b1;
		uint32_t b2;
		uint32_t b3;

		a0 = a & 0x11111111UL;
		a1 = (a >> 1) & 0x11111111UL;
		a2 = (a >> 2) & 0x11111111UL;
		a3 = (a >> 3) & 0x11111111UL;
		b0 = b & 0x11111111UL;
		b1 = (b >> 1) & 0x11111111UL;
		b2 = (b >> 2) & 0x11111111UL;
		b3 = (b >> 3) & 0x11111111UL;

		return gf16v_mulh_u32_u32(a0, a1, a2, a3, b0, b1, b2, b3);
	}

	static inline uint8_t gf256v_reduce_u32(uint32_t a)
	{
		uint16_t aa[2] = { 0 };
		uint8_t rr[2] = { 0 };
		uint16_t r;

		aa[0] = a & 0xFFFFU;
		aa[1] = (a >> 16) & 0xFFFFU;
		r = aa[0] ^ aa[1];
		le16to8(rr, r);

		return rr[0] ^ rr[1];
	}

	static inline uint8_t gf16v_reduce_u32(uint32_t a)
	{
		uint8_t r256;

		r256 = gf256v_reduce_u32(a);

		return (r256 & 0xf) ^ (r256 >> 4);
	}

	static inline uint32_t gf16v_squ_u32(uint32_t a)
	{
		uint32_t a2;

		a2 = gf4v_squ_u32(a);

		return a2 ^ gf4v_mul_2_u32((a2 >> 2) & 0x33333333UL);
	}

	static inline uint32_t gf16v_mul_8_u32(uint32_t a)
	{
		uint32_t a1;
		uint32_t a0;

		a1 = a & 0xCCCCCCCCUL;
		a0 = (a << 2) & 0xCCCCCCCCUL;

		return gf4v_mul_2_u32(a0 ^ a1) | gf4v_mul_3_u32(a1 >> 2);
	}

	static inline uint8_t gf256_is_nonzero(uint8_t a)
	{
		uint32_t a8;
		uint32_t r;

		a8 = a;
		r = 0UL - a8;
		r >>= 8;

		return r & 1;
	}

	static inline uint8_t gf256_mul(uint8_t a, uint8_t b)
	{
		/* gf256 := gf16[X]/X^2+X+xy */

		uint8_t a0;
		uint8_t a1;
		uint8_t b0;
		uint8_t b1;
		uint8_t a0b0;
		uint8_t a1b1;
		uint8_t a0b1a1b0;
		uint8_t a1b1x8;

		a0 = a & 15;
		a1 = (a >> 4);
		b0 = b & 15;
		b1 = (b >> 4);
		a0b0 = gf16_mul(a0, b0);
		a1b1 = gf16_mul(a1, b1);
		a0b1a1b0 = gf16_mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1;
		a1b1x8 = gf16_mul_8(a1b1);

		return ((a0b1a1b0 ^ a1b1) << 4) ^ a0b0 ^ a1b1x8;
	}

	static inline uint8_t gf256_mul_gf16(uint8_t a, uint8_t gf16_b)
	{
		uint8_t a0;
		uint8_t a1;
		uint8_t b0;
		uint8_t a0b0;
		uint8_t a1b0;

		a0 = a & 15;
		a1 = (a >> 4);
		b0 = gf16_b & 15;
		a0b0 = gf16_mul(a0, b0);
		a1b0 = gf16_mul(a1, b0);

		return a0b0 ^ (a1b0 << 4);
	}

	static inline uint8_t gf256_squ(uint8_t a)
	{
		uint8_t a0;
		uint8_t a1;
		uint8_t a1squx8;

		a0 = a & 15;
		a1 = (a >> 4);
		a1 = gf16_squ(a1);
		a1squx8 = gf16_mul_8(a1);

		return (a1 << 4) ^ a1squx8 ^ gf16_squ(a0);
	}

	static inline uint8_t gf256_inv(uint8_t a)
	{
		/* 128+64+32+16+8+4+2 = 254 */

		uint8_t a2;
		uint8_t a4;
		uint8_t a8;
		uint8_t a4x2;
		uint8_t a8x4x2;
		uint8_t a64;
		uint8_t a64x2;
		uint8_t a128;

		a2 = gf256_squ(a);
		a4 = gf256_squ(a2);
		a8 = gf256_squ(a4);
		a4x2 = gf256_mul(a4, a2);
		a8x4x2 = gf256_mul(a4x2, a8);
		a64 = gf256_squ(a8x4x2);
		a64 = gf256_squ(a64);
		a64 = gf256_squ(a64);
		a64x2 = gf256_mul(a64, a8x4x2);
		a128 = gf256_squ(a64x2);

		return gf256_mul(a2, a128);
	}

	static inline uint32_t gf256v_mul_u32(uint32_t a, uint8_t b)
	{
		uint32_t axb0;
		uint32_t axb1;
		uint32_t a0b1;
		uint32_t a1b1;
		uint32_t a1b1x4;

		axb0 = gf16v_mul_u32(a, b);
		axb1 = gf16v_mul_u32(a, b >> 4);
		a0b1 = (axb1 << 4) & 0xF0F0F0F0UL;
		a1b1 = axb1 & 0xF0F0F0F0UL;
		a1b1x4 = a1b1 >> 4;

		return axb0 ^ a0b1 ^ a1b1 ^ gf16v_mul_8_u32(a1b1x4);
	}

	static inline uint32_t gf256v_squ_u32(uint32_t a)
	{
		uint32_t a2;
		uint32_t ar;

		a2 = gf16v_squ_u32(a);
		ar = (a2 >> 4) & 0x0F0F0F0FUL;

		return a2 ^ gf16v_mul_8_u32(ar);
	}

	static inline uint32_t gf256v_mul_gf16_u32(uint32_t a, uint8_t gf16_b)
	{
		return gf16v_mul_u32(a, gf16_b);
	}

	// gf16_u64.h

	static inline uint64_t gf4v_mul_2_u64(uint64_t a)
	{
		uint64_t bit0;
		uint64_t bit1;

		bit0 = a & 0x5555555555555555ULL;
		bit1 = a & 0xAAAAAAAAAAAAAAAAULL;

		return (bit0 << 1) ^ bit1 ^ (bit1 >> 1);
	}

	static inline uint64_t gf4v_mul_3_u64(uint64_t a)
	{
		uint64_t bit0;
		uint64_t bit1;

		bit0 = a & 0x5555555555555555ULL;
		bit1 = a & 0xAAAAAAAAAAAAAAAAULL;

		return (bit0 << 1) ^ bit0 ^ (bit1 >> 1);
	}

	static inline uint64_t gf4v_mul_u64(uint64_t a, uint8_t b)
	{
		uint64_t bitb0;
		uint64_t bitb1;

		bitb0 = 0ULL - ((uint64_t)(b & 1));
		bitb1 = 0ULL - ((uint64_t)((b >> 1) & 1));

		return (a & bitb0) ^ (bitb1 & gf4v_mul_2_u64(a));
	}

	static inline uint64_t gf4v_mulh_u64_u64(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1)
	{
		uint64_t c0;
		uint64_t c1;
		uint64_t c2;

		c0 = a0 & b0;
		c2 = a1 & b1;
		c1 = (a0 ^ a1) & (b0 ^ b1);

		return ((c1 ^ c0) << 1) ^ c0 ^ c2;
	}

	static inline uint64_t gf4v_mul_u64_u64(uint64_t a, uint64_t b)
	{
		uint64_t a0;
		uint64_t a1;
		uint64_t b0;
		uint64_t b1;

		a0 = a & 0xAAAAAAAAAAAAAAAAULL;
		a1 = (a >> 1) & 0xAAAAAAAAAAAAAAAAULL;
		b0 = b & 0xAAAAAAAAAAAAAAAAULL;
		b1 = (b >> 1) & 0xAAAAAAAAAAAAAAAAULL;

		return gf4v_mulh_u64_u64(a0, a1, b0, b1);
	}

	static inline uint64_t gf4v_squ_u64(uint64_t a)
	{
		uint64_t bit1;

		bit1 = a & 0xAAAAAAAAAAAAAAAAULL;

		return a ^ (bit1 >> 1);
	}

	static inline uint64_t gf16v_mul_u64(uint64_t a, uint8_t b)
	{
		uint64_t axb0;
		uint64_t axb1;
		uint64_t a0b1;
		uint64_t a1b1;
		uint64_t a1b1x2;

		axb0 = gf4v_mul_u64(a, b);
		axb1 = gf4v_mul_u64(a, b >> 2);
		a0b1 = (axb1 << 2) & 0xCCCCCCCCCCCCCCCCULL;
		a1b1 = axb1 & 0xCCCCCCCCCCCCCCCCULL;
		a1b1x2 = a1b1 >> 2;

		return axb0 ^ a0b1 ^ a1b1 ^ gf4v_mul_2_u64(a1b1x2);
	}

	static inline uint64_t gf16v_mulh_u64_u64(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t b0, uint64_t b1, uint64_t b2, uint64_t b3)
	{
		uint64_t c0;
		uint64_t c1;
		uint64_t c2x0;
		uint64_t c2x2;
		uint64_t c2x1;
		uint64_t c2r0;
		uint64_t c2r1;

		c0 = gf4v_mulh_u64_u64(a0, a1, b0, b1);
		c1 = gf4v_mulh_u64_u64(a0 ^ a2, a1 ^ a3, b0 ^ b2, b1 ^ b3);
		c2x0 = a2 & b2;
		c2x2 = a3 & b3;
		c2x1 = (a2 ^ a3) & (b2 ^ b3);
		c2r0 = c2x0 ^ c2x2;
		c2r1 = c2x0 ^ c2x1;

		return ((c1 ^ c0) << 2) ^ c0 ^ (c2r0 << 1) ^ c2r1 ^ (c2r1 << 1);
	}

	static inline uint64_t gf16v_mul_u64_u64(uint64_t a, uint64_t b)
	{
		uint64_t a0;
		uint64_t a1;
		uint64_t a2;
		uint64_t a3;
		uint64_t b0;
		uint64_t b1;
		uint64_t b2;
		uint64_t b3;

		a0 = a & 0x1111111111111111ULL;
		a1 = (a >> 1) & 0x1111111111111111ULL;
		a2 = (a >> 2) & 0x1111111111111111ULL;
		a3 = (a >> 3) & 0x1111111111111111ULL;
		b0 = b & 0x1111111111111111ULL;
		b1 = (b >> 1) & 0x1111111111111111ULL;
		b2 = (b >> 2) & 0x1111111111111111ULL;
		b3 = (b >> 3) & 0x1111111111111111ULL;

		return gf16v_mulh_u64_u64(a0, a1, a2, a3, b0, b1, b2, b3);
	}

	static inline uint8_t gf256v_reduce_u64(uint64_t a)
	{
		uint32_t aa[2] = { 0 };
		uint32_t r;

		aa[0] = a & 0xFFFFFFFFUL;
		aa[1] = (a >> 32) & 0xFFFFFFFFUL;
		r = aa[0] ^ aa[1];

		return gf256v_reduce_u32(r);
	}

	static inline uint8_t gf16v_reduce_u64(uint64_t a)
	{
		uint8_t r256;

		r256 = gf256v_reduce_u64(a);

		return (r256 & 0xf) ^ (r256 >> 4);
	}

	static inline uint64_t gf16v_squ_u64(uint64_t a)
	{
		uint64_t a2;

		a2 = gf4v_squ_u64(a);

		return a2 ^ gf4v_mul_2_u64((a2 >> 2) & 0x3333333333333333ULL);
	}

	static inline uint64_t gf16v_mul_8_u64(uint64_t a)
	{
		uint64_t a1;
		uint64_t a0;

		a1 = a & 0xCCCCCCCCCCCCCCCCULL;
		a0 = (a << 2) & 0xCCCCCCCCCCCCCCCCULL;

		return gf4v_mul_2_u64(a0 ^ a1) | gf4v_mul_3_u64(a1 >> 2);
	}

	static inline uint64_t gf256v_mul_u64(uint64_t a, uint8_t b)
	{
		uint64_t axb0;
		uint64_t axb1;
		uint64_t a0b1;
		uint64_t a1b1;
		uint64_t a1b1x4;

		axb0 = gf16v_mul_u64(a, b);
		axb1 = gf16v_mul_u64(a, b >> 4);
		a0b1 = (axb1 << 4) & 0xF0F0F0F0F0F0F0F0ULL;
		a1b1 = axb1 & 0xF0F0F0F0F0F0F0F0ULL;
		a1b1x4 = a1b1 >> 4;

		return axb0 ^ a0b1 ^ a1b1 ^ gf16v_mul_8_u64(a1b1x4);
	}

	static inline uint64_t gf256v_squ_u64(uint64_t a)
	{
		uint64_t a2;
		uint64_t ar;

		a2 = gf16v_squ_u64(a);
		ar = (a2 >> 4) & 0x0F0F0F0F0F0F0F0FULL;

		return a2 ^ gf16v_mul_8_u64(ar);
	}

	static inline uint64_t gf256v_mul_gf16_u64(uint64_t a, uint8_t gf16_b)
	{
		return gf16v_mul_u64(a, gf16_b);
	}

	// intutils.c

	static uint32_t le8to32(const uint8_t* input)
	{
		return ((uint32_t)input[0]) |
			((uint32_t)input[1] << 8) |
			((uint32_t)input[2] << 16) |
			((uint32_t)input[3] << 24);
	}

	static void le16to8(uint8_t* output, uint16_t value)
	{
		output[0] = value & 0xFF;
		output[1] = (value >> 8) & 0xFF;
	}

	static void le32to8(uint8_t* output, uint32_t value)
	{
		output[0] = value & 0xFF;
		output[1] = (value >> 8) & 0xFF;
		output[2] = (value >> 16) & 0xFF;
		output[3] = (value >> 24) & 0xFF;
	}

	// parallel_matrix_op.h

	inline static uint32_t idx_of_trimat(size_t rowi, size_t colj, size_t dim)
	{
		/* Calculate the corresponding index in an array for an upper-triangle(UT) matrix. */

		return (uint32_t)((dim + dim - rowi + 1) * rowi / 2 + colj - rowi);
	}

	inline static uint32_t idx_of_2trimat(size_t rowi, size_t colj, size_t nvar)
	{
		/* Calculate the corresponding index in an array for an upper-triangle or lower-triangle matrix. */

		uint32_t ret;

		if (rowi > colj)
		{
			ret = idx_of_trimat(colj, rowi, nvar);
		}
		else
		{
			ret = idx_of_trimat(rowi, colj, nvar);
		}

		return ret;
	}

	// parallel_matrix_op.c

	static void upper_trianglize(uint8_t* btric, const uint8_t* ba, size_t awidth, size_t batchsize)
	{
		/* Upper trianglize a rectangle matrix to the corresponding upper-trangle matrix. */

		uint8_t* tmpc = btric;
		size_t aheight;
		size_t i;
		size_t idx;
		size_t j;

		aheight = awidth;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < i; ++j)
			{
				idx = idx_of_trimat(j, i, aheight);
				gf256v_add(btric + idx * batchsize, ba + batchsize * (i * awidth + j), batchsize);
			}

			gf256v_add(tmpc, ba + batchsize * (i * awidth + i), batchsize * (aheight - i));
			tmpc += batchsize * (aheight - i);
		}
	}

	static void batch_trimat_madd_gf16(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += btriA * B , in GF(16) */

		size_t awidth;
		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		awidth = bheight;
		aheight = awidth;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (k < i)
					{
						continue;
					}

					gf16v_madd(bc, &btria[(k - i) * batchsize], gf16v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}

			btria += (aheight - i) * batchsize;
		}
	}

	static void batch_trimat_madd_gf256(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* C += btriA * B , in GF(256) */

		size_t awidth;
		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		awidth = bheight;
		aheight = awidth;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (k < i)
					{
						continue;
					}

					gf256v_madd(bc, &btria[(k - i) * batchsize], gf256v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}

			btria += (aheight - i) * batchsize;
		}
	}

	static void batch_trimatTr_madd_gf16(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += btriA^Tr * B , in GF(16) */
		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (i < k)
					{
						continue;
					}

					gf16v_madd(bc, &btria[batchsize * (idx_of_trimat(k, i, aheight))], gf16v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_trimatTr_madd_gf256(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += btriA^Tr * B, in GF(256) */

		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (i < k)
					{
						continue;
					}

					gf256v_madd(bc, &btria[batchsize * (idx_of_trimat(k, i, aheight))], gf256v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_2trimat_madd_gf16(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += (btriA + btriA^Tr) *B, in GF(16) */

		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (i == k)
					{
						continue;
					}

					gf16v_madd(bc, &btria[batchsize * (idx_of_2trimat(i, k, aheight))], gf16v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_2trimat_madd_gf256(uint8_t* bc, const uint8_t* btria, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += (btriA + btriA^Tr) *B, in GF(256) */

		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					if (i == k)
					{
						continue;
					}

					gf256v_madd(bc, &btria[batchsize * (idx_of_2trimat(i, k, aheight))], gf256v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_matTr_madd_gf16(uint8_t* bc, const uint8_t* atotr, size_t aheight, size_t acolvecsize, size_t awidth, const uint8_t* bB, size_t bwidth, size_t batchsize)
	{
		/* bC += A^Tr * bB, in GF(16) */

		size_t atrheight;
		size_t atrwidth;
		size_t i;
		size_t j;

		atrheight = awidth;
		atrwidth = aheight;

		for (i = 0; i < atrheight; ++i)
		{
			for (j = 0; j < atrwidth; ++j)
			{
				gf16v_madd(bc, &bB[j * bwidth * batchsize], gf16v_get_ele(&atotr[acolvecsize * i], (uint32_t)j), batchsize * bwidth);
			}

			bc += batchsize * bwidth;
		}
	}

	static void batch_matTr_madd_gf256(uint8_t* bc, const uint8_t* atotr, size_t aheight, size_t acolvecsize, size_t awidth, const uint8_t* bb, size_t bwidth, size_t batchsize)
	{
		/* bC += A^Tr * bB, in GF(256) */

		size_t atrheight;
		size_t atrwidth;
		size_t i;
		size_t j;

		atrheight = awidth;
		atrwidth = aheight;

		for (i = 0; i < atrheight; ++i)
		{
			for (j = 0; j < atrwidth; ++j)
			{
				gf256v_madd(bc, &bb[j * bwidth * batchsize], gf256v_get_ele(&atotr[acolvecsize * i], (uint32_t)j), batchsize * bwidth);
			}

			bc += batchsize * bwidth;
		}
	}

	static void batch_bmatTr_madd_gf16(uint8_t* bc, const uint8_t* batotr, size_t awidthbeforetr, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += bA^Tr * B, in GF(16) */

		const uint8_t* bA = batotr;
		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = awidthbeforetr;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					gf16v_madd(bc, &bA[batchsize * (i + k * aheight)], gf16v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_bmatTr_madd_gf256(uint8_t* bc, const uint8_t* batotr, size_t awidthbeforetr, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += bA^Tr * B, in GF(256) */

		const uint8_t* ba = batotr;
		size_t aheight;
		size_t i;
		size_t j;
		size_t k;

		aheight = awidthbeforetr;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					gf256v_madd(bc, &ba[batchsize * (i + k * aheight)], gf256v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}
		}
	}

	static void batch_mat_madd_gf16(uint8_t* bc, const uint8_t* ba, size_t aheight, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += bA * B, in GF(16) */

		size_t awidth;
		size_t i;
		size_t j;
		size_t k;

		awidth = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					gf16v_madd(bc, &ba[k * batchsize], gf16v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}

			ba += awidth * batchsize;
		}
	}

	static void batch_mat_madd_gf256(uint8_t* bc, const uint8_t* ba, size_t aheight, const uint8_t* b, size_t bheight, uint32_t bcolvecsize, size_t bwidth, size_t batchsize)
	{
		/* bC += bA * B, in GF(256) */

		size_t awidth;
		size_t i;
		size_t j;
		size_t k;

		awidth = bheight;

		for (i = 0; i < aheight; ++i)
		{
			for (j = 0; j < bwidth; ++j)
			{
				for (k = 0; k < bheight; ++k)
				{
					gf256v_madd(bc, &ba[k * batchsize], gf256v_get_ele(&b[j * bcolvecsize], (uint32_t)k), batchsize);
				}

				bc += batchsize;
			}

			ba += awidth * batchsize;
		}
	}

	static void batch_quad_trimat_eval_gf16(uint8_t* y, const uint8_t* trimat, const uint8_t* x, size_t dim, size_t batchsize)
	{
		/* y =  x^Tr * trimat * x  , in GF(16) */

		uint8_t tmp[256];
		uint8_t tmpx[256];
		size_t i;
		size_t j;

		for (i = 0; i < dim; ++i)
		{
			tmpx[i] = gf16v_get_ele(x, (uint32_t)i);
		}

		gf256v_set_zero(y, (uint32_t)batchsize);

		for (i = 0; i < dim; ++i)
		{
			gf256v_set_zero(tmp, (uint32_t)batchsize);

			for (j = i; j < dim; ++j)
			{
				gf16v_madd(tmp, trimat, tmpx[j], batchsize);
				trimat += batchsize;
			}

			gf16v_madd(y, tmp, tmpx[i], batchsize);
		}
	}

	static void batch_quad_trimat_eval_gf256(uint8_t* y, const uint8_t* trimat, const uint8_t* x, size_t dim, size_t batchsize)
	{
		/* y =  x^Tr * trimat * x, in GF(256) */
		uint8_t tmp[256];
		uint8_t tmpx[256];
		size_t i;
		size_t j;

		for (i = 0; i < dim; ++i)
		{
			tmpx[i] = gf256v_get_ele(x, (uint32_t)i);
		}

		gf256v_set_zero(y, (uint32_t)batchsize);

		for (i = 0; i < dim; ++i)
		{
			gf256v_set_zero(tmp, (uint32_t)batchsize);

			for (j = i; j < dim; ++j)
			{
				gf256v_madd(tmp, trimat, tmpx[j], batchsize);
				trimat += batchsize;
			}

			gf256v_madd(y, tmp, tmpx[i], batchsize);
		}
	}

	static void batch_quad_recmat_eval_gf16(uint8_t* z, const uint8_t* y, unsigned dimy, const uint8_t* mat, const uint8_t* x, size_t dimx, size_t batchsize)
	{
		/* z =  y^Tr * mat * x, in GF(16) */

		uint8_t tmp[128];
		uint8_t tmpx[128];
		uint8_t tmpy[128];
		size_t i;
		size_t j;

		for (i = 0; i < dimx; ++i)
		{
			tmpx[i] = gf16v_get_ele(x, (uint32_t)i);
		}

		for (i = 0; i < dimy; ++i)
		{
			tmpy[i] = gf16v_get_ele(y, (uint32_t)i);
		}

		gf256v_set_zero(z, (uint32_t)batchsize);

		for (i = 0; i < dimy; ++i)
		{
			gf256v_set_zero(tmp, (uint32_t)batchsize);

			for (j = 0; j < dimx; ++j)
			{
				gf16v_madd(tmp, mat, tmpx[j], batchsize);
				mat += batchsize;
			}

			gf16v_madd(z, tmp, tmpy[i], batchsize);
		}
	}

	static void batch_quad_recmat_eval_gf256(uint8_t* z, const uint8_t* y, size_t dimy, const uint8_t* mat, const uint8_t* x, size_t dimx, size_t batchsize)
	{
		/* z =  y^Tr * mat * x, in GF(256) */

		uint8_t tmp[128];
		uint8_t tmpx[128];
		uint8_t tmpy[128];
		size_t i;
		size_t j;

		for (i = 0; i < dimx; ++i)
		{
			tmpx[i] = gf256v_get_ele(x, (uint32_t)i);
		}

		for (i = 0; i < dimy; ++i)
		{
			tmpy[i] = gf256v_get_ele(y, (uint32_t)i);
		}

		gf256v_set_zero(z, (uint32_t)batchsize);

		for (i = 0; i < dimy; ++i)
		{
			gf256v_set_zero(tmp, (uint32_t)batchsize);

			for (j = 0; j < dimx; ++j)
			{
				gf256v_madd(tmp, mat, tmpx[j], batchsize);
				mat += batchsize;
			}

			gf256v_madd(z, tmp, tmpy[i], batchsize);
		}
	}

	// rainbow.c

#define RAINBOW_MAX_ATTEMPT_FRMAT  128
#define RAINBOW_MAX_O ((RAINBOW_O1 > RAINBOW_O2) ? RAINBOW_O1 : RAINBOW_O2)
#define RAINBOW_MAX_O_BYTE ((RAINBOW_O1_BYTE > RAINBOW_O2_BYTE) ? RAINBOW_O1_BYTE : RAINBOW_O2_BYTE)

	static int32_t rainbow_sign_classic(uint8_t * signature, const sk_t * sk, const uint8_t * digest)
	{
		//prng_t prng_sign;
		uint8_t digestsalt[RAINBOW_HASH_LEN + RAINBOW_SALT_BYTE];
		uint8_t prngpreseed[RAINBOW_LEN_SKSEED + RAINBOW_HASH_LEN];
		uint8_t prngseed[RAINBOW_HASH_LEN];
		uint8_t rl1F1[RAINBOW_O1_BYTE] = { 0 };
		uint8_t rl2F1[RAINBOW_O2_BYTE] = { 0 };
		uint8_t tempo[RAINBOW_MAX_O_BYTE + 32] = { 0 };
		uint8_t vinegar[RAINBOW_V1_BYTE];
		uint8_t w[RAINBOW_PUB_N_BYTE];
		uint8_t xo1[RAINBOW_O1_BYTE];
		uint8_t xo2[RAINBOW_O1_BYTE];
		uint8_t y[RAINBOW_PUB_M_BYTE];
		uint8_t z[RAINBOW_PUB_M_BYTE];
		uint8_t* matbuffer;
		uint8_t* matl1;
		uint8_t* matl2;
		uint8_t* matl2F3;
		uint8_t* matl2F2;
		uint8_t* salt;
		uint8_t* xv1;
		size_t i;
		uint32_t l1succ;
		uint32_t nattempt;
		uint32_t succ;
		int32_t ret;

		matl1 = (uint8_t*)malloc(RAINBOW_O1 * RAINBOW_O1_BYTE);
		matl2 = (uint8_t*)malloc(RAINBOW_O2 * RAINBOW_O2_BYTE);
		matbuffer = (uint8_t*)malloc(2 * RAINBOW_MAX_O * RAINBOW_MAX_O_BYTE);
		ret = 0;

		if (matl1 != NULL && matl2 != NULL && matbuffer != NULL)
		{
			memcpy(prngpreseed, sk->sk_seed, RAINBOW_LEN_SKSEED);
			/* prngpreseed = sk_seed || digest */
			memcpy(prngpreseed + RAINBOW_LEN_SKSEED, digest, RAINBOW_HASH_LEN);
			hash_msg(prngseed, RAINBOW_HASH_LEN, prngpreseed, RAINBOW_HASH_LEN + RAINBOW_LEN_SKSEED);
			BCG gen(Enumeration::BlockCiphers::AES);

			//std::vector<byte> seed(RAINBOW_HASH_LEN);
			//memcpy(seed.data(), prngseed, seed.size());

			// TODO: sk-seed size

			std::vector<byte> key(RAINBOW_HASH_LEN - 16);
			std::vector<byte> iv(16);
			memcpy(key.data(), prngseed, key.size());
			memcpy(iv.data(), prngseed + key.size(), iv.size());

			SymmetricKey kp(key, iv);
			gen.Initialize(kp);

			//prng_set(&prng_sign, prngseed, RAINBOW_HASH_LEN);

			/* seed = H( sk_seed || digest ) */
			for (i = 0; i < RAINBOW_LEN_SKSEED + RAINBOW_HASH_LEN; ++i)
			{
				prngpreseed[i] ^= prngpreseed[i];
			}

			for (i = 0; i < RAINBOW_HASH_LEN; ++i)
			{
				prngseed[i] ^= prngseed[i];
			}

			l1succ = 0;
			nattempt = 0;

			/* roll vinegars */
			while (!l1succ)
			{
				if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
				{
					break;
				}




				/* generating vinegars */
				//prng_gen(&prng_sign, vinegar, RAINBOW_V1_BYTE);
				std::vector<byte> tmpv(RAINBOW_V1_BYTE);
				gen.Generate(tmpv);
				memcpy(vinegar, tmpv.data(), tmpv.size());





				/* generating the linear equations for layer 1 */
				gf256mat_prod(matl1, sk->l1_F2, RAINBOW_O1 * RAINBOW_O1_BYTE, RAINBOW_V1, vinegar);
				/* check if the linear equation solvable */
				l1succ = gf256mat_inv(matl1, matl1, RAINBOW_O1, matbuffer);
				++nattempt;
			}

			/* Given the vinegars, pre-compute variables needed for layer 2 */
			batch_quad_trimat_eval_gf256(rl1F1, sk->l1_F1, vinegar, RAINBOW_V1, RAINBOW_O1_BYTE);
			batch_quad_trimat_eval_gf256(rl2F1, sk->l2_F1, vinegar, RAINBOW_V1, RAINBOW_O2_BYTE);
			matl2F3 = (uint8_t*)malloc(RAINBOW_O2 * RAINBOW_O2_BYTE);
			matl2F2 = (uint8_t*)malloc(RAINBOW_O1 * RAINBOW_O2_BYTE);

			if (matl2F3 != NULL && matl2F2 != NULL)
			{
				gf256mat_prod(matl2F3, sk->l2_F3, RAINBOW_O2 * RAINBOW_O2_BYTE, RAINBOW_V1, vinegar);
				gf256mat_prod(matl2F2, sk->l2_F2, RAINBOW_O1 * RAINBOW_O2_BYTE, RAINBOW_V1, vinegar);
				memcpy(digestsalt, digest, RAINBOW_HASH_LEN);
				salt = digestsalt + RAINBOW_HASH_LEN;
				succ = 0;

				while (!succ)
				{
					if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
					{
						break;
					}

					/* The computation: H(digest||salt) --> z --S--> y --C-map--> x --T--> w */
					/* roll the salt */




					std::vector<byte> tmps(RAINBOW_SALT_BYTE);
					gen.Generate(tmps);
					memcpy(digestsalt + RAINBOW_HASH_LEN, tmps.data(), tmps.size());
					//prng_gen(&prng_sign, salt, RAINBOW_SALT_BYTE);





					/* H(digest||salt) */
					hash_msg(z, RAINBOW_PUB_M_BYTE, digestsalt, RAINBOW_HASH_LEN + RAINBOW_SALT_BYTE);
					/* y = S^-1 * z */
					memcpy(y, z, RAINBOW_PUB_M_BYTE);
					/* identity part of S */
					gf256mat_prod(tempo, sk->s1, RAINBOW_O1_BYTE, RAINBOW_O2, z + RAINBOW_O1_BYTE);
					gf256v_add(y, tempo, RAINBOW_O1_BYTE);

					/* Central Map: */
					/* layer 1: calculate xo1 */
					memcpy(tempo, rl1F1, RAINBOW_O1_BYTE);
					gf256v_add(tempo, y, RAINBOW_O1_BYTE);
					gf256mat_prod(xo1, matl1, RAINBOW_O1_BYTE, RAINBOW_O1, tempo);

					/* layer 2: calculate xo2 */
					gf256v_set_zero(tempo, RAINBOW_O2_BYTE);
					/* F2 */
					gf256mat_prod(tempo, matl2F2, RAINBOW_O2_BYTE, RAINBOW_O1, xo1);
					/* F5 */
					batch_quad_trimat_eval_gf256(matl2, sk->l2_F5, xo1, RAINBOW_O1, RAINBOW_O2_BYTE);
					gf256v_add(tempo, matl2, RAINBOW_O2_BYTE);
					/* F1 */
					gf256v_add(tempo, rl2F1, RAINBOW_O2_BYTE);
					gf256v_add(tempo, y + RAINBOW_O1_BYTE, RAINBOW_O2_BYTE);

					/* generate the linear equations of the 2nd layer */
					/* F6 */
					gf256mat_prod(matl2, sk->l2_F6, RAINBOW_O2 * RAINBOW_O2_BYTE, RAINBOW_O1, xo1);
					/* F3 */
					gf256v_add(matl2, matl2F3, RAINBOW_O2 * RAINBOW_O2_BYTE);
					succ = gf256mat_inv(matl2, matl2, RAINBOW_O2, matbuffer);
					/* solve l2 eqs */
					gf256mat_prod(xo2, matl2, RAINBOW_O2_BYTE, RAINBOW_O2, tempo);

					++nattempt;
				};

				/* w = T^-1 * y */
				/* identity part of T */
				xv1 = vinegar;
				memcpy(w, xv1, RAINBOW_V1_BYTE);
				memcpy(w + RAINBOW_V1_BYTE, xo1, RAINBOW_O1_BYTE);
				memcpy(w + RAINBOW_V2_BYTE, xo2, RAINBOW_O2_BYTE);
				/* Computing the t1 part */
				gf256mat_prod(y, sk->t1, RAINBOW_V1_BYTE, RAINBOW_O1, xo1);
				gf256v_add(w, y, RAINBOW_V1_BYTE);
				/* Computing the t4 part */
				gf256mat_prod(y, sk->t4, RAINBOW_V1_BYTE, RAINBOW_O2, xo2);
				gf256v_add(w, y, RAINBOW_V1_BYTE);
				/* Computing the t3 part */
				gf256mat_prod(y, sk->t3, RAINBOW_O1_BYTE, RAINBOW_O2, xo2);
				gf256v_add(w + RAINBOW_V1_BYTE, y, RAINBOW_O1_BYTE);
				/* set the output 0 */
				memset(signature, 0, RAINBOW_SIGNATURE_BYTE);
				/* clean */
				memset(matl1, 0, RAINBOW_O1 * RAINBOW_O1_BYTE);
				free(matl1);
				memset(matl2, 0, RAINBOW_O2 * RAINBOW_O2_BYTE);
				free(matl2);
				memset(matbuffer, 0, 2 * RAINBOW_MAX_O * RAINBOW_MAX_O_BYTE);
				free(matbuffer);
				//memset(&prng_sign, 0, sizeof(prng_t));
				memset(vinegar, 0, RAINBOW_V1_BYTE);
				memset(rl1F1, 0, RAINBOW_O1_BYTE);
				memset(rl2F1, 0, RAINBOW_O2_BYTE);
				memset(matl2F3, 0, RAINBOW_O2 * RAINBOW_O2_BYTE);
				free(matl2F3);
				memset(matl2F2, 0, RAINBOW_O1 * RAINBOW_O2_BYTE);
				free(matl2F2);
				memset(z, 0, RAINBOW_PUB_M_BYTE);
				memset(y, 0, RAINBOW_PUB_M_BYTE);
				memset(xo1, 0, RAINBOW_O1_BYTE);
				memset(xo2, 0, RAINBOW_O2_BYTE);
				memset(tempo, 0, sizeof(tempo));

				/* return: copy w and salt to the signature */
				if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
				{
					ret = -1;
				}
				else
				{
					gf256v_add(signature, w, RAINBOW_PUB_N_BYTE);
					gf256v_add(signature + RAINBOW_PUB_N_BYTE, salt, RAINBOW_SALT_BYTE);
				}
			}
			else
			{
				ret = -1;
			}
		}
		else
		{
			ret = -1;
		}

		return ret;
	}

	static int32_t rainbow_verify_classic(const uint8_t* digest, const uint8_t* signature, const pk_t* pk)
	{
		uint8_t digest_ck[RAINBOW_PUB_M_BYTE];
		uint8_t correct[RAINBOW_PUB_M_BYTE];
		uint8_t digestsalt[RAINBOW_HASH_LEN + RAINBOW_SALT_BYTE];
		size_t i;
		uint8_t cc;

		cc = 0;

		/* public_map( digest_ck , pk , signature ); Evaluating the quadratic public polynomials */
		batch_quad_trimat_eval_gf256(digest_ck, pk->pk, signature, RAINBOW_PUB_N, RAINBOW_PUB_M_BYTE);
		memcpy(digestsalt, digest, RAINBOW_HASH_LEN);
		memcpy(digestsalt + RAINBOW_HASH_LEN, signature + RAINBOW_PUB_N_BYTE, RAINBOW_SALT_BYTE);
		/* H( digest || salt ) */
		hash_msg(correct, RAINBOW_PUB_M_BYTE, digestsalt, RAINBOW_HASH_LEN + RAINBOW_SALT_BYTE);

		/* check consistancy */
		for (i = 0; i < RAINBOW_PUB_M_BYTE; ++i)
		{
			cc |= (digest_ck[i] ^ correct[i]);
		}

		return (0 == cc) ? 0 : -1;
	}

	// rainbow_keypair.c

	static void generate_S_T(uint8_t* sandt, std::unique_ptr<IDrbg> &Rng/*prng_t* prng0*/)
	{
		/* S1 */
		std::vector<byte> tmpst((RAINBOW_O1_BYTE * RAINBOW_O2) + (RAINBOW_V1_BYTE * RAINBOW_O1) + (RAINBOW_V1_BYTE * RAINBOW_O2) + (RAINBOW_O1_BYTE * RAINBOW_O2));
		Rng->Generate(tmpst);
		memcpy(sandt, tmpst.data(), tmpst.size());

		//prng_gen(prng0, sandt, RAINBOW_O1_BYTE * RAINBOW_O2);
		//sandt += RAINBOW_O1_BYTE * RAINBOW_O2;
		/* T1 */
		//prng_gen(prng0, sandt, RAINBOW_V1_BYTE * RAINBOW_O1);
		//sandt += RAINBOW_V1_BYTE * RAINBOW_O1;
		/* T2 */
		//prng_gen(prng0, sandt, RAINBOW_V1_BYTE * RAINBOW_O2);
		//sandt += RAINBOW_V1_BYTE * RAINBOW_O2;
		/* T3 */
		//prng_gen(prng0, sandt, RAINBOW_O1_BYTE * RAINBOW_O2);
	}

	static uint32_t generate_l1_F12(uint8_t* sk, std::unique_ptr<IDrbg> &Rng/*prng_t* prng0*/)
	{
		uint32_t genbytes;

		genbytes = 0;

		std::vector<byte> tmpsk((RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)) + (RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1));
		Rng->Generate(tmpsk);
		memcpy(sk, tmpsk.data(), tmpsk.size());
		genbytes = (uint32_t)tmpsk.size();

		/* l1_F1 */
		//prng_gen(prng0, sk, RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
		//sk += RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1);
		//genbytes += RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1);
		/* l1_F2 */
		//prng_gen(prng0, sk, RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1);
		//sk += RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1;
		//genbytes += RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1;

		return genbytes;
	}

	static uint32_t generate_l2_F12356(uint8_t* sk, std::unique_ptr<IDrbg> &Rng/*prng_t* prng0*/)
	{
		uint32_t genbytes;

		genbytes = 0;

		std::vector<byte> tmpsk((RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1)) + (RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1) +
			(RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O2) + (RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1)) + (RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2));

		Rng->Generate(tmpsk);
		memcpy(sk, tmpsk.data(), tmpsk.size());
		genbytes = (uint32_t)tmpsk.size();

		/* l2_F1 */
		//prng_gen(prng0, sk, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
		//sk += RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1);
		//genbytes += RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1);
		/* l2_F2 */
		//prng_gen(prng0, sk, RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1);
		//sk += RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1;
		//genbytes += RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1;
		/* l2_F3 */
		//prng_gen(prng0, sk, RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O2);
		//sk += RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1;
		//genbytes += RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1;
		/* l2_F5 */
		//prng_gen(prng0, sk, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1));
		//sk += RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1);
		//genbytes += RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1);
		/* l2_F6 */
		//prng_gen(prng0, sk, RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2);
		//genbytes += RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2;

		return genbytes;
	}

	static void generate_B1_B2(uint8_t* sk, std::unique_ptr<IDrbg> &Rng/*prng_t* prng0*/)
	{
		size_t len;

		len = generate_l1_F12(sk, Rng);
		//len = generate_l1_F12(sk, prng0);
		sk += len;
		generate_l2_F12356(sk, Rng);
		//generate_l2_F12356(sk, prng0);
	}

	static void calculate_t4(uint8_t* t2tot4, const uint8_t* t1, const uint8_t* t3)
	{
		/* t4 = T_sk.t1 * T_sk.t3 - T_sk.t2 */

		uint8_t temp[RAINBOW_V1_BYTE + 32];
		uint8_t* t4;
		size_t i;

		t4 = t2tot4;

		for (i = 0; i < RAINBOW_O2; ++i)
		{
			/* t3 width */
			gf256mat_prod(temp, t1, RAINBOW_V1_BYTE, RAINBOW_O1, t3);
			gf256v_add(t4, temp, RAINBOW_V1_BYTE);
			t4 += RAINBOW_V1_BYTE;
			t3 += RAINBOW_O1_BYTE;
		}
	}

	static void obsfucate_l1_polys(uint8_t* l1polys, const uint8_t* l2polys, uint32_t nterms, const uint8_t* s1)
	{
		uint8_t temp[RAINBOW_O1_BYTE + 32];

		while (nterms != 0)
		{
			--nterms;
			gf256mat_prod(temp, s1, RAINBOW_O1_BYTE, RAINBOW_O2, l2polys);
			gf256v_add(l1polys, temp, RAINBOW_O1_BYTE);
			l1polys += RAINBOW_O1_BYTE;
			l2polys += RAINBOW_O2_BYTE;
		}
	}

	static void generate_secretkey_helper(sk_t* sk, const uint8_t* skseed)
	{
		std::unique_ptr<IDrbg> gen(new BCG(Enumeration::BlockCiphers::AES));

		//prng_t prng0;
		// cyclic = true
		memcpy(sk->sk_seed, skseed, RAINBOW_LEN_SKSEED);

		/* set up prng */
		std::vector<byte> key(RAINBOW_LEN_SKSEED - 16);
		std::vector<byte> iv(16);
		memcpy(key.data(), skseed, key.size());
		memcpy(iv.data(), skseed + key.size(), iv.size());
		// TODO: can sk-seed size be increased?


		SymmetricKey kp(key, iv);
		gen->Initialize(kp);
		//prng_set(&prng0, skseed, RAINBOW_LEN_SKSEED);


		/* generating secret key with prng */
		generate_S_T(sk->s1, gen);
		//generate_S_T(sk->s1, &prng0);
		generate_B1_B2(sk->l1_F1, gen);
		//generate_B1_B2(sk->l1_F1, &prng0);
		/* clean prng */
		//memset(&prng0, 0, sizeof(prng_t));
	}

	static void generate_secretkey(sk_t* sk, const uint8_t* skseed)
	{
		generate_secretkey_helper(sk, skseed);
		calculate_t4(sk->t4, sk->t1, sk->t3);
	}

	static void generate_keypair(pk_t* rpk, sk_t* sk, const uint8_t* skseed)
	{
		ext_cpk_t* pk;

		generate_secretkey_helper(sk, skseed);

		/* set up a temporary structure ext_cpk_t for calculating public key */
		pk = (ext_cpk_t*)malloc(sizeof(ext_cpk_t));

		if (pk != NULL)
		{
			calculate_Q_from_F(pk, sk, sk);
			/* compute the public key in ext_cpk_t format */
			calculate_t4(sk->t4, sk->t1, sk->t3);

			obsfucate_l1_polys(pk->l1_Q1, pk->l2_Q1, RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1), sk->s1);
			obsfucate_l1_polys(pk->l1_Q2, pk->l2_Q2, RAINBOW_V1 * RAINBOW_O1, sk->s1);
			obsfucate_l1_polys(pk->l1_Q3, pk->l2_Q3, RAINBOW_V1 * RAINBOW_O2, sk->s1);
			obsfucate_l1_polys(pk->l1_Q5, pk->l2_Q5, RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1), sk->s1);
			obsfucate_l1_polys(pk->l1_Q6, pk->l2_Q6, RAINBOW_O1 * RAINBOW_O2, sk->s1);
			obsfucate_l1_polys(pk->l1_Q9, pk->l2_Q9, RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O2), sk->s1);

			/* so far, the pk contains the full pk but in ext_cpk_t format. */

			/* convert the public key from ext_cpk_t to pk_t. */
			extcpk_to_pk(rpk, pk);
			free(pk);
		}
	}

	// rainbow_keypair_computation.c

	static void extcpk_to_pk(pk_t* pk, const ext_cpk_t* cpk)
	{
		const uint8_t* idx_l1;
		const uint8_t* idx_l2;
		size_t i;
		size_t j;
		uint32_t pubidx;

		idx_l1 = cpk->l1_Q1;
		idx_l2 = cpk->l2_Q1;

		for (i = 0; i < RAINBOW_V1; ++i)
		{
			for (j = i; j < RAINBOW_V1; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}

		idx_l1 = cpk->l1_Q2;
		idx_l2 = cpk->l2_Q2;

		for (i = 0; i < RAINBOW_V1; ++i)
		{
			for (j = RAINBOW_V1; j < RAINBOW_V1 + RAINBOW_O1; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}

		idx_l1 = cpk->l1_Q3;
		idx_l2 = cpk->l2_Q3;

		for (i = 0; i < RAINBOW_V1; ++i)
		{
			for (j = RAINBOW_V1 + RAINBOW_O1; j < RAINBOW_PUB_N; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}

		idx_l1 = cpk->l1_Q5;
		idx_l2 = cpk->l2_Q5;

		for (i = RAINBOW_V1; i < RAINBOW_V1 + RAINBOW_O1; ++i)
		{
			for (j = i; j < RAINBOW_V1 + RAINBOW_O1; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}

		idx_l1 = cpk->l1_Q6;
		idx_l2 = cpk->l2_Q6;

		for (i = RAINBOW_V1; i < RAINBOW_V1 + RAINBOW_O1; ++i)
		{
			for (j = RAINBOW_V1 + RAINBOW_O1; j < RAINBOW_PUB_N; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}

		idx_l1 = cpk->l1_Q9;
		idx_l2 = cpk->l2_Q9;

		for (i = RAINBOW_V1 + RAINBOW_O1; i < RAINBOW_PUB_N; ++i)
		{
			for (j = i; j < RAINBOW_PUB_N; ++j)
			{
				pubidx = idx_of_trimat(i, j, RAINBOW_PUB_N);
				memcpy(&pk->pk[RAINBOW_PUB_M_BYTE * pubidx], idx_l1, RAINBOW_O1_BYTE);
				memcpy((&pk->pk[RAINBOW_PUB_M_BYTE * pubidx]) + RAINBOW_O1_BYTE, idx_l2, RAINBOW_O2_BYTE);
				idx_l1 += RAINBOW_O1_BYTE;
				idx_l2 += RAINBOW_O2_BYTE;
			}
		}
	}

	static void calculate_Q_from_F_ref(ext_cpk_t* Qs, const sk_t* Fs, const sk_t* Ts)
	{
		const uint8_t* t2 = Ts->t4;
		uint8_t* tmpq;
		size_t qsize;

		/* Layer 1 Computing :
		* Q_pk.l1_F1s[i] = F_sk.l1_F1s[i]
		* Q_pk.l1_F2s[i] = (F1* T1 + F2) + F1tr * t1
		* Q_pk.l1_F5s[i] = UT( T1tr* (F1 * T1 + F2))
		*/

		memcpy(Qs->l1_Q1, Fs->l1_F1, RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
		memcpy(Qs->l1_Q2, Fs->l1_F2, RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1);
		/* F1*T1 + F2 */
		batch_trimat_madd_gf256(Qs->l1_Q2, Fs->l1_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O1_BYTE);

		memset(Qs->l1_Q3, 0x00, RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O2);
		memset(Qs->l1_Q5, 0x00, RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1));
		memset(Qs->l1_Q6, 0x00, RAINBOW_O1_BYTE * RAINBOW_O1 * RAINBOW_O2);
		memset(Qs->l1_Q9, 0x00, RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O2));

		qsize = RAINBOW_O1_BYTE * RAINBOW_O1 * RAINBOW_O1;

		if (RAINBOW_O1_BYTE * RAINBOW_O2 * RAINBOW_O2 > qsize)
		{
			qsize = RAINBOW_O1_BYTE * RAINBOW_O2 * RAINBOW_O2;
		}

		if (RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O1 > qsize)
		{
			qsize = RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O1;
		}

		if (RAINBOW_O2_BYTE * RAINBOW_O2 * RAINBOW_O2 > qsize)
		{
			qsize = RAINBOW_O2_BYTE * RAINBOW_O2 * RAINBOW_O2;
		}

		tmpq = (uint8_t*)malloc(qsize + 32);

		if (tmpq != NULL)
		{
			/* l1_Q5 */
			memset(tmpq, 0, RAINBOW_O1_BYTE * RAINBOW_O1 * RAINBOW_O1);
			/* t1_tr*(F1*T1 + F2) */
			batch_matTr_madd_gf256(tmpq, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Qs->l1_Q2, RAINBOW_O1, RAINBOW_O1_BYTE);
			/* UT( ... ) Q5 */
			upper_trianglize(Qs->l1_Q5, tmpq, RAINBOW_O1, RAINBOW_O1_BYTE);
			/* Q2 */
			batch_trimatTr_madd_gf256(Qs->l1_Q2, Fs->l1_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O1_BYTE);

			/* Computing:
			* F1_T2 = F1 * t2
			* F2_T3 = F2 * t3
			* F1_F1T_T2 + F2_T3 = F1_T2 + F2_T3 + F1tr * t2
			* Q_pk.l1_F3s[i] = F1_F1T_T2 + F2_T3
			* Q_pk.l1_F6s[i] = T1tr*( F1_F1T_T2 + F2_T3 ) + F2tr * t2
			* Q_pk.l1_F9s[i] = UT( T2tr* ( F1_T2 + F2_T3 ) )
			*/

			/* F1*T2 */
			batch_trimat_madd_gf256(Qs->l1_Q3, Fs->l1_F1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* F1_T2 + F2_T3 */
			batch_mat_madd_gf256(Qs->l1_Q3, Fs->l1_F2, RAINBOW_V1, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* l1_Q9 */
			memset(tmpq, 0, RAINBOW_O1_BYTE * RAINBOW_O2 * RAINBOW_O2);
			/* T2tr * ( F1_T2 + F2_T3 ) */
			batch_matTr_madd_gf256(tmpq, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, Qs->l1_Q3, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* Q9 */
			upper_trianglize(Qs->l1_Q9, tmpq, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* F1_F1T_T2 + F2_T3 Q3 */
			batch_trimatTr_madd_gf256(Qs->l1_Q3, Fs->l1_F1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* F2tr*T2 */
			batch_bmatTr_madd_gf256(Qs->l1_Q6, Fs->l1_F2, RAINBOW_O1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O1_BYTE);
			/* Q6 */
			batch_matTr_madd_gf256(Qs->l1_Q6, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Qs->l1_Q3, RAINBOW_O2, RAINBOW_O1_BYTE);

			/* layer 2
			* Computing:
			* Q1 = F1
			* Q2 = F1_F1T*T1 + F2
			* Q5 = UT( T1tr( F1*T1 + F2 )  + F5 )
			*/
			memcpy(Qs->l2_Q1, Fs->l2_F1, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
			memcpy(Qs->l2_Q2, Fs->l2_F2, RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1);
			/* F1*T1 + F2 */
			batch_trimat_madd_gf256(Qs->l2_Q2, Fs->l2_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O2_BYTE);
			memcpy(Qs->l2_Q5, Fs->l2_F5, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1));
			/* l2_Q5 */
			memset(tmpq, 0, RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O1);
			/* t1_tr*(F1*T1 + F2) */
			batch_matTr_madd_gf256(tmpq, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Qs->l2_Q2, RAINBOW_O1, RAINBOW_O2_BYTE);
			/* UT( ... ) Q5 */
			upper_trianglize(Qs->l2_Q5, tmpq, RAINBOW_O1, RAINBOW_O2_BYTE);
			/* Q2 */
			batch_trimatTr_madd_gf256(Qs->l2_Q2, Fs->l2_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O2_BYTE);

			/* Computing:
			* F1_T2 = F1 * t2
			* F2_T3 = F2 * t3
			* F1_F1T_T2 + F2_T3 = F1_T2 + F2_T3 + F1tr * t2
			* Q3 =F1_F1T*T2 + F2*T3 + F3
			* Q9 = UT( T2tr*( F1*T2 + F2*T3 + F3 ) + T3tr*( F5*T3 + F6 ) )
			* Q6 = T1tr*( F1_F1T*T2 + F2*T3 + F3 ) + F2Tr*T2 + F5_F5T*T3 + F6
			*/
			memcpy(Qs->l2_Q3, Fs->l2_F3, RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O2);
			/* F1*T2 + F3 */
			batch_trimat_madd_gf256(Qs->l2_Q3, Fs->l2_F1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* F1_T2 + F2_T3 + F3 */
			batch_mat_madd_gf256(Qs->l2_Q3, Fs->l2_F2, RAINBOW_V1, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* l2_Q9 */
			memset(tmpq, 0, RAINBOW_O2_BYTE * RAINBOW_O2 * RAINBOW_O2);
			/* T2tr * ( ..... ) */
			batch_matTr_madd_gf256(tmpq, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, Qs->l2_Q3, RAINBOW_O2, RAINBOW_O2_BYTE);

			memcpy(Qs->l2_Q6, Fs->l2_F6, RAINBOW_O2_BYTE * RAINBOW_O1 * RAINBOW_O2);
			/* F5*T3 + F6 */
			batch_trimat_madd_gf256(Qs->l2_Q6, Fs->l2_F5, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* T2tr*( ..... ) + T3tr*( ..... ) */
			batch_matTr_madd_gf256(tmpq, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, Qs->l2_Q6, RAINBOW_O2, RAINBOW_O2_BYTE);
			memset(Qs->l2_Q9, 0, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O2));
			/* Q9 */
			upper_trianglize(Qs->l2_Q9, tmpq, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* F1_F1T_T2 + F2_T3 + F3 - Q3 */
			batch_trimatTr_madd_gf256(Qs->l2_Q3, Fs->l2_F1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* F5*T3 + F6 +  F2tr*T2 */
			batch_bmatTr_madd_gf256(Qs->l2_Q6, Fs->l2_F2, RAINBOW_O1, t2, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* F2tr*T2 + F5_F5T*T3 + F6 */
			batch_trimatTr_madd_gf256(Qs->l2_Q6, Fs->l2_F5, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* Q6 */
			batch_matTr_madd_gf256(Qs->l2_Q6, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Qs->l2_Q3, RAINBOW_O2, RAINBOW_O2_BYTE);

			memset(tmpq, 0, qsize + 32);
			free(tmpq);
		}
	}

	static void calculate_F_from_Q_ref(sk_t* Fs, const sk_t* Qs, sk_t* Ts)
	{
		uint8_t* tmpq;

		/* Layer 1 */
		/* F_sk.l1_F1s[i] = Q_pk.l1_F1s[i] */
		memcpy(Fs->l1_F1, Qs->l1_F1, RAINBOW_O1_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
		/* F_sk.l1_F2s[i] = ( Q_pk.l1_F1s[i] + Q_pk.l1_F1s[i].transpose() ) * T_sk.t1 + Q_pk.l1_F2s[i] */
		memcpy(Fs->l1_F2, Qs->l1_F2, RAINBOW_O1_BYTE * RAINBOW_V1 * RAINBOW_O1);
		batch_2trimat_madd_gf256(Fs->l1_F2, Qs->l1_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O1_BYTE);

		/*
		* Layer 2 computations:
		* F_sk.l2_F1s[i] = Q_pk.l2_F1s[i]
		* Q1_T1 = Q_pk.l2_F1s[i]*T_sk.t1
		* F_sk.l2_F2s[i] = Q1_T1 + Q_pk.l2_F2s[i]     + Q_pk.l2_F1s[i].transpose() * T_sk.t1
		* F_sk.l2_F5s[i] = UT( t1_tr* ( Q1_T1 + Q_pk.l2_F2s[i] ) ) + Q_pk.l2_F5s[i]
		* Q1_Q1T_T4 =  (Q_pk.l2_F1s[i] + Q_pk.l2_F1s[i].transpose()) * t4
		* #Q1_Q1T_T4 =  Q1_Q1T * t4
		* Q2_T3 = Q_pk.l2_F2s[i]*T_sk.t3
		* F_sk.l2_F3s[i] = Q1_Q1T_T4 + Q2_T3 + Q_pk.l2_F3s[i]
		* F_sk.l2_F6s[i] = t1_tr * ( Q1_Q1T_T4 + Q2_T3 + Q_pk.l2_F3s[i])
		* +  Q_pk.l2_F2s[i].transpose() * t4
		* + (Q_pk.l2_F5s[i] + Q_pk.l2_F5s[i].transpose())*T_sk.t3   + Q_pk.l2_F6s[i]
		*/

		/* F_sk.l2_F1s[i] = Q_pk.l2_F1s[i] */
		memcpy(Fs->l2_F1, Qs->l2_F1, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_V1));
		/* F_sk.l2_F2s[i] = Q1_T1 + Q_pk.l2_F2s[i]+ Q_pk.l2_F1s[i].transpose() * T_sk.t1 */
		/* F_sk.l2_F5s[i] = UT( t1_tr* ( Q1_T1 + Q_pk.l2_F2s[i] ) ) + Q_pk.l2_F5s[i] */
		memcpy(Fs->l2_F2, Qs->l2_F2, RAINBOW_O2_BYTE * RAINBOW_V1 * RAINBOW_O1);
		/* Q1_T1+ Q2 */
		batch_trimat_madd_gf256(Fs->l2_F2, Qs->l2_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O2_BYTE);

		tmpq = (uint8_t*)malloc(RAINBOW_O1 * RAINBOW_O1 * RAINBOW_O2_BYTE + 32);

		if (tmpq != NULL)
		{
			memset(tmpq, 0x00, RAINBOW_O1 * RAINBOW_O1 * RAINBOW_O2_BYTE);
			/* t1_tr*(Q1_T1+Q2) */
			batch_matTr_madd_gf256(tmpq, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Fs->l2_F2, RAINBOW_O1, RAINBOW_O2_BYTE);
			/* F5 */
			memcpy(Fs->l2_F5, Qs->l2_F5, RAINBOW_O2_BYTE * RAINBOW_N_TRIANGLE_TERMS(RAINBOW_O1));
			/* UT( ... ) */
			upper_trianglize(Fs->l2_F5, tmpq, RAINBOW_O1, RAINBOW_O2_BYTE);
			memset(tmpq, 0, RAINBOW_O1 * RAINBOW_O1 * RAINBOW_O2_BYTE + 32);
			free(tmpq);

			/* F2 = Q1_T1 + Q2 + Q1^tr*t1 */
			batch_trimatTr_madd_gf256(Fs->l2_F2, Qs->l2_F1, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, RAINBOW_O2_BYTE);

			/* Q1_Q1T_T4 =  (Q_pk.l2_F1s[i] + Q_pk.l2_F1s[i].transpose()) * t4 */
			/* Q2_T3 = Q_pk.l2_F2s[i]*T_sk.t3 */
			/* F_sk.l2_F3s[i] = Q1_Q1T_T4 + Q2_T3 + Q_pk.l2_F3s[i] */
			memcpy(Fs->l2_F3, Qs->l2_F3, RAINBOW_V1 * RAINBOW_O2 * RAINBOW_O2_BYTE);
			/* Q1_Q1T_T4 */
			batch_2trimat_madd_gf256(Fs->l2_F3, Qs->l2_F1, Ts->t4, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* Q2_T3 */
			batch_mat_madd_gf256(Fs->l2_F3, Qs->l2_F2, RAINBOW_V1, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);

			/* F_sk.l2_F6s[i] = t1_tr * ( Q1_Q1T_T4 + Q2_T3 + Q_pk.l2_F3s[i]) */
			/* +  Q_pk.l2_F2s[i].transpose() * t4 */
			/* + (Q_pk.l2_F5s[i] + Q_pk.l2_F5s[i].transpose())*T_sk.t3 + Q_pk.l2_F6s[i] */
			memcpy(Fs->l2_F6, Qs->l2_F6, RAINBOW_O1 * RAINBOW_O2 * RAINBOW_O2_BYTE);
			/* t1_tr * ( Q1_Q1T_T4 + Q2_T3 + Q_pk.l2_F3s[i]) */
			batch_matTr_madd_gf256(Fs->l2_F6, Ts->t1, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O1, Fs->l2_F3, RAINBOW_O2, RAINBOW_O2_BYTE);
			/* (Q_pk.l2_F5s[i] + Q_pk.l2_F5s[i].transpose())*T_sk.t3 */
			batch_2trimat_madd_gf256(Fs->l2_F6, Qs->l2_F5, Ts->t3, RAINBOW_O1, RAINBOW_O1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
			batch_bmatTr_madd_gf256(Fs->l2_F6, Qs->l2_F2, RAINBOW_O1, Ts->t4, RAINBOW_V1, RAINBOW_V1_BYTE, RAINBOW_O2, RAINBOW_O2_BYTE);
		}
	}

	static void calculate_Q_from_F(ext_cpk_t* Qs, const sk_t* Fs, const sk_t* Ts)
	{
		calculate_Q_from_F_ref(Qs, Fs, Ts);
	}

	static void calculate_F_from_Q(sk_t* Fs, const sk_t* Qs, sk_t* Ts)
	{
		calculate_F_from_Q_ref(Fs, Qs, Ts);
	}

	// sign.h

	static int32_t rainbow_generate(uint8_t* publickey, uint8_t* secretkey, std::unique_ptr<IPrng> &Rng)
	{
		uint8_t skseed[RAINBOW_LEN_SKSEED] = { 0 };

		std::vector<byte> tmps(RAINBOW_LEN_SKSEED);
		Rng->Generate(tmps);

		generate_keypair((pk_t*)publickey, (sk_t*)secretkey, tmps.data());

		//ret = randombytes(skseed, RAINBOW_LEN_SKSEED);

		//if (ret == 0)
		//{
		//	generate_keypair((pk_t*)publickey, (sk_t*)secretkey, skseed);
		//}

		return 0;
	}

	static int32_t rainbow_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* secretkey)
	{
		uint8_t digest[RAINBOW_HASH_LEN] = { 0 };
		int32_t ret;

		ret = hash_msg(digest, RAINBOW_HASH_LEN, message, msglen);

		if (ret == 0)
		{
			memcpy(signedmsg, message, msglen);
			*smsglen = msglen + RAINBOW_SIGNATURE_BYTE;

			ret = rainbow_sign_classic(signedmsg + msglen, (const sk_t*)secretkey, digest);
		}

		return ret;
	}

	static int32_t rainbow_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
	{
		uint8_t digest[RAINBOW_HASH_LEN];
		int32_t ret;

		if (smsglen >= RAINBOW_SIGNATURE_BYTE)
		{
			ret = 0;
		}
		else
		{
			ret = -1;
		}

		if (ret == 0)
		{
			memcpy(message, signedmsg, smsglen - RAINBOW_SIGNATURE_BYTE);
			*msglen = smsglen - RAINBOW_SIGNATURE_BYTE;
			hash_msg(digest, RAINBOW_HASH_LEN, message, *msglen);
			ret = rainbow_verify_classic(digest, signedmsg + *msglen, (const pk_t *)publickey);
		}

		return ret;
	}

	// utils_hash.c

	static void hash_execute(uint8_t* digest, const uint8_t* message, size_t msglen)
	{
#if RAINBOW_HASH_LEN == 32
		std::vector<byte> tmpm(msglen);
		std::vector<byte> tmpd(SHA2::SHA256_DIGEST_SIZE);

		memcpy(tmpm.data(), message, msglen);
		SHA2::Compute256(tmpm, 0, tmpm.size(), tmpd, 0);
		memcpy(digest, tmpd.data(), tmpd.size());

		//sha256_compute(digest, message, msglen);
#elif RAINBOW_HASH_LEN == 48

		std::vector<byte> tmpm(msglen);
		std::vector<byte> tmpd(SHA2::SHA384_DIGEST_SIZE);

		memcpy(tmpm.data(), message, msglen);
		SHA2::Compute384(tmpm, 0, tmpm.size(), tmpd, 0);
		memcpy(digest, tmpd.data(), tmpd.size());

#else
		std::vector<byte> tmpm(msglen);
		std::vector<byte> tmpd(SHA2::SHA512_DIGEST_SIZE);

		memcpy(tmpm.data(), message, msglen);
		SHA2::Compute512(tmpm, 0, tmpm.size(), tmpd, 0);
		memcpy(digest, tmpd.data(), tmpd.size());

		//sha512_compute(digest, message, msglen);
#endif
	}

	static void expand_hash(uint8_t* digest, size_t dgtlen, const uint8_t* hash)
	{
		uint8_t temp[RAINBOW_HASH_LEN];
		size_t i;

		if (RAINBOW_HASH_LEN >= dgtlen)
		{
			for (i = 0; i < dgtlen; ++i)
			{
				digest[i] = hash[i];
			}
		}
		else
		{
			for (i = 0; i < RAINBOW_HASH_LEN; ++i)
			{
				digest[i] = hash[i];
			}

			dgtlen -= RAINBOW_HASH_LEN;

			while (RAINBOW_HASH_LEN <= dgtlen)
			{
				hash_execute(digest + RAINBOW_HASH_LEN, digest, RAINBOW_HASH_LEN);
				dgtlen -= RAINBOW_HASH_LEN;
				digest += RAINBOW_HASH_LEN;
			}

			if (dgtlen)
			{
				hash_execute(temp, digest, RAINBOW_HASH_LEN);

				for (i = 0; i < dgtlen; ++i)
				{
					digest[RAINBOW_HASH_LEN + i] = temp[i];
				}
			}
		}
	}

	static int32_t hash_msg(uint8_t* digest, size_t dgtlen, const uint8_t* message, size_t msglen)
	{
		uint8_t buf[RAINBOW_HASH_LEN] = { 0 };

		hash_execute(buf, message, msglen);
		expand_hash(digest, dgtlen, buf);

		return 0;
	}

	// utils_prng.c

	/*static int32_t prng_set(prng_t* ctx, const uint8_t* seed, size_t seedlen)
	{
		uint8_t tmps[48];
		size_t i;
		int32_t ret;

		ret = 0;

		if (seedlen >= 48)
		{
			for (i = 0; i < 48; ++i)
			{
				tmps[i] = seed[i];
			}
		}
		else
		{
			for (i = 0; i < seedlen; ++i)
			{
				tmps[i] = seed[i];
			}

			ret = hash_msg(tmps + seedlen, 48 - seedlen, seed, seedlen);
		}

		randombytes_init_with_state(ctx, tmps);

		return ret;
	}

	static int32_t prng_gen(prng_t* ctx, uint8_t* out, size_t outlen)
	{
		int32_t ret;

		ret = randombytes_with_state(ctx, out, outlen);

		return ret;
	}*/

	static void Expand()
	{

	}

public:

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, RainbowParameters Parameters)
	{
		PublicKey.resize(RAINBOW_PUBLICKEY_SIZE);
		PrivateKey.resize(RAINBOW_SECRETKEY_SIZE);
		rainbow_generate((uint8_t*)PublicKey.data(), (uint8_t*)PrivateKey.data(), Rng);
	}

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, RainbowParameters Parameters)
	{
		size_t smglen;

		smglen = 0;
		Signature.resize(RAINBOW_SIGNATURE_SIZE + Message.size());
		rainbow_sign((uint8_t*)Signature.data(), &smglen, (uint8_t*)Message.data(), Message.size(), (uint8_t*)PrivateKey.data());

		return (size_t)smglen;
	}

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, RainbowParameters Parameters)
	{
		size_t msglen;
		int32_t ret;

		msglen = 0;
		Message.resize(Signature.size() - RAINBOW_SIGNATURE_SIZE);
		ret = rainbow_verify((uint8_t*)Message.data(), &msglen, (uint8_t*)Signature.data(), Signature.size(), (uint8_t*)PublicKey.data());

		return ret == 0;
	}
};

NAMESPACE_RAINBOWEND
#endif
