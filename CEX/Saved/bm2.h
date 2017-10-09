#ifndef _CEX_BM_H
#define _CEX_BM_H

#include "CexDomain.h"
#include "params.h"
#include "gfm.h"
#include "vec.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class bm2
{
public:

	static void into_vec(uint64_t *out, gf in) 
	{
		int i;

		for (i = 0; i < GFBITS; i++) 
		{
			out[i] = (in >> i) & 1;
			out[i] = ~out[i] + 1;
		}
	}

	static gf vec_reduce(uint64_t *prod) 
	{
		int i;

		uint64_t tmp[GFBITS];
		gf ret = 0;

		for (i = 0; i < GFBITS; i++) 
		{
			tmp[i] = prod[i];
		}

		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 32);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 16);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 8);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 4);

		for (i = GFBITS - 1; i >= 0; i--) 
		{
			ret <<= 1;
			ret |= (0x6996 >> (tmp[i] & 0xF)) & 1;
		};

		return ret;
	}

	static uint64_t mask_nonzero_64bit(gf a) 
	{
		uint64_t ret = a;

		ret -= 1;
		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static uint64_t mask_leq_64bit(uint16_t a, uint16_t b) 
	{
		uint64_t a_tmp = a;
		uint64_t b_tmp = b;
		uint64_t ret = b_tmp - a_tmp;

		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static void vec_cmov(uint64_t *out, uint64_t *in, uint64_t mask) 
	{
		int i;

		for (i = 0; i < GFBITS; i++)
			out[i] = (in[i] & mask) | (out[i] & ~mask);
	}

	static void bm(uint64_t out[GFBITS], uint64_t in[][GFBITS])
	{
		uint16_t i;
		uint16_t N, L;

		uint64_t c[GFBITS];
		uint64_t B[GFBITS];
		uint64_t prod[GFBITS];
		uint64_t in_tmp[GFBITS], r_vec[GFBITS], C_tmp[GFBITS];

		uint64_t mask_nz, mask_leq;
		uint16_t mask_16b;

		gf d, b, b_inv, r;

		// init

		c[0] = 1;
		c[0] <<= 63;
		B[0] = 1;
		B[0] <<= 62;

		for (i = 1; i < GFBITS; i++)
			B[i] = c[i] = 0;

		b = 1;
		L = 0;

		for (N = 0; N < SYS_T * 2; N++) 
		{
			// computing d
			if (N < 64)
			{
				for (i = 0; i < GFBITS; i++)
					in_tmp[i] = in[0][i] << (63 - N);
			}
			else
			{
				for (i = 0; i < GFBITS; i++)
					in_tmp[i] = (in[0][i] >> (N - 63)) | (in[1][i] << (127 - N));
			}

			vec::vec_mul(prod, c, in_tmp);
			d = vec_reduce(prod);

			// 3 cases
			b_inv = gfm::gf_inv(b);
			r = gfm::gf_mul(d, b_inv);
			into_vec(r_vec, r);
			vec::vec_mul(C_tmp, r_vec, B);

			for (i = 0; i < GFBITS; i++)
				C_tmp[i] ^= c[i];

			mask_nz = mask_nonzero_64bit(d);
			mask_leq = mask_leq_64bit(L * 2, N);
			mask_16b = (mask_nz & mask_leq) & 0xFFFF;

			vec_cmov(B, c, mask_nz & mask_leq);
			vec::vec_copy(c, C_tmp);

			b = (d & mask_16b) | (b & ~mask_16b);
			L = ((N + 1 - L) & mask_16b) | (L & ~mask_16b);

			for (i = 0; i < GFBITS; i++)
				B[i] >>= 1;
		}

		vec::vec_copy(out, c);

		for (i = 0; i < GFBITS; i++)
			out[i] >>= 64 - (SYS_T + 1);
	}
};

NAMESPACE_MCELIECEEND
#endif