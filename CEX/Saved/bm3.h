#ifndef _CEX_BM3_H
#define _CEX_BM3_H

#include "CexDomain.h"
#include "gfm.h"
#include "GFVector.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class bm3
{
public:

	static void into_vec(std::vector<ulong> &out, ushort in, size_t Dimension)
	{
		for (size_t i = 0; i < Dimension; i++)
		{
			out[i] = (in >> i) & 1;
			out[i] = ~out[i] + 1;
		}
	}

	static ushort vec_reduce(std::vector<ulong> &prod, size_t Dimension)
	{
		int i;

		std::vector<ulong> tmp(Dimension);
		ushort ret = 0;

		for (i = 0; i < Dimension; i++)
		{
			tmp[i] = prod[i];
		}

		for (i = Dimension - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 32);
		for (i = Dimension - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 16);
		for (i = Dimension - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 8);
		for (i = Dimension - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 4);

		for (i = Dimension - 1; i >= 0; i--)
		{
			ret <<= 1;
			ret |= (0x6996 >> (tmp[i] & 0xF)) & 1;
		};

		return ret;
	}

	static ulong mask_nonzero_64bit(ushort a)
	{
		ulong ret = a;

		ret -= 1;
		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static ulong mask_leq_64bit(uint16_t a, uint16_t b)
	{
		ulong a_tmp = a;
		ulong b_tmp = b;
		ulong ret = b_tmp - a_tmp;

		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static void vec_cmov(std::vector<ulong> &out, std::vector<ulong> &in, ulong mask, size_t Dimension)
	{
		int i;

		for (i = 0; i < Dimension; i++)
			out[i] = (in[i] & mask) | (out[i] & ~mask);
	}

	static void bm(std::vector<ulong> &out, std::vector<std::vector<ulong>> &in, size_t Dimension, size_t T)
	{
		uint16_t i;
		uint16_t N, L;

		std::vector<ulong> c(Dimension);
		std::vector<ulong> B(Dimension);
		std::vector<ulong> prod(Dimension);
		std::vector<ulong> in_tmp(Dimension);
		std::vector<ulong> r_vec(Dimension);
		std::vector<ulong> C_tmp(Dimension);

		ulong mask_nz, mask_leq;
		uint16_t mask_16b;

		ushort d, b, b_inv, r;

		// init

		c[0] = 1;
		c[0] <<= 63;
		B[0] = 1;
		B[0] <<= 62;

		for (i = 1; i < Dimension; i++)
			B[i] = c[i] = 0;

		b = 1;
		L = 0;

		for (N = 0; N < T * 2; N++)
		{
			// computing d
			if (N < 64)
			{
				for (i = 0; i < Dimension; i++)
					in_tmp[i] = in[0][i] << (63 - N);
			}
			else
			{
				for (i = 0; i < Dimension; i++)
					in_tmp[i] = (in[0][i] >> (N - 63)) | (in[1][i] << (127 - N));
			}

			GfVector::vec_mul(prod, 0, c, 0, in_tmp, 0, Dimension);
			d = vec_reduce(prod, Dimension);

			// 3 cases
			b_inv = gfm::gf_inv(b);
			r = gfm::gf_mul(d, b_inv);
			into_vec(r_vec, r, Dimension);
			GfVector::vec_mul(C_tmp, 0, r_vec, 0, B, 0, Dimension);

			for (i = 0; i < Dimension; i++)
				C_tmp[i] ^= c[i];

			mask_nz = mask_nonzero_64bit(d);
			mask_leq = mask_leq_64bit(L * 2, N);
			mask_16b = (mask_nz & mask_leq) & 0xFFFF;

			vec_cmov(B, c, mask_nz & mask_leq, Dimension);
			GfVector::vec_copy(c, C_tmp, Dimension);

			b = (d & mask_16b) | (b & ~mask_16b);
			L = ((N + 1 - L) & mask_16b) | (L & ~mask_16b);

			for (i = 0; i < Dimension; i++)
				B[i] >>= 1;
		}

		GfVector::vec_copy(out, c, Dimension);

		for (i = 0; i < Dimension; i++)
			out[i] >>= 64 - (T + 1);
	}
};

NAMESPACE_MCELIECEEND
#endif