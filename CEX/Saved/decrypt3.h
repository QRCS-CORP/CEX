#ifndef _CEX_MCDECRYPT3_H
#define _CEX_MCDECRYPT3_H

#include "CexDomain.h"
#include "bm3.h"
#include "Benes2.h"
#include "fft3.h"
#include "fft_tr3.h"
//#include "params.h"
#include "Transpose2.h"
#include "util2.h"
#include "GfVector.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class decrypt3
{
public:

	static void scaling(std::vector<std::vector<ulong>> &out, std::vector<std::vector<ulong>> &inv, const std::vector<byte> &sk, std::vector<ulong> &recv, size_t Dimension)
	{
		int i, j;

		std::vector<ulong> sk_int(Dimension);
		std::vector<std::vector<ulong>> eval(64, std::vector<ulong>(Dimension));
		std::vector<ulong> tmp(Dimension);

		// computing inverses
		for (i = 0; i < Dimension; i++)
			sk_int[i] = util2::load8(sk, i * 8);

		fft3::fft(eval, sk_int, Dimension);

		for (i = 0; i < 64; i++)
			GfVector::vec_sq(eval[i], eval[i], Dimension);

		GfVector::vec_copy(inv[0], eval[0], Dimension);

		for (i = 1; i < 64; i++)
			GfVector::vec_mul(inv[i], 0, inv[i - 1], 0, eval[i], 0, Dimension);

		GfVector::vec_inv(tmp, inv[63], Dimension);

		for (i = 62; i >= 0; i--)
		{
			GfVector::vec_mul(inv[i + 1], 0, tmp, 0, inv[i], 0, Dimension);
			GfVector::vec_mul(tmp, 0, tmp, 0, eval[i + 1], 0, Dimension);
		}

		GfVector::vec_copy(inv[0], tmp, Dimension);

		for (i = 0; i < 64; i++)
		{
			for (j = 0; j < Dimension; j++)
				out[i][j] = inv[i][j] & recv[i];
		}
	}

	static void scaling_inv(std::vector<std::vector<ulong>> &out, std::vector<std::vector<ulong>> &inv, std::vector<ulong> &recv, size_t Dimension)
	{
		int i, j;

		for (i = 0; i < 64; i++)
		{
			for (j = 0; j < Dimension; j++)
				out[i][j] = inv[i][j] & recv[i];
		}
	}
/*
#define PK_NROWS (SYS_T * GFBITS)					// 744 (M * T)
#define PK_NCOLS ((1 << GFBITS) - SYS_T * GFBITS)	// 3352 (1 << M) - (M * T)

#define IRR_BYTES (GFBITS * 8)						// 96
#define COND_BYTES (736 * 8)						// 5888 (736? PK_NROWS + 8) * 8
#define SYND_BYTES (PK_NROWS / 8)					// 93
*/
	static void preprocess(std::vector<ulong> &recv, const std::vector<byte> &s, size_t Dimension, size_t T)
	{
		int i;
		const size_t SYNLEN = ((T * Dimension) / 8);

		for (i = 0; i < 64; i++)
			recv[i] = 0;

		for (i = 0; i < SYNLEN / 8; i++)
			recv[i] = util2::load8(s, i * 8);

		for (i = SYNLEN % 8 - 1; i >= 0; i--)
		{
			recv[SYNLEN / 8] <<= 8;
			recv[SYNLEN / 8] |= s[SYNLEN / 8 * 8 + i];
		}
	}

	static void acc(std::vector<ulong> &c, ulong v)
	{
		int i;

		uint64_t carry = v;
		uint64_t t;

		for (i = 0; i < 8; i++)
		{
			t = c[i] ^ carry;
			carry = c[i] & carry;
			c[i] = t;
		}
	}

	static int weight(std::vector<ulong> &v)
	{
		int i;
		int w;

		/*union
		{
			uint64_t data_64[8];
			uint8_t data_8[64];
		} counter;

		//

		for (i = 0; i < 8; i++)
			counter.data_64[i] = 0;

		for (i = 0; i < 64; i++)
			acc(counter.data_64, v[i]);

		transpose::transpose_8x64(counter.data_64);

		w = 0;
		for (i = 0; i < 64; i++)
			w += counter.data_8[i];*/

		std::vector<ulong> wdata(8, 0);

		for (i = 0; i < 64; i++)
			acc(wdata, v[i]);

		Transpose2::transpose_8x64(wdata);

		w = 0;
		for (i = 0; i < 64; i++)
			w += ((byte*)wdata.data())[i];

		return w;
	}

	static void syndrome_adjust(std::vector<std::vector<ulong>> &in, size_t Dimension, size_t T)
	{
		int i;

		for (i = 0; i < Dimension; i++) 
		{
			in[1][i] <<= (128 - T * 2);
			in[1][i] >>= (128 - T * 2);
		}
	}

	static int decrypt(std::vector<byte> &e, const std::vector<byte> &sk, const std::vector<byte> &s, size_t Dimension, size_t T)
	{
		int i, j;
		uint64_t t;
		uint64_t diff;
		const size_t CNDLEN = (Dimension * T) - 8;
		const size_t IRRLEN = Dimension * 8;

		std::vector<std::vector<ulong>> inv(64, std::vector<ulong>(Dimension));
		std::vector<std::vector<ulong>> scaled(64, std::vector<ulong>(Dimension));
		std::vector<std::vector<ulong>> eval(64, std::vector<ulong>(Dimension));
		std::vector<ulong> error(64);
		std::vector<std::vector<ulong>> s_priv(2, std::vector<ulong>(Dimension));
		std::vector<std::vector<ulong>> s_priv_cmp(2, std::vector<ulong>(Dimension));
		std::vector<ulong> locator(Dimension);
		std::vector<ulong> recv(64);
		std::vector<ulong> cond(CNDLEN);

		//uint64_t inv[64][GFBITS];
		//uint64_t scaled[64][GFBITS];
		//uint64_t eval[64][GFBITS];
		//uint64_t error[64];
		//uint64_t s_priv[2][GFBITS];
		//uint64_t s_priv_cmp[2][GFBITS];
		//uint64_t locator[GFBITS];
		//uint64_t recv[64];
		//uint64_t cond[COND_BYTES / 8];

		int xx = 0;
		for (size_t i = 0; i < 100; ++i)
		{
			xx ^= sk[i];
		}


		for (i = 0; i < CNDLEN; i++)
			cond[i] = util2::load8(sk, IRRLEN + i * 8);

		preprocess(recv, s, Dimension, T);
		Benes2::benes_compact(recv, cond, 1);
		scaling(scaled, inv, sk, recv, Dimension); // scaling
		fft_tr3::fft_tr(s_priv, scaled, Dimension);         // transposed FFT
		syndrome_adjust(s_priv, Dimension, T);
		bm3::bm(locator, s_priv, Dimension, T); // Berlekamp Massey
		fft3::fft(eval, locator, Dimension);  // FFT

		for (i = 0; i < 64; i++)
		{
			error[i] = GfVector::vec_or(eval[i], Dimension);
			error[i] = ~error[i];
		}

		{
			// reencrypt
			scaling_inv(scaled, inv, error, Dimension);
			fft_tr3::fft_tr(s_priv_cmp, scaled, Dimension);
			syndrome_adjust(s_priv_cmp, Dimension, T);

			diff = 0;
			for (i = 0; i < 2; i++)
			{
				for (j = 0; j < Dimension; j++)
					diff |= s_priv[i][j] ^ s_priv_cmp[i][j];
			}

			diff |= diff >> 32;
			diff |= diff >> 16;
			diff |= diff >> 8;
			t = diff & 0xFF;
		}

		Benes2::benes_compact(error, cond, 0);

		for (i = 0; i < 64; i++)
			util2::store8(e, i * 8, error[i]);

		t |= weight(error) ^ T;
		t -= 1;
		t >>= 63;

		return (t - 1);
	}
};

NAMESPACE_MCELIECEEND
#endif