#ifndef _CEX_MCENCRYPT3_H
#define _CEX_MCENCRYPT3_H

#include "CexDomain.h"
#include "IPrng.h"
//#include "params.h"
#include "util2.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class encrypt3
{
public:

	static void gen_e(std::vector<byte> &e, Prng::IPrng* r, size_t Dimension, size_t Factor)
	{
		int i, j, eq;
		//uint16_t ind[SYS_T];
		std::vector<ushort> ind(Factor);
		std::vector<ulong> e_int(64);
		uint64_t one = 1;
		uint64_t mask;
		std::vector<ulong> val(Factor);

		while (1)
		{
			//OQS_RAND_n(r, (uint8_t *)ind, sizeof(ind));
			r->Fill(ind, 0, ind.size());

			for (i = 0; i < Factor; i++)
				ind[i] &= (1 << Dimension) - 1;

			eq = 0;
			for (i = 1; i < Factor; i++)
			{
				for (j = 0; j < i; j++)
				{
					if (ind[i] == ind[j])
						eq = 1;
				}
			}

			if (eq == 0)
				break;
		}

		for (j = 0; j < Factor; j++)
			val[j] = one << (ind[j] & 63);

		for (i = 0; i < 64; i++)
		{
			e_int[i] = 0;

			for (j = 0; j < Factor; j++)
			{
				mask = i ^ (ind[j] >> 6);
				mask -= 1;
				mask >>= 63;
				mask = ~mask + 1;
				e_int[i] |= val[j] & mask;
			}
		}

		for (i = 0; i < 64; i++)
			util2::store8(e, i * 8, e_int[i]);
	}

//#define C ((PK_NCOLS + 63) / 64)
/*
#define PK_NROWS (SYS_T * GFBITS)					// 744 (M * T)
#define PK_NCOLS ((1 << GFBITS) - SYS_T * GFBITS)	// 3352 (1 << M) - (M * T)

#define IRR_BYTES (GFBITS * 8)						// 96
#define COND_BYTES (736 * 8)						// 5888 (736? PK_NROWS + 8) * 8
#define SYND_BYTES (PK_NROWS / 8)					// 93
*/
	static void syndrome(std::vector<byte> &s, const std::vector<byte> &pk, const std::vector<byte> &e, size_t Dimension, size_t Factor)
	{
		const size_t PKNROWS = (Factor * Dimension);
		const size_t PKNCOLS = ((1 << Dimension) - PKNROWS);
		const size_t SNDLEN = (PKNROWS / 8);
		const size_t ROWSZE = ((PKNCOLS + 63) / 64);

		int i, j, t;
		const unsigned char *e_ptr = e.data() + SNDLEN;
		std::vector<ulong> e_int(ROWSZE);
		std::vector<ulong> row_int(ROWSZE);
		std::vector<ulong> tmp(8);
		byte b;

		memcpy(s.data(), e.data(), SNDLEN);
		e_int[ROWSZE - 1] = 0;
		memcpy(e_int.data(), e_ptr, PKNCOLS / 8);

		for (i = 0; i < PKNROWS; i += 8)
		{
			for (t = 0; t < 8; t++) 
			{
				row_int[ROWSZE - 1] = 0;
				memcpy(row_int.data(), &pk[(i + t) * (PKNCOLS / 8)], PKNCOLS / 8);
				tmp[t] = 0;

				for (j = 0; j < ROWSZE; j++)
					tmp[t] ^= e_int[j] & row_int[j];
			}

			b = 0;

			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 32);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 16);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 8);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 4);

			for (t = 7; t >= 0; t--)
			{
				b <<= 1;
				b |= (0x6996 >> (tmp[t] & 0xF)) & 1;
			}

			s[i / 8] ^= b;
		}
	}

	static void encrypt(std::vector<byte> &s, std::vector<byte> &e, const std::vector<byte> &pk, Prng::IPrng* r, size_t Dimension, size_t Factor)
	{
		gen_e(e, r, Dimension, Factor);
		syndrome(s, pk, e, Dimension, Factor);
	}
};

NAMESPACE_MCELIECEEND
#endif