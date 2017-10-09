#ifndef _CEX_SKGEN3_H
#define _CEX_SKGEN3_H

#include "CexDomain.h"
#include "gfm2.h"
#include "IPrng.h"
#include "util2.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class sk_gen3
{
public:
	static int irr_gen(std::vector<ushort> &out, std::vector<ushort> &f, size_t Dimension, size_t Factor)
	{
		int i, j, k, c;
		std::vector<std::vector<ushort>> mat(Factor + 1, std::vector<ushort>(Factor));
		ushort mask, inv, t;

		// fill matrix
		mat[0][0] = 1;
		for (i = 1; i < Factor; i++)
			mat[0][i] = 0;

		for (i = 0; i < Factor; i++)
			mat[1][i] = f[i];

		for (j = 2; j <= Factor; j++)
			gfm2::GF_mul(mat[j], mat[j - 1], f, Dimension);

		// gaussian
		for (j = 0; j < Factor; j++)
		{
			for (k = j + 1; k < Factor; k++)
			{
				mask = gfm2::gf_diff(mat[j][j], mat[j][k]);

				for (c = 0; c < Factor + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;
			}

			if (mat[j][j] == 0)
			{
				// return if not invertible
				return -1;
			}

			// compute inverse
			inv = gfm2::gf_inv(mat[j][j], Dimension);

			for (c = 0; c < Factor + 1; c++)
				mat[c][j] = gfm2::gf_mul(mat[c][j], inv, Dimension);

			for (k = 0; k < Factor; k++)
			{
				t = mat[j][k];

				if (k != j) {
					for (c = 0; c < Factor + 1; c++)
						mat[c][k] ^= gfm2::gf_mul(mat[c][j], t, Dimension);
				}
			}
		}

		for (i = 0; i < Factor; i++)
			out[i] = mat[Factor][i];

		out[Factor] = 1;

		return 0;
	}

	static void sk_gen(std::vector<byte> &sk, Prng::IPrng* r, size_t Dimension, size_t Factor)
	{
		//uint64_t cond[COND_BYTES / 8];
		const size_t CNDLEN = (Dimension * Factor) - 8;
		const size_t IRRLEN = Dimension * 8;
		std::vector<ulong> cond(CNDLEN);
		std::vector<ulong> sk_int(Dimension);

		int i, j;

		std::vector<ushort> irr(Factor + 1); //63
		//ushort f[Factor]; //62
		std::vector<ushort> f(Factor);

		while (1)
		{
			r->Fill(f, 0, f.size());
			//OQS_RAND_n(r, (uint8_t *)f, sizeof(f));

			for (i = 0; i < Factor; i++)
				f[i] &= (1 << Dimension) - 1;

			if (irr_gen(irr, f, Dimension, Factor) == 0)
				break;
		}

		for (i = 0; i < Dimension; i++)
		{
			sk_int[i] = 0;

			for (j = Factor; j >= 0; j--)
			{
				sk_int[i] <<= 1;
				sk_int[i] |= (irr[j] >> i) & 1;
			}

			util2::store8(sk, i * 8, sk_int[i]);
		}

		r->Fill(cond, 0, cond.size());
		//OQS_RAND_n(r, (uint8_t *)cond, sizeof(cond));

		for (i = 0; i < CNDLEN; i++)
			util2::store8(sk, IRRLEN + i * 8, cond[i]);
	}
};

NAMESPACE_MCELIECEEND
#endif