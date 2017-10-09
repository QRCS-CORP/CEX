#ifndef _CEX_PHFM12T62_H
#define _CEX_PHFM12T62_H

#include "CexDomain.h"
#include "GF.h"
#include "IDigest.h"
#include "IPrng.h"
#include "MPKCParamSet.h"

NAMESPACE_MCELIECE

/// <summary>
/// McEliece M12T62 paramaterized helper functions
/// </summary>
class PHFM12T62
{
public:

	/// <summary>
	/// 
	/// </summary>
	static const uint GF = 12;

	/// <summary>
	/// 
	/// </summary>
	static const int T = 62;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t PUBLICKEY_SIZE = 311736;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t MAXSEED_BYTES = 109;

	/// <summary>
	/// The byte size of A's forward message to host B
	/// </summary>
	static const size_t SECRETKEY_SIZE = 5984;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	/**
	* \internal
	*/

	void KeyGen(std::vector<byte> &PubKey, std::vector<byte> &PriKey, Prng::IPrng* Rng, bool Parallel)
	{
		while (1)
		{
			sk_gen(PubKey, Rng);

			if (pk_gen(PubKey, PriKey) == 0)
				break;
		}
	}

	void Decrypt()
	{

	}

	void Encrypt()
	{

	}

	void Initialize()
	{

	}

private:

	static const uint GFBITS = 12;
	static const uint SYS_T = 62;
	static const uint PK_NROWS = (T * GF);
	static const uint PK_NCOLS = ((1 << GF) - T * GF);	// 3352 (1 << M) - (M * T)
	static const uint IRR_BYTES = (GF * 8);				// 96
	static const uint COND_BYTES = (736 * 8);			// 5888 (736? PK_NROWS + 8) * 8
	static const uint SYND_BYTES = (PK_NROWS / 8);		// 93
	static const uint CRYPTO_SECRETKEYBYTES = (IRR_BYTES + COND_BYTES);	// 5984 (IRR_BYTES + COND_BYTES)
	static const uint CRYPTO_PUBLICKEYBYTES = 311736;	// 311736
	static const uint CRYPTO_BYTES = 109;				// 109


	static void sk_gen(std::vector<byte> &PriKey, Prng::IPrng* Rng)
	{
		std::vector<ulong> cond(COND_BYTES / 8);
		std::vector<ulong> sk_int(GFBITS);

		int i, j;

		std::vector<ushort> irr(SYS_T + 1); //63
		std::vector<ushort> f(SYS_T); //62

		while (1)
		{
			Fill<ushort>(f, 0, Rng);
			//OQS_RAND_n(r, (uint8_t *)f, sizeof(f));

			for (i = 0; i < SYS_T; i++)
				f[i] &= (1 << GFBITS) - 1;

			if (irr_gen(irr, f) == 0)
				break;
		}

		for (i = 0; i < GFBITS; i++)
		{
			sk_int[i] = 0;

			for (j = SYS_T; j >= 0; j--)
			{
				sk_int[i] <<= 1;
				sk_int[i] |= (irr[j] >> i) & 1;
			}

			store8(PriKey, i * 8, sk_int[i]);
		}


		Fill<ulong>(cond, 0, Rng);
		//OQS_RAND_n(r, (uint8_t *)cond, sizeof(cond));

		for (i = 0; i < COND_BYTES / 8; i++)
			store8(PriKey, IRR_BYTES + i * 8, cond[i]);
	}

	static int irr_gen(std::vector<ushort> &out, std::vector<ushort> &f)
	{
		int i, j, k, c;

		std::vector<std::vector<ushort>> mat(SYS_T + 1, std::vector<ushort>(SYS_T));
		//gf mat[SYS_T + 1][SYS_T];
		ushort mask, inv, t;

		// fill matrix

		mat[0][0] = 1;
		for (i = 1; i < SYS_T; i++)
			mat[0][i] = 0;

		for (i = 0; i < SYS_T; i++)
			mat[1][i] = f[i];

		for (j = 2; j <= SYS_T; j++)
			GF_mul(mat[j], mat[j - 1], f, GFBITS);

		// gaussian

		for (j = 0; j < SYS_T; j++)
		{
			for (k = j + 1; k < SYS_T; k++)
			{
				mask = gf_diff(mat[j][j], mat[j][k]);

				for (c = 0; c < SYS_T + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;
			}

			if (mat[j][j] == 0)
			{
				// return if not invertible
				return -1;
			}

			// compute inverse
			inv = gf_inv(mat[j][j], GFBITS);

			for (c = 0; c < SYS_T + 1; c++)
				mat[c][j] = gf_mul(mat[c][j], inv, GFBITS);

			//

			for (k = 0; k < SYS_T; k++) {
				t = mat[j][k];

				if (k != j)
				{
					for (c = 0; c < SYS_T + 1; c++)
						mat[c][k] ^= gf_mul(mat[c][j], t, GFBITS);
				}
			}
		}

		//

		for (i = 0; i < SYS_T; i++)
			out[i] = mat[SYS_T][i];

		out[SYS_T] = 1;

		return 0;
	}

	static void store8(std::vector<byte> &out, size_t offset, ulong in)
	{
		out[offset] = (in >> 0x00) & 0xFF;
		out[offset + 1] = (in >> 0x08) & 0xFF;
		out[offset + 2] = (in >> 0x10) & 0xFF;
		out[offset + 3] = (in >> 0x18) & 0xFF;
		out[offset + 4] = (in >> 0x20) & 0xFF;
		out[offset + 5] = (in >> 0x28) & 0xFF;
		out[offset + 6] = (in >> 0x30) & 0xFF;
		out[offset + 7] = (in >> 0x38) & 0xFF;
	}

	static uint64_t load8(std::vector<byte> &in)
	{
		int i;
		uint64_t ret = in[7];

		for (i = 6; i >= 0; i--)
		{
			ret <<= 8;
			ret |= in[i];
		}

		return ret;
	}

	template <class T>
	static void Fill(std::vector<T> &Output, size_t Offset, Prng::IPrng* Rng)
	{
		size_t bufSze = Output.size() * sizeof(T);
		std::vector<byte> buf(bufSze);
		Rng->GetBytes(buf);
		Utility::MemUtils::Copy(buf, 0, Output, Offset, bufSze);
	}
};

NAMESPACE_MCELIECEEND
#endif