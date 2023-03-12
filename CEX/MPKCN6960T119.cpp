#include "MPKCN6960T119.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "MPKCUtils.h"

NAMESPACE_MCELIECE

using Tools::IntegerTools;
using Digest::Keccak;
using Tools::MemoryTools;

static const int32_t MCELIECE_N6960T119_GFBITS = 13;
static const int32_t MCELIECE_N6960T119_SYS_N = 6960;
static const int32_t MCELIECE_N6960T119_SYS_T = 119;
static const int32_t MCELIECE_N6960T119_COND_BYTES = ((1 << (MCELIECE_N6960T119_GFBITS - 4)) * (2 * MCELIECE_N6960T119_GFBITS - 1));
static const int32_t MCELIECE_N6960T119_IRR_BYTES = (MCELIECE_N6960T119_SYS_T * 2);
static const int32_t MCELIECE_N6960T119_PK_NROWS = (MCELIECE_N6960T119_SYS_T * MCELIECE_N6960T119_GFBITS);
static const int32_t MCELIECE_N6960T119_PK_NCOLS = (MCELIECE_N6960T119_SYS_N - MCELIECE_N6960T119_PK_NROWS);
static const int32_t MCELIECE_N6960T119_PK_ROW_BYTES = ((MCELIECE_N6960T119_PK_NCOLS + 7) / 8);
static const int32_t MCELIECE_N6960T119_SYND_BYTES = ((MCELIECE_N6960T119_PK_NROWS + 7) / 8);
static const int32_t MCELIECE_N6960T119_GFMASK((1 << MCELIECE_N6960T119_GFBITS) - 1);
static const int32_t MCELIECE_N6960T119_GENITR_MAX = 100;

void MPKCN6960T119::GfMul(uint16_t* Output, const uint16_t* Input0, const uint16_t* Input1)
{
	// input: in0, in1 in GF((2^m)^t)
	// output: out = in0*in1

	uint16_t prod[MCELIECE_N6960T119_SYS_T * 2 - 1] = { 0 };
	size_t i;
	size_t j;

	for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
	{
		for (j = 0; j < MCELIECE_N6960T119_SYS_T; ++j)
		{
			prod[i + j] ^= MPKCUtils::GfMultiply(Input0[i], Input1[j]);
		}
	}

	for (i = (MCELIECE_N6960T119_SYS_T - 1) * 2; i >= MCELIECE_N6960T119_SYS_T; --i)
	{
		prod[i - MCELIECE_N6960T119_SYS_T + 8] ^= prod[i];
		prod[i - MCELIECE_N6960T119_SYS_T] ^= prod[i];
	}

	MemoryTools::CopyRaw((uint8_t*)prod, (uint8_t*)Output, MCELIECE_N6960T119_SYS_T * sizeof(uint16_t));
}

void MPKCN6960T119::SupportGen(uint16_t* S, const uint8_t* C)
{
	// input: condition bits c output: support s

	uint8_t L[MCELIECE_N6960T119_GFBITS][(1 << MCELIECE_N6960T119_GFBITS) / 8] = { 0 };
	size_t i;
	size_t j;
	uint16_t a;

	for (i = 0; i < (1 << MCELIECE_N6960T119_GFBITS); ++i)
	{
		a = MPKCUtils::BitReverse((uint16_t)i);

		for (j = 0; j < MCELIECE_N6960T119_GFBITS; ++j)
		{
			L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
		}
	}

	for (j = 0; j < MCELIECE_N6960T119_GFBITS; ++j)
	{
		MPKCUtils::ApplyBenes(L[j], C, 0);
	}

	for (i = 0; i < MCELIECE_N6960T119_SYS_N; ++i)
	{
		S[i] = 0;
		j = MCELIECE_N6960T119_GFBITS;

		do
		{
			--j;
			S[i] <<= 1;
			S[i] |= (L[j][i / 8] >> (i % 8)) & 1;
		} while (j != 0);
	}
}

int32_t MPKCN6960T119::Decrypt(uint8_t* E, const uint8_t* Sk, const uint8_t* C)
{
	// Niederreiter decryption with the Berlekamp decoder.
	// input: sk, secret key c, ciphertext
	// output: e, error vector
	// return: 0 for success; 1 for failure

	uint16_t g[MCELIECE_N6960T119_SYS_T + 1] = { 0 };
	uint16_t L[MCELIECE_N6960T119_SYS_N];
	uint16_t s[MCELIECE_N6960T119_SYS_T * 2];
	uint16_t s_cmp[MCELIECE_N6960T119_SYS_T * 2];
	uint16_t locator[MCELIECE_N6960T119_SYS_T + 1];
	uint16_t images[MCELIECE_N6960T119_SYS_N];
	uint8_t r[MCELIECE_N6960T119_SYS_N / 8];
	int32_t i;
	int32_t w;
	uint16_t check;
	uint16_t t;

	w = 0;
	MemoryTools::CopyRaw((uint8_t*)C, (uint8_t*)r, MCELIECE_N6960T119_SYND_BYTES);
	MemoryTools::ClearRaw(r + MCELIECE_N6960T119_SYND_BYTES, (MCELIECE_N6960T119_SYS_N / 8) - MCELIECE_N6960T119_SYND_BYTES);

	for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
	{
		g[i] = MPKCUtils::LoadGf(Sk);
		Sk += 2;
	}

	g[MCELIECE_N6960T119_SYS_T] = 1;
	SupportGen(L, Sk);
	MPKCUtils::Synd(s, g, L, r, MCELIECE_N6960T119_SYS_N, MCELIECE_N6960T119_SYS_T);
	MPKCUtils::Bm(locator, s, MCELIECE_N6960T119_SYS_T);
	MPKCUtils::Root(images, locator, L, MCELIECE_N6960T119_SYS_N, MCELIECE_N6960T119_SYS_T);

	MemoryTools::ClearRaw(E, MCELIECE_N6960T119_SYS_N / 8);

	for (i = 0; i < MCELIECE_N6960T119_SYS_N; ++i)
	{
		t = MPKCUtils::GfIsZero(images[i]) & 1;
		E[i / 8] |= t << (i % 8);
		w += t;
	}

	MPKCUtils::Synd(s_cmp, g, L, E, MCELIECE_N6960T119_SYS_N, MCELIECE_N6960T119_SYS_T);
	check = (uint16_t)w;
	check ^= MCELIECE_N6960T119_SYS_T;

	for (i = 0; i < MCELIECE_N6960T119_SYS_T * 2; ++i)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15;

	return (check ^ 1);
}

void MPKCN6960T119::GenE(uint8_t* E, std::unique_ptr<IPrng> &Rng)
{
	// output: e, an error vector of weight t
	uint16_t ind[MCELIECE_N6960T119_SYS_T] = { 0 };
	uint8_t val[MCELIECE_N6960T119_SYS_T] = { 0 };
	size_t eq;
	size_t i;
	size_t j;
	uint8_t mask;
	size_t count;
	uint16_t nrnd[MCELIECE_N6960T119_SYS_T * 2] = { 0 };
	std::vector<uint8_t> brnd(MCELIECE_N6960T119_SYS_T * 2 * sizeof(uint16_t));

	while (true)
	{
		Rng->Fill(brnd, 0, brnd.size());

		for (i = 0; i < MCELIECE_N6960T119_SYS_T * 2; ++i)
		{
			nrnd[i] = MPKCUtils::LoadGf(brnd.data() + (i * 2));
		}

		// moving and counting indices in the correct range

		count = 0;

		for (i = 0; i < MCELIECE_N6960T119_SYS_T * 2; ++i)
		{
			if (nrnd[i] < MCELIECE_N6960T119_SYS_N)
			{
				ind[count] = nrnd[i];
				++count;

				if (count >= MCELIECE_N6960T119_SYS_T)
				{
					break;
				}
			}
		}

		if (count < MCELIECE_N6960T119_SYS_T)
		{
			continue;
		}

		// check for repetition

		eq = 0;

		for (i = 1; i < MCELIECE_N6960T119_SYS_T; ++i)
		{
			for (j = 0; j < i; ++j)
			{
				if (ind[i] == ind[j])
				{
					eq = 1;
					break;
				}
			}
		}

		if (eq == 0)
		{
			break;
		}
	}

	for (j = 0; j < MCELIECE_N6960T119_SYS_T; ++j)
	{
		val[j] = (uint8_t)(1 << (ind[j] & 7));
	}

	for (i = 0; i < MCELIECE_N6960T119_SYS_N / 8; ++i)
	{
		E[i] = 0;

		for (j = 0; j < MCELIECE_N6960T119_SYS_T; ++j)
		{
			mask = MPKCUtils::SameMask((uint16_t)i, (ind[j] >> 3));
			E[i] |= val[j] & mask;
		}
	}
}

void MPKCN6960T119::Syndrome(uint8_t* S, const uint8_t* Pk, const uint8_t* E)
{
	// input: public key pk, error vector e
	// output: Syndrome s

	uint8_t row[MCELIECE_N6960T119_SYS_N / 8];
	const uint8_t* pk_ptr = Pk;
	size_t j;
	uint8_t b;
	int32_t tail;

	tail = MCELIECE_N6960T119_PK_NROWS % 8;
	MemoryTools::ClearRaw(S, MCELIECE_N6960T119_SYND_BYTES);

	for (size_t i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
	{
		MemoryTools::ClearRaw(row, MCELIECE_N6960T119_SYS_N / 8);

		for (j = 0; j < MCELIECE_N6960T119_PK_ROW_BYTES; ++j)
		{
			row[MCELIECE_N6960T119_SYS_N / 8 - MCELIECE_N6960T119_PK_ROW_BYTES + j] = pk_ptr[j];
		}

		for (j = MCELIECE_N6960T119_SYS_N / 8 - 1; j >= MCELIECE_N6960T119_SYS_N / 8 - MCELIECE_N6960T119_PK_ROW_BYTES; --j)
		{
			row[j] = (uint8_t)((row[j] << tail) | (row[j - 1] >> (8 - tail)));
		}

		row[i / 8] |= 1 << (i % 8);
		b = 0;

		for (j = 0; j < MCELIECE_N6960T119_SYS_N / 8; ++j)
		{
			b ^= row[j] & E[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;
		S[i / 8] |= (b << (i % 8));

		pk_ptr += MCELIECE_N6960T119_PK_ROW_BYTES;
	}
}

void MPKCN6960T119::Encrypt(uint8_t* S, const uint8_t* Pk, uint8_t* E, std::unique_ptr<IPrng> &Rng)
{
	GenE(E, Rng);
	Syndrome(S, Pk, E);
}

int32_t MPKCN6960T119::CheckCPadding(const uint8_t* C)
{
	// Note artifact, no longer used
	// check if the padding bits of c are all zero
	uint8_t b;
	int32_t ret;

	b = C[MCELIECE_N6960T119_SYND_BYTES - 1] >> (MCELIECE_N6960T119_PK_NROWS % 8);
	b -= 1;
	b >>= 7;
	ret = b;

	return (ret - 1);
}

int32_t MPKCN6960T119::CheckPkPadding(const uint8_t* Pk)
{
	// Note artifact, no longer used
	uint8_t b;
	int32_t ret;

	b = 0;

	for (size_t i = 0; i < MCELIECE_N6960T119_PK_NROWS; i++)
	{
		b |= Pk[i * MCELIECE_N6960T119_PK_ROW_BYTES + MCELIECE_N6960T119_PK_ROW_BYTES - 1];
	}

	b >>= (MCELIECE_N6960T119_PK_NCOLS % 8);
	b -= 1;
	b >>= 7;
	ret = b;

	return (ret - 1);
}

int32_t MPKCN6960T119::PkGen(uint8_t* Pk, const uint8_t* Sk, const uint32_t* Perm, int16_t* Pi)
{
	// input: secret key sk output: public key pk

	uint64_t buf[1 << MCELIECE_N6960T119_GFBITS] = { 0 };
	uint16_t g[MCELIECE_N6960T119_SYS_T + 1] = { 0 };	// Goppa polynomial
	uint16_t L[MCELIECE_N6960T119_SYS_N] = { 0 };		// support
	uint16_t inv[MCELIECE_N6960T119_SYS_N];
	uint8_t** mat;
	size_t i;
	size_t j;
	size_t k;
	size_t col;
	size_t row;
	int32_t res;
	uint8_t b;
	uint8_t mask;
	bool balc;
	uint8_t* pk_ptr = Pk;
	int32_t tail;

	res = -1;

	mat = (uint8_t**)MemoryTools::Malloc(MCELIECE_N6960T119_PK_NROWS * sizeof(uint8_t*));

	if (mat != NULL)
	{
		balc = true;

		for (i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
		{
			mat[i] = (uint8_t*)MemoryTools::Malloc(MCELIECE_N6960T119_SYS_N / 8);

			if (mat[i] == NULL)
			{
				balc = false;
				break;
			}
		}

		if (balc == true)
		{
			g[MCELIECE_N6960T119_SYS_T] = 1;

			for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
			{
				g[i] = MPKCUtils::LoadGf(Sk); Sk += 2;
			}

			for (i = 0; i < (1 << MCELIECE_N6960T119_GFBITS); i++)
			{
				buf[i] = Perm[i];
				buf[i] <<= 31;
				buf[i] |= i;
			}

			MPKCUtils::Sort64(buf, 1 << MCELIECE_N6960T119_GFBITS);

			for (i = 1; i < (1 << MCELIECE_N6960T119_GFBITS); ++i)
			{
				if ((buf[i - 1] >> 31) == (buf[i] >> 31))
				{
					res = -2;
					break;
				}
			}

			if (res != -2)
			{
				for (i = 0; i < (1 << MCELIECE_N6960T119_GFBITS); ++i)
				{
					Pi[i] = buf[i] & MCELIECE_N6960T119_GFMASK;
				}

				for (i = 0; i < MCELIECE_N6960T119_SYS_N; ++i)
				{
					L[i] = MPKCUtils::BitReverse(Pi[i]);
				}

				// filling the matrix

				MPKCUtils::Root(inv, g, L, MCELIECE_N6960T119_SYS_N, MCELIECE_N6960T119_SYS_T);

				for (i = 0; i < MCELIECE_N6960T119_SYS_N; ++i)
				{
					inv[i] = MPKCUtils::GfInv(inv[i]);
				}

				for (i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
				{
					for (j = 0; j < MCELIECE_N6960T119_SYS_N / 8; ++j)
					{
						mat[i][j] = 0;
					}
				}

				for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
				{
					for (j = 0; j < MCELIECE_N6960T119_SYS_N; j += 8)
					{
						for (k = 0; k < MCELIECE_N6960T119_GFBITS; ++k)
						{
							b = (inv[j + 7] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 6] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 5] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 4] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 3] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 2] >> k) & 1;
							b <<= 1;
							b |= (inv[j + 1] >> k) & 1;
							b <<= 1;
							b |= (inv[j] >> k) & 1;

							mat[i * MCELIECE_N6960T119_GFBITS + k][j / 8] = b;
						}
					}

					for (j = 0; j < MCELIECE_N6960T119_SYS_N; ++j)
					{
						inv[j] = MPKCUtils::GfMultiply(inv[j], L[j]);
					}
				}

				// gaussian elimination

				for (i = 0; i < (MCELIECE_N6960T119_PK_NROWS + 7) / 8; ++i)
				{
					for (j = 0; j < 8; ++j)
					{
						row = i * 8 + j;

						if (row >= MCELIECE_N6960T119_PK_NROWS)
						{
							break;
						}

						for (k = row + 1; k < MCELIECE_N6960T119_PK_NROWS; ++k)
						{
							mask = mat[row][i] ^ mat[k][i];
							mask >>= j;
							mask &= 1;
							mask = -mask;

							for (col = 0; col < MCELIECE_N6960T119_SYS_N / 8; ++col)
							{
								mat[row][col] ^= mat[k][col] & mask;
							}
						}

						if (((mat[row][i] >> j) & 1) == 0) // return if not systematic
						{
							for (i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
							{
								MemoryTools::MallocFree(mat[i]);
							}

							MemoryTools::MallocFree(mat);

							return -1;
						}

						for (k = 0; k < MCELIECE_N6960T119_PK_NROWS; ++k)
						{
							if (k != row)
							{
								mask = mat[k][i] >> j;
								mask &= 1;
								mask = -mask;

								for (col = 0; col < MCELIECE_N6960T119_SYS_N / 8; ++col)
								{
									mat[k][col] ^= mat[row][col] & mask;
								}
							}
						}
					}
				}

				tail = MCELIECE_N6960T119_PK_NROWS % 8;

				for (i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
				{
					for (j = (MCELIECE_N6960T119_PK_NROWS - 1) / 8; j < MCELIECE_N6960T119_SYS_N / 8 - 1; ++j)
					{
						*pk_ptr = (uint8_t)((mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail)));
						++pk_ptr;
					}

					*pk_ptr = (mat[i][j] >> tail);
					++pk_ptr;
				}
			}

			res = 0;
		}

		for (i = 0; i < MCELIECE_N6960T119_PK_NROWS; ++i)
		{
			MemoryTools::MallocFree(mat[i]);
		}

		MemoryTools::MallocFree(mat);
	}

	return res;
}

int32_t MPKCN6960T119::GenPolyGen(uint16_t* Output, const uint16_t* F)
{
	// input: f, element in GF((2^m)^t)
	// output: out, minimal polynomial of f
	// return: 0 for success and -1 for failure

	uint16_t mat[MCELIECE_N6960T119_SYS_T + 1][MCELIECE_N6960T119_SYS_T] = { 0 };
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	int32_t res;
	uint16_t inv;
	uint16_t mask;
	uint16_t t;

	// fill matrix

	res = 0;
	mat[0][0] = 1;

	for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
	{
		mat[1][i] = F[i];
	}

	for (j = 2; j <= MCELIECE_N6960T119_SYS_T; ++j)
	{
		GfMul(mat[j], mat[j - 1], F);
	}

	// gaussian

	for (j = 0; j < MCELIECE_N6960T119_SYS_T; ++j)
	{
		for (k = j + 1; k < MCELIECE_N6960T119_SYS_T; ++k)
		{
			mask = MPKCUtils::GfIsZero(mat[j][j]);

			for (c = j; c < MCELIECE_N6960T119_SYS_T + 1; ++c)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if (mat[j][j] != 0)
		{
			inv = MPKCUtils::GfInv(mat[j][j]);

			for (c = j; c < MCELIECE_N6960T119_SYS_T + 1; ++c)
			{
				mat[c][j] = MPKCUtils::GfMultiply(mat[c][j], inv);
			}

			for (k = 0; k < MCELIECE_N6960T119_SYS_T; ++k)
			{
				if (k != j)
				{
					t = mat[j][k];

					for (c = j; c < MCELIECE_N6960T119_SYS_T + 1; ++c)
					{
						mat[c][k] ^= MPKCUtils::GfMultiply(mat[c][j], t);
					}
				}
			}
		}
		else
		{
			// return if not systematic
			res = -1;
			break;
		}

		for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
		{
			Output[i] = mat[MCELIECE_N6960T119_SYS_T][i];
		}
	}

	return res;
}

bool MPKCN6960T119::Decapsulate(const std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
{
	std::vector<uint8_t> conf(32);
	std::vector<uint8_t> preimage(1 + MCELIECE_N6960T119_SYS_N / 8 + (MCELIECE_N6960T119_SYND_BYTES + 32));
	std::vector<uint8_t> twoe(1 + MCELIECE_N6960T119_SYS_N / 8);
	const uint8_t* sk = PrivateKey.data();
	const uint8_t* s = sk + 40 + MCELIECE_N6960T119_IRR_BYTES + MCELIECE_N6960T119_COND_BYTES;
	size_t i;
	uint16_t m;
	uint8_t ret_confirm;
	uint8_t ret_decrypt;
	uint8_t* e = twoe.data() + 1;
	uint8_t* x = preimage.data();
	int32_t padding_ok;
	uint8_t mask;

	padding_ok = CheckCPadding(CipherText.data());

	twoe[0] = 2;
	ret_confirm = 0;
	ret_decrypt = (uint8_t)Decrypt(e, (sk + 40), CipherText.data());
	Keccak::XOFP1600(twoe, 0, twoe.size(), conf, 0, conf.size(), Keccak::KECCAK256_RATE_SIZE);

	for (i = 0; i < 32; ++i)
	{
		ret_confirm |= conf[i] ^ CipherText[MCELIECE_N6960T119_SYND_BYTES + i];
	}

	m = ret_decrypt | ret_confirm;
	m -= 1;
	m >>= 8;

	*x = m & 1;
	++x;

	for (i = 0; i < MCELIECE_N6960T119_SYS_N / 8; ++i)
	{
		*x = (~m & s[i]) | (m & e[i]);
		++x;
	}

	for (i = 0; i < MCELIECE_N6960T119_SYND_BYTES + 32; ++i)
	{
		*x = CipherText[i];
		++x;
	}

	Keccak::XOFP1600(preimage, 0, preimage.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);

	// clear outputs (set to all 1's) if padding bits are not all zero
	mask = (uint8_t)padding_ok;

	for (i = 0; i < 32; ++i)
	{
		SharedSecret[i] |= mask;
	}

	return ((ret_decrypt + ret_confirm + padding_ok) == 0);
}

bool MPKCN6960T119::Encapsulate(const std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret, std::unique_ptr<IPrng> &Rng)
{
	std::vector<uint8_t> oneec(1 + MCELIECE_N6960T119_SYS_N / 8 + (MCELIECE_N6960T119_SYND_BYTES + 32));
	std::vector<uint8_t> twoe(1 + MCELIECE_N6960T119_SYS_N / 8);
	uint8_t* e = twoe.data() + 1;
	uint8_t* c = CipherText.data();
	const uint8_t* pk = PublicKey.data();
	uint8_t mask;
	int32_t i;
	int32_t padding_ok;

	padding_ok = CheckPkPadding(pk);

	oneec[0] = 1;
	twoe[0] = 2;
	Encrypt(c, pk, e, Rng);

	Keccak::XOFP1600(twoe, 0, twoe.size(), CipherText, MCELIECE_N6960T119_SYND_BYTES, 32, Keccak::KECCAK256_RATE_SIZE);
	MemoryTools::CopyRaw(e, oneec.data() + 1, MCELIECE_N6960T119_SYS_N / 8);
	MemoryTools::CopyRaw(c, oneec.data() + 1 + MCELIECE_N6960T119_SYS_N / 8, MCELIECE_N6960T119_SYND_BYTES + 32);
	Keccak::XOFP1600(oneec, 0, oneec.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);

	mask = padding_ok;
	mask ^= 0xFF;

	for (i = 0; i < MCELIECE_N6960T119_SYND_BYTES + 32; ++i)
	{
		c[i] &= mask;
	}

	for (i = 0; i < 32; ++i)
	{
		SharedSecret[i] &= mask;
	}

	return (padding_ok == 0);
}

bool MPKCN6960T119::Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng)
{
	const size_t RLEN = (MCELIECE_N6960T119_SYS_N / 8) + ((1 << MCELIECE_N6960T119_GFBITS) * sizeof(uint32_t)) + (MCELIECE_N6960T119_SYS_T * 2) + 32;
	uint32_t perm[1 << MCELIECE_N6960T119_GFBITS] = { 0 };	// random permutation as 32-bit integers
	int16_t pi[1 << MCELIECE_N6960T119_GFBITS];	// random permutation
	uint16_t f[MCELIECE_N6960T119_SYS_T] = { 0 };	// element in GF(2 ^ mt)
	uint16_t irr[MCELIECE_N6960T119_SYS_T];		// Goppa polynomial
	std::vector<uint8_t> r(RLEN);
	uint8_t* seed;
	std::vector<uint8_t> tmps(33);
	uint8_t* skp;
	int32_t i;
	size_t idx;
	size_t itr;

	itr = 0;
	tmps[0] = 64;
	Rng->Generate(tmps, 1, 32);
	seed = tmps.data();

	while (true)
	{
		++itr;

		if (itr > MCELIECE_N6960T119_GENITR_MAX)
		{
			break;
		}

		idx = r.size() - 32;
		skp = PrivateKey.data();

		// expanding and updating the seed
		Keccak::XOFP1600(tmps, 0, tmps.size(), r, 0, r.size(), Keccak::KECCAK256_RATE_SIZE);
		MemoryTools::CopyRaw(seed + 1, skp, 32);
		skp += 32 + 8;
		MemoryTools::CopyRaw(r.data() + idx, seed + 1, 32);

		// generating irreducible polynomial
		idx -= sizeof(f);

		for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
		{
			f[i] = MPKCUtils::LoadGf(r.data() + idx + (size_t)i * 2);
		}

		if (GenPolyGen(irr, f) != 0)
		{
			continue;
		}

		for (i = 0; i < MCELIECE_N6960T119_SYS_T; ++i)
		{
			IntegerTools::Le16ToBytesRaw(irr[i], skp + ((size_t)i * 2));
		}

		skp += MCELIECE_N6960T119_IRR_BYTES;

		// generating permutation
		idx -= sizeof(perm);

		for (i = 0; i < (1 << MCELIECE_N6960T119_GFBITS); ++i)
		{
			perm[i] = IntegerTools::LeBytesTo32Raw(r.data() + idx + ((size_t)i * 4));
		}

		if (PkGen(PublicKey.data(), skp - MCELIECE_N6960T119_IRR_BYTES, perm, pi) != 0)
		{
			continue;
		}

		MPKCUtils::ControlBitsFromPermutation(skp, pi, MCELIECE_N6960T119_GFBITS, 1 << MCELIECE_N6960T119_GFBITS);
		skp += MCELIECE_N6960T119_COND_BYTES;

		// storing the random string s
		idx -= MCELIECE_N6960T119_SYS_N / 8;
		MemoryTools::CopyRaw((uint8_t*)r.data() + idx, (uint8_t*)skp, MCELIECE_N6960T119_SYS_N / 8);

		// storing positions of the 32 pivots
		IntegerTools::Le64ToBytesRaw(0x00000000FFFFFFFFULL, PrivateKey.data() + 32);

		break;
	}

	return (itr <= MCELIECE_N6960T119_GENITR_MAX);
}

NAMESPACE_MCELIECEEND
