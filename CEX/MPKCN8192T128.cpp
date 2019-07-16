#include "MPKCN8192T128.h"
#include "Keccak.h"
#include "IntegerTools.h"
#include "McElieceUtils.h"

NAMESPACE_MCELIECE

using Digest::Keccak;
using Utility::IntegerTools;

bool MPKCN8192T128::Decapsulate(const std::vector<byte> &PrivateKey, const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> conf(SECRET_SIZE);
	std::vector<byte> e2(1 + (MPKC_N / 8), 0x02);
	std::vector<byte> preimage(1 + (MPKC_N / 8) + SYND_BYTES + SECRET_SIZE);
	size_t pctr;
	size_t i;
	ushort m;
	byte confirm;
	byte derr;

	pctr = 0;
	confirm = 0;
	derr = DecryptE(e2.data() + 1, PrivateKey.data() + (MPKC_N / 8), CipherText.data());

	XOF(e2, 0, e2.size(), conf, 0, conf.size(), Keccak::KECCAK256_RATE_SIZE);

	for (i = 0; i < SECRET_SIZE; ++i)
	{
		confirm |= conf[i] ^ CipherText[SYND_BYTES + i];
	}

	m = derr | confirm;
	m -= 1;
	m >>= 8;
	preimage[pctr] = (~m & 0) | (m & 1);
	++pctr;

	for (i = 0; i < MPKC_N / 8; ++i)
	{
		preimage[pctr] = (~m & PrivateKey[i]) | (m & e2[i + 1]);
		++pctr;
	}

	for (i = 0; i < SYND_BYTES + SECRET_SIZE; ++i)
	{
		preimage[pctr] = CipherText[i];
		++pctr;
	}

	XOF(preimage, 0, preimage.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);

	return static_cast<bool>(confirm == 0 && derr == 0);
}

void MPKCN8192T128::Encapsulate(const std::vector<byte> &PublicKey, std::vector<byte> &CipherText, std::vector<byte> &SharedSecret, std::unique_ptr<IPrng> &Rng)
{
	std::vector<byte> e2(1 + (MPKC_N / 8), 0x02);
	std::vector<byte> ec1(1 + (MPKC_N / 8) + SYND_BYTES + SECRET_SIZE, 0x01);

	EncryptE(CipherText.data(), PublicKey.data(), e2.data() + 1, Rng);
	XOF(e2, 0, e2.size(), CipherText, SYND_BYTES, MAC_SIZE, Keccak::KECCAK256_RATE_SIZE);

	std::memcpy(ec1.data() + 1, e2.data() + 1, MPKC_N / 8);
	std::memcpy(ec1.data() + 1 + (MPKC_N / 8), CipherText.data(), SYND_BYTES + MAC_SIZE);

	XOF(ec1, 0, ec1.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);
}

bool MPKCN8192T128::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<IPrng> &Rng)
{
	size_t i;

	for (i = 0; i < KEYGEN_RETRIES; ++i)
	{
		SkPartGen(PrivateKey.data(), Rng);

		if (PkGen(PublicKey.data(), PrivateKey.data() + MPKC_N / 8) == 0)
		{
			break;
		}
	}

	Rng->Generate(PrivateKey, 0, MPKC_N / 8);

	return static_cast<bool>(i < KEYGEN_RETRIES);
}

void MPKCN8192T128::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

// benes.c //

void MPKCN8192T128::SupportGen(ushort* S, const byte* C)
{
	byte L[GFBITS][(1 << GFBITS) / 8];
	ushort bctr;
	size_t i;
	size_t j;
	ushort a;

	for (i = 0; i < GFBITS; ++i)
	{
		for (j = 0; j < (1 << GFBITS) / 8; ++j)
		{
			L[i][j] = 0;
		}
	}

	for (bctr = 0; bctr < (1 << GFBITS); ++bctr)
	{
		a = McElieceUtils::BitReverse(bctr);

		for (j = 0; j < GFBITS; ++j)
		{
			L[j][bctr / 8] |= ((a >> j) & 1) << (bctr % 8);
		}
	}

	for (j = 0; j < GFBITS; ++j)
	{
		McElieceUtils::ApplyBenes(L[j], C, false);
	}

	for (i = 0; i < SYS_N; ++i)
	{
		S[i] = 0;
		j = GFBITS;

		do
		{
			--j;
			S[i] <<= 1;
			S[i] |= (L[j][i / 8] >> (i % 8)) & 1;
		} while (j > 0);
	}
}

// bm.c //

void MPKCN8192T128::BerlekampMassey(ushort* Output, const ushort* S)
{
	ushort T[SYS_T + 1];
	ushort C[SYS_T + 1];
	ushort B[SYS_T + 1];
	size_t i;
	uint N;
	ushort L;
	ushort mle;
	ushort mne;
	ushort b;
	ushort d;
	ushort f;

	b = 1;
	L = 0;

	for (i = 0; i < SYS_T + 1; ++i)
	{
		C[i] = B[i] = 0;
	}

	B[1] = C[0] = 1;

	for (N = 0; N < 2 * SYS_T; N++)
	{
		d = 0;

		for (i = 0; i <= IntegerTools::Min(N, SYS_T); ++i)
		{
			d ^= GF::Multiply(C[i], S[N - i]);
		}

		mne = d;
		mne -= 1;
		mne >>= 15;
		mne -= 1;
		mle = static_cast<ushort>(N);
		mle -= 2U * L;
		mle >>= 15;
		mle -= 1;
		mle &= mne;

		for (i = 0; i <= SYS_T; ++i)
		{
			T[i] = C[i];
		}

		f = GF::Fractional(b, d);

		for (i = 0; i <= SYS_T; ++i)
		{
			C[i] ^= GF::Multiply(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1 - L) & mle);

		for (i = 0; i <= SYS_T; ++i)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);
		i = SYS_T;

		do
		{
			B[i] = B[i - 1];
			--i;
		} while (i > 0);

		B[0] = 0;
	}

	for (i = 0; i <= SYS_T; ++i)
	{
		Output[i] = C[SYS_T - i];
	}
}

// controlbits.c //

void MPKCN8192T128::ControlBits(byte* Output, const uint* Pi)
{
	byte c[(((2 * GFBITS) - 1) * (1 << GFBITS)) / 16] = { 0 };
	size_t i;

	McElieceUtils::PermuteBits(GFBITS, (1UL << GFBITS), 1UL, 0UL, c, Pi);

	for (i = 0; i < sizeof(c); ++i)
	{
		Output[i] = c[i];
	}
}

// decrypt.c //

byte MPKCN8192T128::DecryptE(byte* E, const byte* Sk, const byte* C)
{
	ushort g[SYS_T + 1];
	ushort L[SYS_N];
	ushort s[SYS_T * 2];
	ushort s_cmp[SYS_T * 2];
	ushort locator[SYS_T + 1];
	ushort images[SYS_N];
	byte r[SYS_N / 8];
	size_t i;
	ushort check;
	ushort t;
	ushort w;

	for (i = 0; i < SYND_BYTES; ++i)
	{
		r[i] = C[i];
	}

	for (i = SYND_BYTES; i < SYS_N / 8; ++i)
	{
		r[i] = 0;
	}

	for (i = 0; i < SYS_T; ++i)
	{
		g[i] = McElieceUtils::Load16(Sk);
		g[i] &= GFMASK;
		Sk += 2;
	}

	g[SYS_T] = 1;
	SupportGen(L, Sk);
	Syndrome(s, g, L, r);
	BerlekampMassey(locator, s);
	Root(images, locator, L);

	for (i = 0; i < SYS_N / 8; ++i)
	{
		E[i] = 0;
	}

	w = 0;

	for (i = 0; i < SYS_N; ++i)
	{
		t = GF::IsZero(images[i]) & 1;
		E[i / 8] |= t << (i % 8);
		w += t;
	}

	Syndrome(s_cmp, g, L, E);
	check = w;
	check ^= SYS_T;

	for (i = 0; i < SYS_T * 2; ++i)
	{
		check |= s[i] ^ s_cmp[i];
	}

	check -= 1;
	check >>= 15;
	check ^= 1;

	return static_cast<byte>(check);
}

// encrypt.c //

void MPKCN8192T128::GenE(byte* E, std::unique_ptr<IPrng> &Rng)
{
	std::array<ushort, SYS_T> ind;
	ulong eint[SYS_N / 64];
	ulong val[SYS_T];
	ulong mask;
	ulong one;
	size_t eq;
	size_t i;
	size_t j;

	one = 1;

	for (;;)
	{
		Rng->Fill(ind, 0, ind.size());

		for (i = 0; i < SYS_T; ++i)
		{
			ind[i] &= GFMASK;
		}

		eq = 0;

		for (i = 1; i < SYS_T; ++i)
		{
			for (j = 0; j < i; ++j)
			{
				if (ind[i] == ind[j])
				{
					eq = 1;
				}
			}
		}

		if (eq == 0)
		{
			break;
		}
	}

	for (j = 0; j < SYS_T; ++j)
	{
		val[j] = one << (ind[j] & 63);
	}

	for (i = 0; i < SYS_N / 64; ++i)
	{
		eint[i] = 0;

		for (j = 0; j < SYS_T; ++j)
		{
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			eint[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < SYS_N / 64; ++i)
	{
		McElieceUtils::Store64(E + i * 8, eint[i]);
	}
}

void MPKCN8192T128::Syndrome(byte* S, const byte* Pk, byte* E)
{
	byte row[SYS_N / 8];
	size_t i;
	size_t j;
	size_t poft;
	byte b;

	for (i = 0; i < SYND_BYTES; ++i)
	{
		S[i] = 0;
	}

	poft = 0;

	for (i = 0; i < PK_NROWS; ++i)
	{
		for (j = 0; j < SYS_N / 8; ++j)
		{
			row[j] = 0;
		}

		for (j = 0; j < PK_ROW_BYTES; ++j)
		{
			row[SYS_N / 8 - PK_ROW_BYTES + j] = Pk[poft + j];
		}

		row[i / 8] |= 1 << (i % 8);
		b = 0;

		for (j = 0; j < SYS_N / 8; ++j)
		{
			b ^= row[j] & E[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;
		S[i / 8] |= (b << (i % 8));

		poft += PK_ROW_BYTES;
	}
}

void MPKCN8192T128::EncryptE(byte* S, const byte* Pk, byte* E, std::unique_ptr<IPrng> &Rng)
{
	GenE(E, Rng);
	Syndrome(S, Pk, E);
}

// pk_gen.c //

int32_t MPKCN8192T128::PkGen(byte* Pk, const byte* Sk)
{
	byte** mat = new byte*[GFBITS * SYS_T];
	ushort g[SYS_T + 1];
	ushort L[SYS_N];
	ushort inv[SYS_N];
	int32_t ret;
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	size_t row;
	uint8_t b;
	uint8_t mask;

	ret = (mat == nullptr) ? -1 : 0;

	if (ret == 0)
	{
		g[SYS_T] = 1;

		for (i = 0; i < SYS_T; i++)
		{
			g[i] = McElieceUtils::Load16(Sk);
			g[i] &= GFMASK;
			Sk += 2;
		}

		SupportGen(L, Sk);
		Root(inv, g, L);

		for (i = 0; i < SYS_N; i++)
		{
			inv[i] = GF::Inverse(inv[i]);
		}

		for (i = 0; i < GFBITS * SYS_T; ++i)
		{
			mat[i] = new byte[SYS_N / 8];

			if (mat[i] == nullptr)
			{
				ret = -1;
				break;
			}

			std::memset(mat[i], 0, SYS_N / 8);
		}

		if (ret == 0)
		{
			for (i = 0; i < SYS_T; i++)
			{
				for (j = 0; j < SYS_N; j += 8)
				{
					for (k = 0; k < GFBITS; k++)
					{
						b = (inv[j + 7] >> k) & 1; b <<= 1;
						b |= (inv[j + 6] >> k) & 1; b <<= 1;
						b |= (inv[j + 5] >> k) & 1; b <<= 1;
						b |= (inv[j + 4] >> k) & 1; b <<= 1;
						b |= (inv[j + 3] >> k) & 1; b <<= 1;
						b |= (inv[j + 2] >> k) & 1; b <<= 1;
						b |= (inv[j + 1] >> k) & 1; b <<= 1;
						b |= (inv[j + 0] >> k) & 1;

						mat[i * GFBITS + k][j / 8] = b;
					}
				}

				for (j = 0; j < SYS_N; j++)
				{
					inv[j] = GF::Multiply(inv[j], L[j]);
				}
			}

			for (i = 0; i < (GFBITS * SYS_T + 7) / 8; i++)
			{
				for (j = 0; j < 8; j++)
				{
					row = i * 8 + j;

					if (row >= GFBITS * SYS_T)
					{
						break;
					}

					for (k = row + 1; k < GFBITS * SYS_T; k++)
					{
						mask = mat[row][i] ^ mat[k][i];
						mask >>= j;
						mask &= 1;
						mask = ~mask + 1;

						for (c = 0; c < SYS_N / 8; c++)
						{
							mat[row][c] ^= mat[k][c] & mask;
						}
					}

					// return if not systematic
					if (((mat[row][i] >> j) & 1) == 0)
					{
						return -1;
					}

					for (k = 0; k < GFBITS * SYS_T; k++)
					{
						if (k != row)
						{
							mask = mat[k][i] >> j;
							mask &= 1;
							mask = ~mask + 1;

							for (c = 0; c < SYS_N / 8; c++)
							{
								mat[k][c] ^= mat[row][c] & mask;
							}
						}
					}
				}
			}

			for (i = 0; i < PK_NROWS; i++)
			{
				std::memcpy(Pk + i * PK_ROW_BYTES, mat[i] + PK_NROWS / 8, PK_ROW_BYTES);
			}

			for (i = 0; i < GFBITS * SYS_T; ++i)
			{
				if (mat[i] != nullptr)
				{
					delete[] mat[i];
				}
			}
		}

		if (mat != nullptr)
		{
			delete[] mat;
		}
	}

	return ret;
}

// sk_gen.c //

int32_t MPKCN8192T128::IrrGen(ushort* Output, const ushort* F)
{
	ushort mat[SYS_T + 1][SYS_T];
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	int32_t ret;
	ushort mask;
	ushort inv;
	ushort t;

	ret = 0;
	mat[0][0] = 1;

	for (i = 1; i < SYS_T; ++i)
	{
		mat[0][i] = 0;
	}

	for (i = 0; i < SYS_T; ++i)
	{
		mat[1][i] = F[i];
	}

	for (j = 2; j <= SYS_T; ++j)
	{
		GF::Multiply(mat[j], mat[j - 1], F);
	}

	for (j = 0; j < SYS_T; ++j)
	{
		for (k = j + 1; k < SYS_T; k++)
		{
			mask = GF::IsZero(mat[j][j]);

			for (c = j; c < SYS_T + 1; c++)
			{
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		// return if not systematic
		if (mat[j][j] == 0)
		{
			ret = -1;
			break;
		}

		inv = GF::Inverse(mat[j][j]);

		for (c = j; c < SYS_T + 1; c++)
		{
			mat[c][j] = GF::Multiply(mat[c][j], inv);
		}

		for (k = 0; k < SYS_T; k++)
		{
			if (k != j)
			{
				t = mat[j][k];

				for (c = j; c < SYS_T + 1; c++)
				{
					mat[c][k] ^= GF::Multiply(mat[c][j], t);
				}
			}
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < SYS_T; ++i)
		{
			Output[i] = mat[SYS_T][i];
		}
	}

	return ret;
}

int32_t MPKCN8192T128::PermConversion(uint* Perm)
{
	ulong L[1 << GFBITS];
	size_t i;
	int32_t ret;

	ret = 0;

	for (i = 0; i < (1 << GFBITS); ++i)
	{
		L[i] = Perm[i];
		L[i] <<= 31;
		L[i] |= i;
	}

	McElieceUtils::Sort63b(1 << GFBITS, L);

	for (i = 1; i < (1 << GFBITS); ++i)
	{
		if ((L[i - 1] >> 31) == (L[i] >> 31))
		{
			ret = -1;
			break;
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < (1 << GFBITS); ++i)
		{
			Perm[i] = L[i] & GFMASK;
		}
	}

	return ret;
}

int32_t MPKCN8192T128::SkPartGen(byte* Sk, std::unique_ptr<IPrng> &Rng)
{
	// random permutation
	std::array<uint, 1 << GFBITS> perm;
	// irreducible polynomial
	ushort g[SYS_T];
	// random element in GF(2^mt)
	std::array<ushort, SYS_T> a;
	size_t i;

	for (;;)
	{
		Rng->Fill(a, 0, a.size());

		for (i = 0; i < SYS_T; ++i)
		{
			a[i] &= GFMASK;
		}

		if (IrrGen(g, (ushort*)a.data()) == 0)
		{
			break;
		}
	}

	for (;;)
	{
		Rng->Fill(perm, 0, perm.size());

		if (PermConversion((uint*)perm.data()) == 0)
		{
			break;
		}
	}

	for (i = 0; i < SYS_T; ++i)
	{
		McElieceUtils::Store16(Sk + SYS_N / 8 + i * 2, g[i]);
	}

	ControlBits(Sk + SYS_N / 8 + IRR_BYTES, (uint*)perm.data());

	return 0;
}

// root.c //

ushort MPKCN8192T128::Evaluate(const ushort* F, ushort A)
{
	size_t i;
	ushort r;

	r = F[SYS_T];
	i = SYS_T;

	do
	{
		--i;
		r = GF::Multiply(r, A);
		r = GF::Add(r, F[i]);
	} while (i != 0);

	return r;
}

void MPKCN8192T128::Root(ushort* Output, const ushort* F, const ushort* L)
{
	size_t i;

	for (i = 0; i < SYS_N; ++i)
	{
		Output[i] = Evaluate(F, L[i]);
	}
}

// syndrome.c //

void MPKCN8192T128::Syndrome(ushort* Output, const ushort* F, const ushort* L, const byte* R)
{
	size_t i;
	size_t j;
	ushort c;
	ushort e;
	ushort einv;

	for (j = 0; j < 2 * SYS_T; ++j)
	{
		Output[j] = 0;
	}

	for (i = 0; i < SYS_N; ++i)
	{
		c = (R[i / 8] >> (i % 8)) & 1;
		e = Evaluate(F, L[i]);
		einv = GF::Inverse(GF::Multiply(e, e));

		for (j = 0; j < 2 * SYS_T; ++j)
		{
			Output[j] = GF::Add(Output[j], GF::Multiply(einv, c));
			einv = GF::Multiply(einv, L[i]);
		}
	}
}

// gf.c //

ushort MPKCN8192T128::GF::Sq2(ushort Input)
{
	ulong x;
	ulong t;
	size_t i;

	const ulong B[] =
	{
		0x1111111111111111ULL,
		0x0303030303030303ULL,
		0x000F000F000F000FULL,
		0x000000FF000000FFULL
	};

	const ulong M[] =
	{
		0x0001FF0000000000ULL,
		0x000000FF80000000ULL,
		0x000000007FC00000ULL,
		0x00000000003FE000ULL
	};

	x = Input;
	x = (x | (x << 24)) & B[3];
	x = (x | (x << 12)) & B[2];
	x = (x | (x << 6)) & B[1];
	x = (x | (x << 3)) & B[0];

	for (i = 0; i < 4; ++i)
	{
		t = x & M[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (ushort)(x & GFMASK);
}

ushort MPKCN8192T128::GF::SqMul(ushort Input, ushort M)
{
	ulong x;
	ulong t0;
	ulong t1;
	ulong t;
	size_t i;

	const ulong MA[] =
	{
		0x0000001FF0000000ULL,
		0x000000000FF80000ULL,
		0x000000000007E000ULL
	};

	t0 = Input;
	t1 = M;
	x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= (t0 << 7);

	x ^= (t1 * (t0 & (0x04001)));
	x ^= (t1 * (t0 & (0x08002))) << 1;
	x ^= (t1 * (t0 & (0x10004))) << 2;
	x ^= (t1 * (t0 & (0x20008))) << 3;
	x ^= (t1 * (t0 & (0x40010))) << 4;
	x ^= (t1 * (t0 & (0x80020))) << 5;

	for (i = 0; i < 3; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (ushort)(x & GFMASK);
}

ushort MPKCN8192T128::GF::Sq2Mul(ushort Input, ushort M)
{
	ulong x;
	ulong t0;
	ulong t1;
	ulong t;
	size_t i;

	const ulong MA[] =
	{
		0x1FF0000000000000ULL,
		0x000FF80000000000ULL,
		0x000007FC00000000ULL,
		0x00000003FE000000ULL,
		0x0000000001FE0000ULL,
		0x000000000001E000ULL
	};

	t0 = Input;
	t1 = M;
	x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= (t0 << 21);

	x ^= (t1 * (t0 & (0x010000001)));
	x ^= (t1 * (t0 & (0x020000002))) << 3;
	x ^= (t1 * (t0 & (0x040000004))) << 6;
	x ^= (t1 * (t0 & (0x080000008))) << 9;
	x ^= (t1 * (t0 & (0x100000010))) << 12;
	x ^= (t1 * (t0 & (0x200000020))) << 15;

	for (i = 0; i < 6; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return (ushort)(x & GFMASK);
}

ushort MPKCN8192T128::GF::Add(ushort A, ushort B)
{
	return A ^ B;
}

ushort MPKCN8192T128::GF::Fractional(ushort Den, ushort Num)
{
	ushort tmp11;
	ushort tmp1111;
	ushort out;

	// ^11
	tmp11 = SqMul(Den, Den);
	// ^1111
	tmp1111 = Sq2Mul(tmp11, tmp11);
	out = Sq2(tmp1111);
	// ^11111111
	out = Sq2Mul(out, tmp1111);
	out = Sq2(out);
	// ^111111111111
	out = Sq2Mul(out, tmp1111);
	// ^1111111111110 = ^-1
	return SqMul(out, Num);
}

ushort MPKCN8192T128::GF::Inverse(ushort Den)
{
	return Fractional(Den, 1U);
}

ushort MPKCN8192T128::GF::IsZero(ushort A)
{
	uint t;

	t = A;
	t -= 1;
	t >>= 19;

	return static_cast<ushort>(t);
}

ushort MPKCN8192T128::GF::Multiply(ushort A, ushort B)
{
	ulong t;
	ulong t0;
	ulong t1;
	ulong tmp;
	size_t i;

	t0 = A;
	t1 = B;
	tmp = t0 * (t1 & 1);

	for (i = 1; i < GFBITS; ++i)
	{
		tmp ^= (t0 * (t1 & (1ULL << i)));
	}

	t = tmp & 0x0000000001FF0000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000ULL;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return static_cast<ushort>(tmp & GFMASK);
}

void MPKCN8192T128::GF::Multiply(ushort* Output, ushort* X, const ushort* Y)
{
	ushort prod[255];
	size_t i;
	size_t j;

	for (i = 0; i < 255; ++i)
	{
		prod[i] = 0;
	}

	for (i = 0; i < 128; ++i)
	{
		for (j = 0; j < 128; ++j)
		{
			prod[i + j] ^= Multiply(X[i], Y[j]);
		}
	}

	for (i = 254; i >= 128; i--)
	{
		prod[i - 123] ^= Multiply(prod[i], GF_MUL_FACTOR1);
		prod[i - 125] ^= Multiply(prod[i], GF_MUL_FACTOR2);
		prod[i - 128] ^= Multiply(prod[i], GF_MUL_FACTOR3);
	}

	for (i = 0; i < 128; ++i)
	{
		Output[i] = prod[i];
	}
}

NAMESPACE_MCELIECEEND