#include "MPKCN6960T119.h"
#include "Keccak.h"
#include "IntegerTools.h"
#include "MPKCUtils.h"

NAMESPACE_MCELIECE

using Digest::Keccak;
using Tools::IntegerTools;

/// <summary>
/// Decrypts the cipher-text and returns the shared secret
/// </summary>
/// 
/// <param name="PrivateKey">The private-key vector</param>
/// <param name="CipherText">The input cipher-text vector</param>
/// <param name="SharedSecret">The output shared-secret (an array of MCELIECE_SECRET_SIZE bytes)</param>
bool MPKCN6960T119::Decapsulate(const std::vector<byte> &PrivateKey, const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret)
{
	std::vector<byte> conf(32);
	std::vector<byte> e2(1 + (MPKC_N / 8), 0x02);
	std::vector<byte> preimage(1 + (MPKC_N / 8) + (SYND_BYTES + 32));
	size_t pctr;
	size_t i;
	ushort m;
	byte confirm;
	byte derr;

	pctr = 0;
	confirm = 0;
	derr = DecryptE(&e2[1], &PrivateKey[MPKC_N / 8], CipherText.data());
	XOF(e2, 0, e2.size(), conf, 0, conf.size(), Keccak::KECCAK256_RATE_SIZE);

	for (i = 0; i < MAC_SIZE; i++)
	{
		confirm |= conf[i] ^ CipherText[SYND_BYTES + i];
	}

	m = derr | confirm;
	m -= 1;
	m >>= 8;
	preimage[pctr] = (~m & 0) | (m & 1);
	++pctr;

	for (i = 0; i < MPKC_N / 8; i++)
	{
		preimage[pctr] = (~m & PrivateKey[i]) | (m & e2[i + 1]);
		++pctr;
	}

	for (i = 0; i < SYND_BYTES + 32; i++)
	{
		preimage[pctr] = CipherText[i];
		++pctr;
	}

	XOF(preimage, 0, preimage.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);

	return static_cast<bool>(confirm == 0 && derr == 0);
}

/// <summary>
/// Generates the cipher-text and shared-secret for a given public key
/// </summary>
/// 
/// <param name="PublicKey">The public-key vector</param>
/// <param name="CipherText">The output cipher-text vector</param>
/// <param name="SharedSecret">The output shared-secret (an array of MCELIECE_SECRET_SIZE bytes)</param>
/// <param name="Rng">The random generator instance</param>
void MPKCN6960T119::Encapsulate(const std::vector<byte> &PublicKey, std::vector<byte> &CipherText, std::vector<byte> &SharedSecret, std::unique_ptr<IPrng> &Rng)
{
	std::vector<byte> e2(1 + (MPKC_N / 8), 0x02);
	std::vector<byte> ec1(1 + (MPKC_N / 8) + (SYND_BYTES + MAC_SIZE), 0x01);

	EncryptE(&CipherText[0], &PublicKey[0], &e2[1], Rng);
	XOF(e2, 0, e2.size(), CipherText, SYND_BYTES, MAC_SIZE, Keccak::KECCAK256_RATE_SIZE);

	std::memcpy(&ec1[1], &e2[1], MPKC_N / 8);
	std::memcpy(&ec1[1 + (MPKC_N / 8)], CipherText.data(), SYND_BYTES + MAC_SIZE);
	XOF(ec1, 0, ec1.size(), SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);
}

/// <summary>
/// Generate a public/private key-pair
/// </summary>
/// 
/// <param name="PublicKey">The public-key vector</param>
/// <param name="PrivateKey">The private-key vector</param>
/// <param name="Rng">The random generator instance</param>
/// 
/// <returns>The key-pair was generated succesfully, or false for generation failure</returns>
bool MPKCN6960T119::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<IPrng> &Rng)
{
	size_t i;

	for (i = 0; i < KEYGEN_RETRIES; ++i)
	{
		SkPartGen(PrivateKey.data(), Rng);

		if (PkGen(PublicKey.data(), &PrivateKey[MPKC_N / 8]) == 0)
		{
			break;
		}
	}

	Rng->Generate(PrivateKey, 0, MPKC_N / 8);

	return static_cast<bool>(i < KEYGEN_RETRIES);
}


void MPKCN6960T119::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

// benes.c //

void MPKCN6960T119::SupportGen(ushort* S, const byte* C)
{
	// input: condition bits c
	// output: support s

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

	for (bctr = 0; bctr < (1U << GFBITS); ++bctr)
	{
		a = MPKCUtils::BitReverse(bctr);

		for (j = 0; j < GFBITS; ++j)
		{
			L[j][bctr / 8] |= ((a >> j) & 1) << (bctr % 8);
		}
	}

	for (j = 0; j < GFBITS; ++j)
	{
		MPKCUtils::ApplyBenes(L[j], C, false);
	}

	for (i = 0; i < MPKC_N; ++i)
	{
		S[i] = 0;

		j = GFBITS;

		do
		{
			--j;
			S[i] <<= 1;
			S[i] |= (L[j][i / 8] >> (i % 8)) & 1;
		}
		while (j > 0);
	}
}

// bm.c //

void MPKCN6960T119::BerlekampMassey(ushort* Output, const ushort* S)
{
	// the Berlekamp-Massey algorithm
	// input: s, sequence of field elements
	// output: out, minimal polynomial of s

	ushort T[MPKC_T + 1];
	ushort C[MPKC_T + 1];
	ushort B[MPKC_T + 1];
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

	for (i = 0; i < MPKC_T + 1; ++i)
	{
		B[i] = 0;
		C[i] = 0;
	}

	B[1] = 1;
	C[0] = 1;

	for (N = 0; N < 2 * MPKC_T; ++N)
	{
		d = 0;

		for (i = 0; i <= IntegerTools::Min(N, MPKC_T); ++i)
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

		for (i = 0; i <= MPKC_T; ++i)
		{
			T[i] = C[i];
		}

		f = GF::GfFrac(b, d);

		for (i = 0; i <= MPKC_T; ++i)
		{
			C[i] ^= GF::Multiply(f, B[i]) & mne;
		}

		L = (L & ~mle) | ((N + 1 - L) & mle);

		for (i = 0; i <= MPKC_T; ++i)
		{
			B[i] = (B[i] & ~mle) | (T[i] & mle);
		}

		b = (b & ~mle) | (d & mle);
		i = MPKC_T;

		do
		{

			B[i] = B[i - 1];
			--i;
		} 
		while (i > 0);

		B[0] = 0;
	}

	for (i = 0; i <= MPKC_T; ++i)
	{
		Output[i] = C[MPKC_T - i];
	}
}

// controlbits.c //

void MPKCN6960T119::ControlBits(byte* Output, const uint* Pi)
{
	// input: pi, a permutation
	// output: out, control bits w.r.t. pi

	byte c[(((2 * GFBITS) - 1) * (1 << GFBITS)) / 16] = { 0 };
	size_t i;

	MPKCUtils::PermuteBits(GFBITS, (1UL << GFBITS), 1UL, 0UL, c, Pi);

	for (i = 0; i < sizeof(c); ++i)
	{
		Output[i] = c[i];
	}
}

// decrypt.c //

byte MPKCN6960T119::DecryptE(byte* E, const byte* Sk, const byte* C)
{
	ushort g[MPKC_T + 1];
	ushort L[MPKC_N];
	ushort s[MPKC_T * 2];
	ushort scmp[MPKC_T * 2];
	ushort locator[MPKC_T + 1];
	ushort images[MPKC_N];
	byte r[MPKC_N / 8];
	size_t i;
	int32_t w;
	ushort check;
	ushort t;

	for (i = 0; i < SYND_BYTES; ++i)
	{
		r[i] = C[i];
	}

	r[i - 1] &= (1UL << ((GFBITS * MPKC_T) % 8)) - 1;

	for (i = SYND_BYTES; i < MPKC_N / 8; ++i)
	{
		r[i] = 0;
	}

	for (i = 0; i < MPKC_T; ++i)
	{
		g[i] = MPKCUtils::Load16(Sk);
		g[i] &= GFMASK;
		Sk += 2;
	}

	g[MPKC_T] = 1U;
	SupportGen(L, Sk);
	Syndrome(s, g, L, r);
	BerlekampMassey(locator, s);
	Root(images, locator, L);
	w = 0;

	for (i = 0; i < MPKC_N / 8; ++i)
	{
		E[i] = 0x00;
	}

	for (i = 0; i < MPKC_N; ++i)
	{
		t = GF::IsZero(images[i]) & 1U;
		E[i / 8] |= static_cast<byte>(t << (i % 8));
		w += t;

	}

	Syndrome(scmp, g, L, E);
	check = static_cast<ushort>(w);
	check ^= MPKC_T;

	for (i = 0; i < MPKC_T * 2; ++i)
	{
		check |= s[i] ^ scmp[i];
	}

	check -= 1U;
	check >>= 15;
	check ^= 1U;

	return static_cast<byte>(check);
}

// encrypt.c //

void MPKCN6960T119::EncryptE(byte* SS, const byte* Pk, byte* E, std::unique_ptr<IPrng> &Rng)
{
	GenE(E, Rng);
	Syndrome(SS, Pk, E);
}

void MPKCN6960T119::GenE(byte* E, std::unique_ptr<IPrng> &Rng)
{
	// output: e, an error vector of weight t
	ulong e_int[(MPKC_N + 63) / 64];
	ulong val[MPKC_T];
	std::array<ushort, MPKC_T * 2> ind;
	ulong mask;
	int32_t eq;
	int32_t i;
	int32_t j;

	for (;;)
	{
		Rng->Fill(ind, 0, ind.size());

		for (i = 0; i < MPKC_T * 2; ++i)
		{
			ind[i] &= GFMASK;
		}

		if (MovForward(reinterpret_cast<ushort*>(ind.data())) == 0)
		{
			continue;
		}

		// check for repetition
		eq = 0;

		for (i = 1; i < MPKC_T; ++i)
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

	for (j = 0; j < MPKC_T; ++j)
	{
		val[j] = 1ULL << (ind[j] & 63);
	}

	for (i = 0; i < (MPKC_N + 63) / 64; ++i)
	{
		e_int[i] = 0;

		for (j = 0; j < MPKC_T; ++j)
		{
			mask = i ^ (ind[j] >> 6);
			mask -= 1;
			mask >>= 63;
			mask = ~mask + 1;
			e_int[i] |= val[j] & mask;
		}
	}

	for (i = 0; i < (MPKC_N + 63) / 64 - 1; ++i)
	{
		MPKCUtils::Store64(E, e_int[i]);
		E += 8;
	}

	for (j = 0; j < (MPKC_N % 64); j += 8)
	{
		E[j / 8] = (e_int[i] >> j) & 0xFF;
	}
}

int32_t MPKCN6960T119::MovForward(ushort* Ind)
{
	size_t i;
	size_t j;
	int32_t found;
	ushort t;

	for (i = 0; i < MPKC_T; ++i)
	{
		found = 0;

		for (j = i; j < MPKC_T * 2; ++j)
		{
			if (Ind[j] < MPKC_N)
			{
				t = Ind[i];
				Ind[i] = Ind[j];
				Ind[j] = t;
				found = 1;
				break;
			}
		}

		if (found == 0)
		{
			break;
		}
	}

	return found;
}

void MPKCN6960T119::Syndrome(byte* S, const byte* Pk, const byte* E)
{
	// input: public key pk, error vector e
	// output: Syndrome s

	const byte* pkptr = Pk;
	byte row[MPKC_N / 8];
	size_t i;
	size_t j;
	uint tail;
	byte b;

	for (i = 0; i < SYND_BYTES; ++i)
	{
		S[i] = 0;
	}

	tail = PK_NROWS % 8;

	for (i = 0; i < PK_NROWS; ++i)
	{
		for (j = 0; j < MPKC_N / 8; ++j)
		{
			row[j] = 0;
		}

		for (j = 0; j < PK_ROW_BYTES; ++j)
		{
			row[((MPKC_N / 8) - PK_ROW_BYTES) + j] = pkptr[j];
		}

		for (j = (MPKC_N / 8) - 1; j >= (MPKC_N / 8) - PK_ROW_BYTES; --j)
		{
			row[j] = (row[j] << tail) | (row[j - 1] >> (8UL - tail));
		}

		row[i / 8] |= 1 << (i % 8);
		b = 0;

		for (j = 0; j < MPKC_N / 8; ++j)
		{
			b ^= row[j] & E[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;

		S[i / 8] |= (b << (i % 8));
		pkptr += PK_ROW_BYTES;
	}
}

// pk_gen.c //

int32_t MPKCN6960T119::PkGen(byte* Pk, const byte* Sk)
{
	byte** mat = new byte*[GFBITS * SYS_T];
	ushort g[SYS_T + 1];
	ushort L[SYS_N];
	ushort inv[SYS_N];
	size_t c;
	size_t i;
	size_t j;
	size_t k;
	size_t row;
	uint tail;
	int32_t ret;
	byte b;
	byte mask;

	g[SYS_T] = 1;
	ret = 0;
	
	for (i = 0; i < SYS_T; i++)
	{
		g[i] = MPKCUtils::Load16(Sk);
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
		std::memset(mat[i], 0, SYS_N / 8);
	}

	for (i = 0; i < SYS_T; i++)
	{
		for (j = 0; j < SYS_N; j += 8)
		{
			for (k = 0; k < GFBITS; k++)
			{
				/* jgu: checked */
				/*lint -save -e661, -e662 */
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
				/*lint -restore */
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
			row = (i * 8) + j;

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
				ret = -1;
				break;
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

		if (ret != 0)
		{
			break;
		}
	}

	tail = (GFBITS * SYS_T) % 8;
	k = 0;

	for (i = 0; i < GFBITS * SYS_T; i++)
	{
		for (j = ((GFBITS * SYS_T) - 1) / 8; j < (SYS_N / 8) - 1; j++)
		{
			Pk[k] = (mat[i][j] >> tail) | (mat[i][j + 1UL] << (8UL - tail));
			++k;
		}

		Pk[k] = (mat[i][j] >> tail);
		++k;
	}

	for (i = 0; i < GFBITS * SYS_T; ++i)
	{
		if (mat[i] != nullptr)
		{
			delete[] mat[i];
		}
	}

	if (mat[i] != nullptr)
	{
		delete[] mat;
	}

	return ret;
}

// root.c //

ushort MPKCN6960T119::Evaluate(const ushort* F, ushort A)
{
	size_t i;
	ushort r;

	r = F[MPKC_T];
	i = MPKC_T;

	do
	{
		--i;
		r = GF::Multiply(r, A);
		r = GF::Add(r, F[i]);
	}
	while (i != 0);

	return r;
}

void MPKCN6960T119::Root(ushort* Output, const ushort* F, const ushort* L)
{
	// input: polynomial f and list of field elements L
	// output: out = [ f(a) for a in L ]

	size_t i;

	for (i = 0; i < MPKC_N; ++i)
	{
		Output[i] = Evaluate(F, L[i]);
	}
}

// sk_gen.c //

int32_t MPKCN6960T119::IrrGen(ushort* Output, const ushort* F)
{
	// input: f, an element in GF((2^m)^t)
	// output: out, the generating polynomial of f (first t coefficients only)
	// return: 0 for success, -1 for failure

	ushort mat[MPKC_T + 1][MPKC_T];
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

	for (i = 1; i < MPKC_T; ++i)
	{
		mat[0][i] = 0;
	}

	for (i = 0; i < MPKC_T; ++i)
	{
		mat[1][i] = F[i];
	}

	for (j = 2; j <= MPKC_T; ++j)
	{
		GF::Multiply(mat[j], mat[j - 1], F);
	}

	for (j = 0; j < MPKC_T; ++j)
	{
		for (k = j + 1; k < MPKC_T; ++k)
		{
			mask = GF::IsZero(mat[j][j]);

			for (c = j; c < MPKC_T + 1; ++c)
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

		for (c = j; c < MPKC_T + 1; ++c)
		{
			mat[c][j] = GF::Multiply(mat[c][j], inv);
		}

		for (k = 0; k < MPKC_T; ++k)
		{
			if (k != j)
			{
				t = mat[j][k];

				for (c = j; c < MPKC_T + 1; ++c)
				{
					mat[c][k] ^= GF::Multiply(mat[c][j], t);
				}
			}
		}
	}

	if (ret == 0)
	{
		for (i = 0; i < MPKC_T; ++i)
		{
			Output[i] = mat[MPKC_T][i];
		}
	}

	return ret;
}

int32_t MPKCN6960T119::PermConversion(uint* Perm)
{
	// input: permutation represented by 32-bit integers
	// output: an equivalent permutation represented by integers in {0, ..., 2^m-1}
	// return  0 if no repeated intergers in the input
	// return -1 if there are repeated intergers in the input

	ulong L[1 << GFBITS];
	size_t i;
	int32_t ret;

	for (i = 0; i < (1 << GFBITS); ++i)
	{
		L[i] = Perm[i];
		L[i] <<= 31;
		L[i] |= i;
	}

	MPKCUtils::Sort63b(1 << GFBITS, L);
	ret = 0;

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

int32_t MPKCN6960T119::SkPartGen(byte* Sk, std::unique_ptr<IPrng> &Rng)
{
	// random permutation
	std::array<uint, 1 << GFBITS> perm;
	// irreducible polynomial
	ushort g[MPKC_T];
	// random element in GF(2^mt)
	std::array<ushort, MPKC_T> a;
	size_t i;

	for (;;)
	{
		Rng->Fill(a, 0, a.size());

		for (i = 0; i < MPKC_T; ++i)
		{
			a[i] &= GFMASK;
		}

		if (IrrGen(g, reinterpret_cast<ushort*>(a.data())) == 0)
		{
			break;
		}
	}

	for (;;)
	{
		Rng->Fill(perm, 0, perm.size());

		if (PermConversion(reinterpret_cast<uint*>(perm.data())) == 0)
		{
			break;
		}
	}

	for (i = 0; i < MPKC_T; ++i)
	{
		MPKCUtils::Store16(Sk + MPKC_N / 8 + i * 2, g[i]);
	}

	ControlBits(Sk + MPKC_N / 8 + IRR_BYTES, reinterpret_cast<uint*>(perm.data()));

	return 0;
}

// syndrome.c //

void MPKCN6960T119::Syndrome(ushort* Output, const ushort* F, const ushort* L, const byte* R)
{
	// input: Goppa polynomial f, support L, received word r
	// output: out, the Syndrome of length 2t

	size_t i;
	size_t j;
	ushort c;
	ushort e;
	ushort einv;

	for (j = 0; j < 2 * MPKC_T; ++j)
	{
		Output[j] = 0;
	}

	for (i = 0; i < MPKC_N; ++i)
	{
		c = (R[i / 8] >> (i % 8)) & 1;
		e = Evaluate(F, L[i]);
		einv = GF::Inverse(GF::Multiply(e, e));

		for (j = 0; j < 2 * MPKC_T; ++j)
		{
			Output[j] = GF::Add(Output[j], GF::Multiply(einv, c));
			einv = GF::Multiply(einv, L[i]);
		}
	}
}

// gf.c //

ushort MPKCN6960T119::GF::Add(ushort A, ushort B)
{
	return A ^ B;
}

ushort MPKCN6960T119::GF::GfFrac(ushort Den, ushort Num)
{
	// input: field element den, num
	// return: (num/den)
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

ushort MPKCN6960T119::GF::IsZero(ushort A)
{
	uint t;

	t = A;
	t -= 1;
	t >>= 19;

	return static_cast<ushort>(t);
}

ushort MPKCN6960T119::GF::Inverse(ushort Den)
{
	return GfFrac(Den, 1U);
}

ushort MPKCN6960T119::GF::Multiply(ushort A, ushort B)
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

void MPKCN6960T119::GF::Multiply(ushort* Output, const ushort* X, const ushort* Y)
{
	// input: X, Y in GF((2^m)^t)
	// output: out = X*Y

	ushort prod[IRR_BYTES - 1];
	size_t i;
	size_t j;

	for (i = 0; i < IRR_BYTES - 1; ++i)
	{
		prod[i] = 0;
	}

	for (i = 0; i < MPKC_T; ++i)
	{
		for (j = 0; j < MPKC_T; ++j)
		{
			prod[i + j] ^= Multiply(X[i], Y[j]);
		}
	}

	for (i = IRR_BYTES - 2; i >= MPKC_T; --i)
	{
		prod[i - (MPKC_T - 2)] ^= Multiply(prod[i], GF_MUL_FACTOR1);
		prod[i - MPKC_T] ^= Multiply(prod[i], GF_MUL_FACTOR2);
	}

	for (i = 0; i < MPKC_T; ++i)
	{
		Output[i] = prod[i];
	}
}

ushort MPKCN6960T119::GF::Sq2(ushort Input)
{
	// input: field element in
	// return: (in^2)^2

	ulong t;
	ulong x;
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

	return static_cast<ushort>(x & GFMASK);
}

ushort MPKCN6960T119::GF::SqMul(ushort Input, ushort M)
{
	// input: field element in, m
	// return: (in^2)*m

	ulong t;
	ulong t0;
	ulong t1;
	ulong x;
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

	x ^= (t1 * (t0 & (0x0000000000004001ULL)));
	x ^= (t1 * (t0 & (0x0000000000008002ULL))) << 1;
	x ^= (t1 * (t0 & (0x0000000000010004ULL))) << 2;
	x ^= (t1 * (t0 & (0x0000000000020008ULL))) << 3;
	x ^= (t1 * (t0 & (0x0000000000040010ULL))) << 4;
	x ^= (t1 * (t0 & (0x0000000000080020ULL))) << 5;

	for (i = 0; i < 3; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return static_cast<ushort>(x & GFMASK);
}

ushort MPKCN6960T119::GF::Sq2Mul(ushort Input, ushort M)
{
	// input: field element in, m
	// return: ((in^2)^2)*m
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
	x ^= (t1 * (t0 & (0x0000000010000001ULL)));
	x ^= (t1 * (t0 & (0x0000000020000002ULL))) << 3;
	x ^= (t1 * (t0 & (0x0000000040000004ULL))) << 6;
	x ^= (t1 * (t0 & (0x0000000080000008ULL))) << 9;
	x ^= (t1 * (t0 & (0x0000000100000010ULL))) << 12;
	x ^= (t1 * (t0 & (0x0000000200000020ULL))) << 15;

	for (i = 0; i < 6; ++i)
	{
		t = x & MA[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return static_cast<ushort>(x & GFMASK);
}

NAMESPACE_MCELIECEEND
