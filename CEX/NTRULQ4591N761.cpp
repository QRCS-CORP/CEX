#include "NTRULQ4591N761.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "Keccak512.h"
#include "MemoryTools.h"

NAMESPACE_NTRU

using Utility::IntegerTools;
using Digest::Keccak;
using Digest::Keccak512;
using Utility::MemoryTools;

//~~~Public Functions~~~//

const std::string NTRULQ4591N761::Name = "NTRULQ4591N761";

int NTRULQ4591N761::Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
{
	std::array<int16_t, NTRU_P> aB;
	std::array<int16_t, NTRU_P> B;
	std::array<int16_t, 256> C;
	std::array<int8_t, NTRU_P> a;
	std::vector<byte> r(NTRU_SEED_SIZE);
	std::vector<byte> checkcstr(NTRU_CIPHERTEXT_SIZE);
	std::vector<byte> maybek(NTRU_SEED_SIZE);
	size_t i;
	uint result;
	uint tmp;

	SmallDecode(a, PrivateKey);
	RqDecodeRounded(B, CipherText, 0);
	RqMult(aB, B, a);

	for (i = 0; i < 128; ++i)
	{
		tmp = CipherText[NTRU_RQENCODEROUNDED_SIZE + NTRU_SEED_SIZE + i];
		C[(2 * i)] = ((tmp & 15) * 287) - 2007;
		C[(2 * i) + 1] = ((tmp >> 4) * 287) - 2007;
	}

	for (i = 0; i < 256; ++i)
	{
		C[i] = -(ModqFreeze((C[i] - aB[i]) + (4 * (NTRU_W + 1))) >> 14);
	}

	for (i = 0; i < 256; ++i)
	{
		r[i / 8] |= (C[i] << (i & 7));
	}

	Hide(checkcstr, maybek, PrivateKey, NTRU_SMALLENCODE_SIZE, r);
	result = Verify(CipherText, checkcstr);

	for (i = 0; i < NTRU_SEED_SIZE; ++i)
	{
		Secret[i] = maybek[i] & ~result;
	}

	return result;
}

void NTRULQ4591N761::Encrypt(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<byte> r(NTRU_SEED_SIZE);

	Rng->Generate(r);
	Hide(CipherText, Secret, PublicKey, 0, r);
}

void NTRULQ4591N761::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::array<int16_t, NTRU_P> A;
	std::array<int16_t, NTRU_P> G;
	std::array<int8_t, NTRU_P> a;
	std::vector<byte> k1(NTRU_SEED_SIZE);
	std::vector<byte> k2(NTRU_SEED_SIZE);

	Rng->Generate(k1);
	Rng->Generate(k2);

	RqFromSeed(G, k1, 0);
	SeededWeightW(a, k2);
	RqMult(A, G, a);
	RqRound3(A, A);

	MemoryTools::Copy(k1, 0, PublicKey, 0, NTRU_SEED_SIZE);
	RqEncodeRounded(PublicKey, A);

	SmallEncode(PrivateKey, a);
	MemoryTools::Copy(PublicKey, 0, PrivateKey, NTRU_SMALLENCODE_SIZE, NTRU_PUBLICKEY_SIZE);
}

//~~~Internal Functions~~~//

void NTRULQ4591N761::Hide(std::vector<byte> &CipherText, std::vector<byte> &Secret, const std::vector<byte> &Key, size_t KeyOffset, const std::vector<byte> &Seed)
{
	std::array<int16_t, NTRU_P> G;
	std::array<int16_t, NTRU_P> A;
	std::array<int16_t, NTRU_P> B;
	std::array<int16_t, NTRU_P> C;
	std::array<int8_t, NTRU_P> tmpb;
	std::vector<byte> k12(64);
	std::vector<byte> k34(64);
	size_t i;
	int16_t x;

	RqFromSeed(G, Key, KeyOffset);
	RqDecodeRounded(A, Key, KeyOffset);

	Keccak512 dgt;
	// compute k12 from s
	dgt.Update(Seed, 0, NTRU_SEED_SIZE);
	dgt.Finalize(k12, 0);

	// exp w
	SeededWeightW(tmpb, k12);
	// hash top of k12
	dgt.Update(k12, NTRU_SEED_SIZE, NTRU_SEED_SIZE);
	dgt.Finalize(k34, 0);

	// mult
	RqMult(B, G, tmpb);
	RqRound3(B, B);
	RqMult(C, A, tmpb);

	// calc c
	for (i = 0; i < 256; ++i)
	{
		x = C[i];
		x = ModqSum(x, 2295 * (1 & (Seed[i / 8] >> (i & 7))));
		x = (((x + 2156) * 114) + 16384) >> 15;
		// between 0 and 15
		C[i] = x;
	}

	// copy k34 to sec and cpt
	MemoryTools::Copy(k34, 0, CipherText, 0, NTRU_SEED_SIZE);
	MemoryTools::Copy(k34, NTRU_SEED_SIZE, Secret, 0, NTRU_SEED_SIZE);
	// encode b to cpt
	RqEncodeRounded(CipherText, B);

	// copy c to cpt
	const size_t CTOFT = NTRU_RQENCODEROUNDED_SIZE + NTRU_SEED_SIZE;

	for (i = 0; i < 128; ++i)
	{
		CipherText[CTOFT + i] = C[2 * i] + (C[(2 * i) + 1] << 4);
	}
}

void NTRULQ4591N761::MinMax(int32_t &X, int32_t &Y)
{
	uint c;
	uint xi;
	uint xy;
	uint yi;

	xi = X;
	yi = Y;
	xy = xi ^ yi;
	c = yi - xi;
	c ^= xy & (c ^ yi);
	c >>= 31;
	c = ~c + 1;
	c &= xy;
	X = xi ^ c;
	Y = yi ^ c;
}

int16_t NTRULQ4591N761::ModqFreeze(int32_t A)
{
	// input between -9000000 and 9000000 output between -2295 and 2295

	A -= NTRU_Q * ((0x000000E4L * A) >> 20);
	A -= NTRU_Q * (((0x0000E466L * A) + 0x08000000L) >> 28);

	return A;
}

int16_t NTRULQ4591N761::ModqFromUL(uint A)
{
	// input between 0 and 4294967295 output = (input % NTRU_Q) - 2295

	int32_t r;

	// <= 8010861
	r = (A & 0x0007FFFFUL) + (A >> 19) * 0x00000392UL;

	return ModqFreeze(r - 0x000008F7UL);
}

int16_t NTRULQ4591N761::ModqPlusProduct(int16_t A, int16_t B, int16_t C)
{
	int32_t s;

	s = A + (B * C);

	return ModqFreeze(s);
}

int16_t NTRULQ4591N761::ModqSum(int16_t A, int16_t B)
{
	int32_t s;

	s = A + B;

	return ModqFreeze(s);
}

void NTRULQ4591N761::RqDecodeRounded(std::array<int16_t, NTRU_P> &F, const std::vector<byte> &Key, size_t KeyOffset)
{
	size_t i;
	uint c0;
	uint c1;
	uint c2;
	uint c3;
	uint f0;
	uint f1;
	uint f2;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		c0 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4)];
		c1 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4) + 1];
		c2 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4) + 2];
		c3 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4) + 3];
		f2 = ((0x00E38E39UL * c3) + (0x0000E38EUL * c2) + (0x000000E4L * (c1 + 2))) >> 21;

		c2 += c3 << 8;
		c2 -= (f2 * 9) << 2;
		f1 = ((0x05555555UL * c2) + (0x00055555UL * c1) + (0x00000555UL * (c0 + 1))) >> 21;
		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;
		c0 += c1 << 8;
		f0 = c0;

		F[(i * 3)] = ModqFreeze((f0 * 3) + NTRU_Q - NTRU_QSHIFT);
		F[(i * 3) + 1] = ModqFreeze((f1 * 3) + NTRU_Q - NTRU_QSHIFT);
		F[(i * 3) + 2] = ModqFreeze((f2 * 3) + NTRU_Q - NTRU_QSHIFT);
	}

	c0 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4)];
	c1 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4) + 1];
	c2 = Key[NTRU_SEED_SIZE + KeyOffset + (i * 4) + 2];
	f1 = ((0x05555555UL * c2) + (0x00055555UL * c1) + (0x00000555UL * (c0 + 1))) >> 21;

	c1 += c2 << 8;
	c1 -= (f1 * 3) << 1;
	c0 += c1 << 8;
	f0 = c0;

	F[(i * 3)] = ModqFreeze((f0 * 3) + NTRU_Q - NTRU_QSHIFT);
	F[(i * 3) + 1] = ModqFreeze((f1 * 3) + NTRU_Q - NTRU_QSHIFT);
}

void NTRULQ4591N761::RqEncodeRounded(std::vector<byte> &C, const std::array<int16_t, NTRU_P> &Key)
{
	size_t i;
	int32_t f0;
	int32_t f1;
	int32_t f2;

	for (i = 0; i < NTRU_P / 3; ++i)
	{
		f0 = Key[(i * 3)] + NTRU_QSHIFT;
		f1 = Key[(i * 3) + 1] + NTRU_QSHIFT;
		f2 = Key[(i * 3) + 2] + NTRU_QSHIFT;
		f0 = (0x5556 * f0) >> 16;
		f1 = (0x5556 * f1) >> 16;
		f2 = (0x5556 * f2) >> 16;

		// now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer
		f2 *= 3;
		f1 += f2 << 9;
		f1 *= 3;
		f0 += f1 << 9;

		C[NTRU_SEED_SIZE + (i * 4)] = f0;
		f0 >>= 8;
		C[NTRU_SEED_SIZE + (i * 4) + 1] = f0;
		f0 >>= 8;
		C[NTRU_SEED_SIZE + (i * 4) + 2] = f0;
		f0 >>= 8;
		C[NTRU_SEED_SIZE + (i * 4) + 3] = f0;
	}

	// using p mod 3 = 2
	f0 = NTRU_QSHIFT + Key[(i * 3)];
	f1 = NTRU_QSHIFT + Key[(i * 3) + 1];
	f0 = (0x5556 * f0) >> 16;
	f1 = (0x5556 * f1) >> 16;
	f1 *= 3;
	f0 += f1 << 9;

	C[NTRU_SEED_SIZE + (i * 4)] = f0;
	f0 >>= 8;
	C[NTRU_SEED_SIZE + (i * 4) + 1] = f0;
	f0 >>= 8;
	C[NTRU_SEED_SIZE + (i * 4) + 2] = f0;
}

void NTRULQ4591N761::RqFromSeed(std::array<int16_t, NTRU_P> &H, const std::vector<byte> &Key, size_t KeyOffset)
{
	std::array<uint, NTRU_P> buf;
	std::vector<byte> btbuf(buf.size() * sizeof(uint));
	std::vector<byte> n(16, 0);
	size_t i;

	// changed from aes-ctr to shake
	XOF(Key, KeyOffset, NTRU_SEED_SIZE, btbuf, 0, btbuf.size(), Keccak::KECCAK256_RATE_SIZE);
	MemoryTools::Copy(btbuf, 0, buf, 0, btbuf.size());

	for (i = 0; i < NTRU_P; ++i)
	{
		H[i] = ModqFromUL(buf[i]);
	}
}

void NTRULQ4591N761::RqMult(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F, const std::array<int8_t, NTRU_P> &G)
{
	std::array<int16_t, NTRU_P + NTRU_P - 1> fg;
	size_t i;
	size_t j;
	int16_t result;

	for (i = 0; i < NTRU_P; ++i)
	{
		result = 0;

		for (j = 0; j <= i; ++j)
		{
			result = ModqPlusProduct(result, F[j], G[i - j]);
		}

		fg[i] = result;
	}

	for (i = NTRU_P; i < NTRU_P + NTRU_P - 1; ++i)
	{
		result = 0;

		for (j = i - NTRU_P + 1; j < NTRU_P; ++j)
		{
			result = ModqPlusProduct(result, F[j], G[i - j]);
		}

		fg[i] = result;
	}

	for (i = NTRU_P + NTRU_P - 2; i >= NTRU_P; --i)
	{
		fg[(i - NTRU_P)] = ModqSum(fg[(i - NTRU_P)], fg[i]);
		fg[(i - NTRU_P) + 1] = ModqSum(fg[(i - NTRU_P) + 1], fg[i]);
	}

	for (i = 0; i < NTRU_P; ++i)
	{
		H[i] = fg[i];
	}
}

void NTRULQ4591N761::RqRound3(std::array<int16_t, NTRU_P> &H, const std::array<int16_t, NTRU_P> &F)
{
	size_t i;

	for (i = 0; i < NTRU_P; ++i)
	{
		H[i] = (((0x5556 * (F[i] + 0x08F7) + 0x8000) >> 16) * 3) - 0x08F7;
	}
}

void NTRULQ4591N761::SeededWeightW(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &K)
{
	std::array<int32_t, NTRU_P> r;
	std::vector<byte> tmpk(NTRU_SEED_SIZE);
	std::vector<byte> tmpr(r.size() * sizeof(int32_t));
	size_t i;

	// changed from aes-ctr to shake
	XOF(K, 0, NTRU_SEED_SIZE, tmpr, 0, tmpr.size(), Keccak::KECCAK256_RATE_SIZE);
	MemoryTools::Copy(tmpr, 0, r, 0, tmpr.size());

	for (i = 0; i < NTRU_P; ++i)
	{
		r[i] ^= 0x80000000L;
	}

	for (i = 0; i < NTRU_W; ++i)
	{
		r[i] &= -2;
	}

	for (i = NTRU_W; i < NTRU_P; ++i)
	{
		r[i] = (r[i] & -3) | 1;
	}

	Sort(r);

	for (i = 0; i < NTRU_P; ++i)
	{
		F[i] = (static_cast<int8_t>(r[i]) & 3) - 1;
	}
}

void NTRULQ4591N761::SmallDecode(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &C)
{
	size_t i;
	int8_t c0;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = C[i];
		F[(i * 4)] = (c0 & 3) - 1;
		c0 >>= 2;
		F[(i * 4) + 1] = (c0 & 3) - 1;
		c0 >>= 2;
		F[(i * 4) + 2] = (c0 & 3) - 1;
		c0 >>= 2;
		F[(i * 4) + 3] = (c0 & 3) - 1;
	}

	c0 = static_cast<int8_t>(C[i]);
	F[i * 4] = (c0 & 3) - 1;
}

void NTRULQ4591N761::SmallEncode(std::vector<byte> &C, const std::array<int8_t, NTRU_P> &F)
{
	// all coefficients in -1, 0, 1
	size_t i;
	byte c0;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = F[(i * 4)] + 1;
		c0 += (F[(i * 4) + 1] + 1) << 2;
		c0 += (F[(i * 4) + 2] + 1) << 4;
		c0 += (F[(i * 4) + 3] + 1) << 6;
		C[i] = c0;
	}

	c0 = F[(i * 4)] + 1;
	C[i] = c0;
}

void NTRULQ4591N761::Sort(std::array<int32_t, NTRU_P> &X)
{
	const int32_t SRTTOP = 512;
	int32_t i;
	int32_t p;
	int32_t q;

	for (p = SRTTOP; p > 0; p >>= 1)
	{
		for (i = 0; i < NTRU_P - p; ++i)
		{
			if (!(i & p))
			{
				MinMax(X[i], X[i + p]);
			}
		}

		for (q = SRTTOP; q > p; q >>= 1)
		{
			for (i = 0; i < NTRU_P - q; ++i)
			{
				if (!(i & p))
				{
					MinMax(X[i + p], X[i + q]);
				}
			}
		}
	}
}

int32_t NTRULQ4591N761::Verify(const std::vector<byte> &X, const std::vector<byte> &Y)
{
	size_t i;
	uint diff;

	diff = 0;

	for (i = 0; i < NTRU_CIPHERTEXT_SIZE; ++i)
	{
		diff |= X[i] ^ Y[i];
	}

	return (1 & ((diff - 1) >> 8)) - 1;
}

void NTRULQ4591N761::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::XOFR48P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#else
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#endif
}

NAMESPACE_NTRUEND
