#include "NTRULQ4591N761.h"

NAMESPACE_NTRU

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

	Rng->GetBytes(r);
	Hide(CipherText, Secret, PublicKey, 0, r);
}

void NTRULQ4591N761::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::array<int16_t, NTRU_P> A;
	std::array<int16_t, NTRU_P> G;
	std::array<int8_t, NTRU_P> a;
	std::vector<byte> k1(NTRU_SEED_SIZE);
	std::vector<byte> k2(NTRU_SEED_SIZE);

	Rng->GetBytes(k1);
	Rng->GetBytes(k2);

	RqFromSeed(G, k1, 0);
	SeededWeightW(a, k2);
	RqMult(A, G, a);
	RqRound3(A, A);

	std::memcpy(PublicKey.data(), k1.data(), NTRU_SEED_SIZE);
	RqEncodeRounded(PublicKey, A);

	SmallEncode(PrivateKey, a);
	std::memcpy(PrivateKey.data() + NTRU_SMALLENCODE_SIZE, PublicKey.data(), NTRU_PUBLICKEY_SIZE);
}

//~~~Internal Functions~~~//

void NTRULQ4591N761::Hide(std::vector<byte> &CipherText, std::vector<byte> &Secret, const std::vector<byte> &Key, size_t KeyOffset, const std::vector<byte> &Rand)
{
	std::array<int16_t, NTRU_P> G;
	std::array<int16_t, NTRU_P> A;
	std::array<int16_t, NTRU_P> B;
	std::array<int16_t, NTRU_P> C;
	std::array<int8_t, NTRU_P> b;
	std::vector<byte> k12(64);
	std::vector<byte> k34(64);
	size_t i;
	int16_t x;

	RqFromSeed(G, Key, KeyOffset);
	RqDecodeRounded(A, Key, KeyOffset);

	Digest::Keccak512 dgt;
	dgt.Compute(Rand, k12);

	SeededWeightW(b, k12);
	dgt.Update(k12, NTRU_SEED_SIZE, NTRU_SEED_SIZE);
	dgt.Finalize(k34, 0);

	RqMult(B, G, b);
	RqRound3(B, B);
	RqMult(C, A, b);

	for (i = 0; i < 256; ++i)
	{
		x = C[i];
		x = ModqSum(x, 2295 * (1 & (Rand[i / 8] >> (i & 7))));
		x = (((x + 2156) * 114) + 16384) >> 15;
		// between 0 and 15
		C[i] = x;
	}

	std::memcpy(CipherText.data(), k34.data(), NTRU_SEED_SIZE);
	std::memcpy(Secret.data(), k34.data() + NTRU_SEED_SIZE, NTRU_SEED_SIZE);
	RqEncodeRounded(CipherText, B);

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
	A -= 4591 * ((228 * A) >> 20);
	A -= 4591 * (((58470 * A) + 134217728) >> 28);

	return A;
}

int16_t NTRULQ4591N761::ModqFromUL(uint A)
{
	// input between 0 and 4294967295 output = (input % 4591) - 2295
	int32_t r;

	// <= 8010861
	r = (A & 524287) + (A >> 19) * 914;

	return ModqFreeze(r - 2295);
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
		f2 = ((14913081 * c3) + (58254 * c2) + (228 * (c1 + 2))) >> 21;

		c2 += c3 << 8;
		c2 -= (f2 * 9) << 2;
		f1 = ((89478485 * c2) + (349525 * c1) + (1365 * (c0 + 1))) >> 21;

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
	f1 = ((89478485 * c2) + (349525 * c1) + (1365 * (c0 + 1))) >> 21;

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
		f0 = (21846 * f0) >> 16;
		f1 = (21846 * f1) >> 16;
		f2 = (21846 * f2) >> 16;

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
	f0 = (21846 * f0) >> 16;
	f1 = (21846 * f1) >> 16;
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
	std::vector<byte> btbuf(NTRU_P * sizeof(uint));
	std::vector<byte> tmpK(NTRU_SEED_SIZE);
	std::vector<byte> n(16, 0);
	size_t i;

	std::memcpy(tmpK.data(), Key.data() + KeyOffset, NTRU_SEED_SIZE);

	Drbg::BCG gen(Enumeration::BlockCiphers::AHX);
	gen.Initialize(tmpK, n);
	gen.Generate(btbuf, 0, btbuf.size());

	std::memcpy(buf.data(), btbuf.data(), btbuf.size());

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
		H[i] = (((21846 * (F[i] + 2295) + 32768) >> 16) * 3) - 2295;
	}
}

void NTRULQ4591N761::SeededWeightW(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &K)
{
	std::array<int32_t, NTRU_P> r;
	std::vector<byte> tmpK(NTRU_SEED_SIZE);
	std::vector<byte> tmpR(NTRU_P * sizeof(int32_t));
	size_t i;

	std::memcpy(tmpK.data(), K.data(), tmpK.size());
	Prng::CSR rng(tmpK);
	rng.GetBytes(tmpR);
	std::memcpy(r.data(), tmpR.data(), tmpR.size());

	for (i = 0; i < NTRU_P; ++i)
	{
		r[i] ^= 0x80000000;
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
		F[i] = ((uint8_t)(r[i] & 3)) - 1;
	}
}

void NTRULQ4591N761::SmallDecode(std::array<int8_t, NTRU_P> &F, const std::vector<byte> &C)
{
	size_t i;
	byte c0;

	for (i = 0; i < NTRU_P / 4; ++i)
	{
		c0 = C[i];
		F[(i * 4)] = ((uint8_t)(c0 & 3)) - 1;
		c0 >>= 2;
		F[(i * 4) + 1] = ((uint8_t)(c0 & 3)) - 1;
		c0 >>= 2;
		F[(i * 4) + 2] = ((uint8_t)(c0 & 3)) - 1;
		c0 >>= 2;
		F[(i * 4) + 3] = ((uint8_t)(c0 & 3)) - 1;
	}

	c0 = C[i];
	F[i * 4] = ((uint8_t)(c0 & 3)) - 1;
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
	const int32_t TOP = 512;

	int32_t i;
	int32_t p;
	int32_t q;
	int32_t n;

	n = NTRU_P;

	for (p = TOP; p > 0; p >>= 1)
	{
		for (i = 0; i < n - p; ++i)
		{
			if (!(i & p))
			{
				MinMax(X[i], X[i + p]);
			}
		}

		for (q = TOP; q > p; q >>= 1)
		{
			for (i = 0; i < n - q; ++i)
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

NAMESPACE_NTRUEND