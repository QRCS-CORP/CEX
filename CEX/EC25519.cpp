#include "EC25519.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_ECDH

using Tools::IntegerTools;
using Tools::MemoryTools;

int32_t EC25519::EcdsaBaseIsZero(const std::vector<uint8_t> &N, const size_t Nlen)
{
	size_t i;
	uint8_t d;

	d = 0;

	for (i = 0; i < Nlen; ++i)
	{
		d |= N[i];
	}

	return 1 & ((d - 1) >> 8);
}

uint64_t EC25519::EcdsaBaseLoad3(const std::vector<uint8_t> &Input, size_t Offset)
{
	uint64_t res;

	res = static_cast<uint64_t>(Input[Offset]);
	res |= (static_cast<uint64_t>(Input[Offset+ 1])) << 8;
	res |= (static_cast<uint64_t>(Input[Offset + 2])) << 16;

	return res;
}

uint64_t EC25519::EcdsaBaseLoad4(const std::vector<uint8_t> &Input, size_t Offset)
{
	uint64_t res;

	res = static_cast<uint64_t>(Input[Offset]);
	res |= (static_cast<uint64_t>(Input[Offset + 1])) << 8;
	res |= (static_cast<uint64_t>(Input[Offset + 2])) << 16;
	res |= (static_cast<uint64_t>(Input[Offset + 3])) << 24;

	return res;
}

uint8_t EC25519::EcdsaBaseNegative(int8_t B)
{
	uint64_t x;

	x = B;
	x >>= 63;

	return static_cast<uint8_t>(x);
}

void EC25519::EcdsaBaseSlideVarTime(std::vector<int8_t> &R, const std::vector<uint8_t> &A, size_t AOffset)
{
	size_t i;
	size_t k;
	int32_t b;
	int32_t cmp;
	int32_t ribs;

	for (i = 0; i < 256; ++i)
	{
		R[i] = 1 & (A[AOffset + (i >> 3)] >> (i & 7));
	}

	for (i = 0; i < 256; ++i)
	{
		if (!R[i])
		{
			continue;
		}

		for (b = 1; b <= 6 && i + b < 256; ++b)
		{
			if (!R[i + b])
			{
				continue;
			}

			ribs = R[i + b] << b;
			cmp = R[i] + ribs;

			if (cmp <= 15)
			{
				R[i] = cmp;
				R[i + b] = 0;
			}
			else
			{
				cmp = R[i] - ribs;

				if (cmp < -15)
				{
					break;
				}

				R[i] = cmp;

				for (k = i + b; k < 256; ++k)
				{
					if (!R[k])
					{
						R[k] = 1;
						break;
					}

					R[k] = 0;
				}
			}
		}
	}
}

#if defined(CEX_SYSTEM_NATIVE_UINT128)

const EC25519::fe25519 EC25519::Fe25519SqrtM1 =
{
	// sqrt(-1)
	1718705420411056, 234908883556509, 2233514472574048, 2117202627021982, 765476049583133
};

const EC25519::fe25519 EC25519::Ed25519SqrtaM2 =
{
	// sqrt(-486664)
	1693982333959686, 608509411481997, 2235573344831311, 947681270984193, 266558006233600
};

const EC25519::fe25519 EC25519::Ed25519D =
{
	// 37095705934669439343138083508754565189542113879843219016388785533085940283555
	929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575
};

const EC25519::fe25519 EC25519::Ed25519D2 =
{
	// 2 * d = 16295367250680780974490674513165176452449235426866156013048779062215315747161
	1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903
};

const EC25519::fe25519 EC25519::Ed25519A =
{
	// A = 486662
	Ed25519A32, 0, 0, 0, 0
};

const EC25519::fe25519 EC25519::Ed25519SqrtadM1 =
{
	// sqrt(ad - 1) with a = -1 (mod p)
	2241493124984347, 425987919032274, 2207028919301688, 1220490630685848, 974799131293748
};

const EC25519::fe25519 EC25519::Ed25519InvSqrtaMd =
{
	// 1 / sqrt(a - d)
	278908739862762, 821645201101625, 8113234426968, 1777959178193151, 2118520810568447
};

const EC25519::fe25519 EC25519::Ed25519OneMsQd =
{
	// 1 - d ^ 2
	1136626929484150, 1998550399581263, 496427632559748, 118527312129759, 45110755273534
};

const EC25519::fe25519 EC25519::Ed25519SqdMOne =
{
	// (d - 1) ^ 2
	1507062230895904, 1572317787530805, 683053064812840, 317374165784489, 1572899562415810
};

void EC25519::Fe25519Zero(fe25519 &H)
{
	MemoryTools::Clear(H, 0, H.size() * sizeof(uint64_t));
}

void EC25519::Fe25519One(fe25519 &H)
{
	MemoryTools::Clear(H, 0, H.size() * sizeof(uint64_t));
	H[0] = 1;
}

void EC25519::Fe25519Add(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	// h = f + g; Can overlap h with f or g
	uint64_t h0;
	uint64_t h1;
	uint64_t h2;
	uint64_t h3;
	uint64_t h4;

	h0 = F[0] + G[0];
	h1 = F[1] + G[1];
	h2 = F[2] + G[2];
	h3 = F[3] + G[3];
	h4 = F[4] + G[4];
	H[0] = h0;
	H[1] = h1;
	H[2] = h2;
	H[3] = h3;
	H[4] = h4;
}

void EC25519::Fe25519Sub(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	// h = f - g
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint64_t h0;
	uint64_t h1;
	uint64_t h2;
	uint64_t h3;
	uint64_t h4;

	h0 = G[0];
	h1 = G[1];
	h2 = G[2];
	h3 = G[3];
	h4 = G[4];

	h1 += h0 >> 51;
	h0 &= MASK;
	h2 += h1 >> 51;
	h1 &= MASK;
	h3 += h2 >> 51;
	h2 &= MASK;
	h4 += h3 >> 51;
	h3 &= MASK;
	h0 += 19ULL * (h4 >> 51);
	h4 &= MASK;

	h0 = (F[0] + 0xFFFFFFFFFFFDAULL) - h0;
	h1 = (F[1] + 0xFFFFFFFFFFFFEULL) - h1;
	h2 = (F[2] + 0xFFFFFFFFFFFFEULL) - h2;
	h3 = (F[3] + 0xFFFFFFFFFFFFEULL) - h3;
	h4 = (F[4] + 0xFFFFFFFFFFFFEULL) - h4;

	H[0] = h0;
	H[1] = h1;
	H[2] = h2;
	H[3] = h3;
	H[4] = h4;
}

void EC25519::Fe25519Neg(fe25519 &H, const fe25519 &F)
{
	// h = -f
	fe25519 zero = { 0 };

	Fe25519Zero(zero);
	Fe25519Sub(H, zero, F);
}


void EC25519::Fe25519cMov(fe25519 &F, const fe25519 &G, uint32_t B)
{
	// Replace (f,g) with (g,g) if b == 1;
	// replace (f,g) with (f,g) if b == 0.
	// Preconditions: b in {0,1}.
	const uint64_t MASK = ~B + 1;
	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	uint64_t f4;
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;

	f0 = F[0];
	f1 = F[1];
	f2 = F[2];
	f3 = F[3];
	f4 = F[4];

	x0 = f0 ^ G[0];
	x1 = f1 ^ G[1];
	x2 = f2 ^ G[2];
	x3 = f3 ^ G[3];
	x4 = f4 ^ G[4];

	x0 &= MASK;
	x1 &= MASK;
	x2 &= MASK;
	x3 &= MASK;
	x4 &= MASK;

	F[0] = f0 ^ x0;
	F[1] = f1 ^ x1;
	F[2] = f2 ^ x2;
	F[3] = f3 ^ x3;
	F[4] = f4 ^ x4;
}

void EC25519::Fe25519cSwap(fe25519 &F, fe25519 &G, uint32_t B)
{
	// Replace (f,g) with (g,f) if b == 1;
	// replace (f,g) with (f,g) if b == 0.
	// Preconditions: b in {0,1}.
	const uint64_t MASK = ~B + 1;
	uint64_t f0;
	uint64_t f1;
	uint64_t f2;
	uint64_t f3;
	uint64_t f4;
	uint64_t g0;
	uint64_t g1;
	uint64_t g2;
	uint64_t g3;
	uint64_t g4;
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;

	f0 = F[0];
	f1 = F[1];
	f2 = F[2];
	f3 = F[3];
	f4 = F[4];

	g0 = G[0];
	g1 = G[1];
	g2 = G[2];
	g3 = G[3];
	g4 = G[4];

	x0 = f0 ^ g0;
	x1 = f1 ^ g1;
	x2 = f2 ^ g2;
	x3 = f3 ^ g3;
	x4 = f4 ^ g4;

	x0 &= MASK;
	x1 &= MASK;
	x2 &= MASK;
	x3 &= MASK;
	x4 &= MASK;

	F[0] = f0 ^ x0;
	F[1] = f1 ^ x1;
	F[2] = f2 ^ x2;
	F[3] = f3 ^ x3;
	F[4] = f4 ^ x4;

	G[0] = g0 ^ x0;
	G[1] = g1 ^ x1;
	G[2] = g2 ^ x2;
	G[3] = g3 ^ x3;
	G[4] = g4 ^ x4;
}

void EC25519::Fe25519Copy(fe25519 &H, const fe25519 &F)
{
	MemoryTools::Copy(F, 0, H, 0, F.size() * sizeof(5));
}

int32_t EC25519::Fe25519IsNegative(const fe25519 &F)
{
	// return 1 if f is in {1,3,5,...,q-2}
	// return 0 if f is in {0,2,4,...,q-1}
	std::vector<uint8_t> s(32);

	Fe25519ToBytes(s, F);

	return s[0] & 1;
}

int32_t EC25519::Fe25519IsZero(const fe25519 &F)
{
	std::vector<uint8_t> s(32);

	Fe25519ToBytes(s, F);

	return EcdsaBaseIsZero(s, 32);
}

void EC25519::Fe25519Mul(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	// h = f * g; Can overlap h with f or g
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint128_t r0;
	uint128_t r1;
	uint128_t r2;
	uint128_t r3;
	uint128_t r4;
	uint128_t f0;
	uint128_t f1;
	uint128_t f2;
	uint128_t f3;
	uint128_t f4;
	uint128_t f119;
	uint128_t f219;
	uint128_t f319;
	uint128_t f419;
	uint128_t g0;
	uint128_t g1;
	uint128_t g2;
	uint128_t g3;
	uint128_t g4;
	uint128_t r01;
	uint128_t r02;
	uint128_t r03;
	uint128_t r04;
	uint64_t  carry;
	uint64_t  r00;

	f0 = static_cast<uint128_t>(F[0]);
	f1 = static_cast<uint128_t>(F[1]);
	f2 = static_cast<uint128_t>(F[2]);
	f3 = static_cast<uint128_t>(F[3]);
	f4 = static_cast<uint128_t>(F[4]);

	g0 = static_cast<uint128_t>(G[0]);
	g1 = static_cast<uint128_t>(G[1]);
	g2 = static_cast<uint128_t>(G[2]);
	g3 = static_cast<uint128_t>(G[3]);
	g4 = static_cast<uint128_t>(G[4]);

	f119 = 19ULL * f1;
	f219 = 19ULL * f2;
	f319 = 19ULL * f3;
	f419 = 19ULL * f4;

	r0 = f0 * g0 + f119 * g4 + f219 * g3 + f319 * g2 + f419 * g1;
	r1 = f0 * g1 + f1 * g0 + f219 * g4 + f319 * g3 + f419 * g2;
	r2 = f0 * g2 + f1 * g1 + f2 * g0 + f319 * g4 + f419 * g3;
	r3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f419 * g4;
	r4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

	r00 = static_cast<uint64_t>(r0) & MASK;
	carry = static_cast<uint64_t>(r0 >> 51);
	r1 += carry;
	r01 = static_cast<uint64_t>(r1) & MASK;
	carry = static_cast<uint64_t>(r1 >> 51);
	r2 += carry;
	r02 = static_cast<uint64_t>(r2) & MASK;
	carry = static_cast<uint64_t>(r2 >> 51);
	r3 += carry;
	r03 = static_cast<uint64_t>(r3) & MASK;
	carry = static_cast<uint64_t>(r3 >> 51);
	r4 += carry;
	r04 = static_cast<uint64_t>(r4) & MASK;
	carry = static_cast<uint64_t>(r4 >> 51);
	r00 += 19ULL * carry;
	carry = r00 >> 51;
	r00 &= MASK;
	r01 += carry;
	carry = r01 >> 51;
	r01 &= MASK;
	r02 += carry;

	H[0] = r00;
	H[1] = r01;
	H[2] = r02;
	H[3] = r03;
	H[4] = r04;
}

void EC25519::Fe25519Sq(fe25519 &H, const fe25519 &F)
{
	// h = f * f; Can overlap h with f
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint128_t r0;
	uint128_t r1;
	uint128_t r2;
	uint128_t r3;
	uint128_t r4;
	uint128_t f0;
	uint128_t f1;
	uint128_t f2;
	uint128_t f3;
	uint128_t f4;
	uint128_t f0x2;
	uint128_t f1x2;
	uint128_t f138;
	uint128_t f238;
	uint128_t f338;
	uint128_t f319;
	uint128_t f419;
	uint128_t r01;
	uint128_t r02;
	uint128_t r03;
	uint128_t r04;
	uint64_t  carry;
	uint64_t r00;

	f0 = static_cast<uint128_t>(F[0]);
	f1 = static_cast<uint128_t>(F[1]);
	f2 = static_cast<uint128_t>(F[2]);
	f3 = static_cast<uint128_t>(F[3]);
	f4 = static_cast<uint128_t>(F[4]);

	f0x2 = f0 << 1;
	f1x2 = f1 << 1;
	f138 = 38ULL * f1;
	f238 = 38ULL * f2;
	f338 = 38ULL * f3;
	f319 = 19ULL * f3;
	f419 = 19ULL * f4;

	r0 = f0 * f0 + f138 * f4 + f238 * f3;
	r1 = f0x2 * f1 + f238 * f4 + f319 * f3;
	r2 = f0x2 * f2 + f1 * f1 + f338 * f4;
	r3 = f0x2 * f3 + f1x2 * f2 + f419 * f4;
	r4 = f0x2 * f4 + f1x2 * f3 + f2 * f2;

	r00 = static_cast<uint64_t>(r0) & MASK;
	carry = static_cast<uint64_t>(r0 >> 51);
	r1 += carry;
	r01 = static_cast<uint64_t>(r1) & MASK;
	carry = static_cast<uint64_t>(r1 >> 51);
	r2 += carry;
	r02 = static_cast<uint64_t>(r2) & MASK;
	carry = static_cast<uint64_t>(r2 >> 51);
	r3 += carry;
	r03 = static_cast<uint64_t>(r3) & MASK;
	carry = static_cast<uint64_t>(r3 >> 51);
	r4 += carry;
	r04 = static_cast<uint64_t>(r4) & MASK;
	carry = static_cast<uint64_t>(r4 >> 51);
	r00 += 19ULL * carry;
	carry = r00 >> 51;
	r00 &= MASK;
	r01 += carry;
	carry = r01 >> 51;
	r01 &= MASK;
	r02 += carry;

	H[0] = r00;
	H[1] = r01;
	H[2] = r02;
	H[3] = r03;
	H[4] = r04;
}

void EC25519::Fe25519Sq2(fe25519 &H, const fe25519 &F)
{
	// h = 2 * f * f; Can overlap h with f
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint128_t r0;
	uint128_t r1;
	uint128_t r2;
	uint128_t r3;
	uint128_t r4;
	uint128_t f0;
	uint128_t f1;
	uint128_t f2;
	uint128_t f3;
	uint128_t f4;
	uint128_t f0x2;
	uint128_t f1x2;
	uint128_t f138;
	uint128_t f238;
	uint128_t f338;
	uint128_t f319;
	uint128_t f419;
	uint128_t r01;
	uint128_t r02;
	uint128_t r03;
	uint128_t r04;
	uint64_t carry;
	uint64_t r00;

	f0 = static_cast<uint128_t>(F[0]);
	f1 = static_cast<uint128_t>(F[1]);
	f2 = static_cast<uint128_t>(F[2]);
	f3 = static_cast<uint128_t>(F[3]);
	f4 = static_cast<uint128_t>(F[4]);

	f0x2 = f0 << 1;
	f1x2 = f1 << 1;
	f138 = 38ULL * f1;
	f238 = 38ULL * f2;
	f338 = 38ULL * f3;
	f319 = 19ULL * f3;
	f419 = 19ULL * f4;

	r0 = f0 * f0 + f138 * f4 + f238 * f3;
	r1 = f0x2 * f1 + f238 * f4 + f319 * f3;
	r2 = f0x2 * f2 + f1 * f1 + f338 * f4;
	r3 = f0x2 * f3 + f1x2 * f2 + f419 * f4;
	r4 = f0x2 * f4 + f1x2 * f3 + f2 * f2;

	r0 <<= 1;
	r1 <<= 1;
	r2 <<= 1;
	r3 <<= 1;
	r4 <<= 1;

	r00 = static_cast<uint64_t>(r0) & MASK;
	carry = static_cast<uint64_t>(r0 >> 51);
	r1 += carry;
	r01 = static_cast<uint64_t>(r1) & MASK;
	carry = static_cast<uint64_t>(r1 >> 51);
	r2 += carry;
	r02 = static_cast<uint64_t>(r2) & MASK;
	carry = static_cast<uint64_t>(r2 >> 51);
	r3 += carry;
	r03 = static_cast<uint64_t>(r3) & MASK;
	carry = static_cast<uint64_t>(r3 >> 51);
	r4 += carry;
	r04 = static_cast<uint64_t>(r4) & MASK;
	carry = static_cast<uint64_t>(r4 >> 51);
	r00 += 19ULL * carry;
	carry = r00 >> 51;
	r00 &= MASK;
	r01 += carry;
	carry = r01 >> 51;
	r01 &= MASK;
	r02 += carry;

	H[0] = r00;
	H[1] = r01;
	H[2] = r02;
	H[3] = r03;
	H[4] = r04;
}

void EC25519::Fe25519Mul32(fe25519 &H, const fe25519 &F, uint32_t N)
{
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint128_t a;
	uint128_t sn;
	uint64_t h0;
	uint64_t h1;
	uint64_t h2;
	uint64_t h3;
	uint64_t h4;

	sn = static_cast<uint128_t>(N);
	a = F[0] * sn;
	h0 = static_cast<uint64_t>(a) & MASK;
	a = (F[1] * sn) + static_cast<uint64_t>(a >> 51);
	h1 = static_cast<uint64_t>(a) & MASK;
	a = (F[2] * sn) + static_cast<uint64_t>(a >> 51);
	h2 = static_cast<uint64_t>(a) & MASK;
	a = (F[3] * sn) + static_cast<uint64_t>(a >> 51);
	h3 = static_cast<uint64_t>(a) & MASK;
	a = (F[4] * sn) + static_cast<uint64_t>(a >> 51);
	h4 = static_cast<uint64_t>(a) & MASK;
	h0 += static_cast<uint64_t>(a >> 51) * 19ULL;

	H[0] = h0;
	H[1] = h1;
	H[2] = h2;
	H[3] = h3;
	H[4] = h4;
}

void EC25519::Fe25519FromBytes(fe25519 &H, const std::vector<uint8_t> &S)
{
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	uint64_t h0;
	uint64_t h1;
	uint64_t h2;
	uint64_t h3;
	uint64_t h4;

	h0 = (IntegerTools::LeBytesTo64(S, 0)) & MASK;
	h1 = (IntegerTools::LeBytesTo64(S, 6) >> 3) & MASK;
	h2 = (IntegerTools::LeBytesTo64(S, 12) >> 6) & MASK;
	h3 = (IntegerTools::LeBytesTo64(S, 19) >> 1) & MASK;
	h4 = (IntegerTools::LeBytesTo64(S, 24) >> 12) & MASK;

	H[0] = h0;
	H[1] = h1;
	H[2] = h2;
	H[3] = h3;
	H[4] = h4;
}

void EC25519::Fe25519Reduce(fe25519 &H, const fe25519 &F)
{
	const uint64_t MASK = 0x7FFFFFFFFFFFFULL;
	std::array<uint128_t, 5> t = { 0 };

	t[0] = F[0];
	t[1] = F[1];
	t[2] = F[2];
	t[3] = F[3];
	t[4] = F[4];

	t[1] += t[0] >> 51;
	t[0] &= MASK;
	t[2] += t[1] >> 51;
	t[1] &= MASK;
	t[3] += t[2] >> 51;
	t[2] &= MASK;
	t[4] += t[3] >> 51;
	t[3] &= MASK;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= MASK;

	t[1] += t[0] >> 51;
	t[0] &= MASK;
	t[2] += t[1] >> 51;
	t[1] &= MASK;
	t[3] += t[2] >> 51;
	t[2] &= MASK;
	t[4] += t[3] >> 51;
	t[3] &= MASK;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= MASK;

	// now t is between 0 and 2^255-1, properly carried
	// case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1
	t[0] += 19ULL;
	t[1] += t[0] >> 51;
	t[0] &= MASK;
	t[2] += t[1] >> 51;
	t[1] &= MASK;
	t[3] += t[2] >> 51;
	t[2] &= MASK;
	t[4] += t[3] >> 51;
	t[3] &= MASK;
	t[0] += 19ULL * (t[4] >> 51);
	t[4] &= MASK;

	// now between 19 and 2^255-1 in both cases, and offset by 19
	t[0] += 0x8000000000000ULL - 19ULL;
	t[1] += 0x8000000000000ULL - 1ULL;
	t[2] += 0x8000000000000ULL - 1ULL;
	t[3] += 0x8000000000000ULL - 1ULL;
	t[4] += 0x8000000000000ULL - 1ULL;

	// now between 2^255 and 2^256-20, and offset by 2^255
	t[1] += t[0] >> 51;
	t[0] &= MASK;
	t[2] += t[1] >> 51;
	t[1] &= MASK;
	t[3] += t[2] >> 51;
	t[2] &= MASK;
	t[4] += t[3] >> 51;
	t[3] &= MASK;
	t[4] &= MASK;

	H[0] = t[0];
	H[1] = t[1];
	H[2] = t[2];
	H[3] = t[3];
	H[4] = t[4];
}

void EC25519::Fe25519ToBytes(std::vector<uint8_t> &S, const fe25519 &H)
{
	fe25519 t = { 0 };
	uint64_t t0;
	uint64_t t1;
	uint64_t t2;
	uint64_t t3;

	Fe25519Reduce(t, H);
	t0 = t[0] | (t[1] << 51);
	t1 = (t[1] >> 13) | (t[2] << 38);
	t2 = (t[2] >> 26) | (t[3] << 25);
	t3 = (t[3] >> 39) | (t[4] << 12);
	IntegerTools::Le64ToBytes(t0, S, 0);
	IntegerTools::Le64ToBytes(t1, S, 8);
	IntegerTools::Le64ToBytes(t2, S, 16);
	IntegerTools::Le64ToBytes(t3, S, 24);
}

#else

const EC25519::fe25519 EC25519::Ed25519D =
{
	// 37095705934669439343138083508754565189542113879843219016388785533085940283555
	-10913610, 13857413, -15372611, 6949391,   114729, -8787816, -6275908, -3247719, -18696448, -12055116
};

const EC25519::fe25519 EC25519::Fe25519SqrtM1 =
{
	// sqrt(-1)
	-32595792, -7943725,  9377950,  3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
};

const EC25519::fe25519 EC25519::Ed25519D2 =
{
	// 2 * d = 16295367250680780974490674513165176452449235426866156013048779062215315747161
	-21827239, -5839606,  -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199
};

void EC25519::Fe25519Zero(fe25519 &H)
{
	MemoryTools::Clear(H, 0, H.size() * sizeof(int32_t));
}

void EC25519::Fe25519One(fe25519 &H)
{
	MemoryTools::Clear(H, 0, H.size() * sizeof(int32_t));
	H[0] = 1;
}

void EC25519::Fe25519Add(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	H[0] = F[0] + G[0];
	H[1] = F[1] + G[1];
	H[2] = F[2] + G[2];
	H[3] = F[3] + G[3];
	H[4] = F[4] + G[4];
	H[5] = F[5] + G[5];
	H[6] = F[6] + G[6];
	H[7] = F[7] + G[7];
	H[8] = F[8] + G[8];
	H[9] = F[9] + G[9];
}

void EC25519::Fe25519cSwap(fe25519 &F, fe25519 &G, uint32_t B)
{
	const uint32_t MASK = ~B + 1;
	int32_t f0;
	int32_t f1;
	int32_t f2;
	int32_t f3;
	int32_t f4;
	int32_t f5;
	int32_t f6;
	int32_t f7;
	int32_t f8;
	int32_t f9;
	int32_t g0;
	int32_t g1;
	int32_t g2;
	int32_t g3;
	int32_t g4;
	int32_t g5;
	int32_t g6;
	int32_t g7;
	int32_t g8;
	int32_t g9;
	int32_t x0;
	int32_t x1;
	int32_t x2;
	int32_t x3;
	int32_t x4;
	int32_t x5;
	int32_t x6;
	int32_t x7;
	int32_t x8;
	int32_t x9;

	f0 = F[0];
	f1 = F[1];
	f2 = F[2];
	f3 = F[3];
	f4 = F[4];
	f5 = F[5];
	f6 = F[6];
	f7 = F[7];
	f8 = F[8];
	f9 = F[9];

	g0 = G[0];
	g1 = G[1];
	g2 = G[2];
	g3 = G[3];
	g4 = G[4];
	g5 = G[5];
	g6 = G[6];
	g7 = G[7];
	g8 = G[8];
	g9 = G[9];

	x0 = f0 ^ g0;
	x1 = f1 ^ g1;
	x2 = f2 ^ g2;
	x3 = f3 ^ g3;
	x4 = f4 ^ g4;
	x5 = f5 ^ g5;
	x6 = f6 ^ g6;
	x7 = f7 ^ g7;
	x8 = f8 ^ g8;
	x9 = f9 ^ g9;

	x0 &= MASK;
	x1 &= MASK;
	x2 &= MASK;
	x3 &= MASK;
	x4 &= MASK;
	x5 &= MASK;
	x6 &= MASK;
	x7 &= MASK;
	x8 &= MASK;
	x9 &= MASK;

	F[0] = f0 ^ x0;
	F[1] = f1 ^ x1;
	F[2] = f2 ^ x2;
	F[3] = f3 ^ x3;
	F[4] = f4 ^ x4;
	F[5] = f5 ^ x5;
	F[6] = f6 ^ x6;
	F[7] = f7 ^ x7;
	F[8] = f8 ^ x8;
	F[9] = f9 ^ x9;

	G[0] = g0 ^ x0;
	G[1] = g1 ^ x1;
	G[2] = g2 ^ x2;
	G[3] = g3 ^ x3;
	G[4] = g4 ^ x4;
	G[5] = g5 ^ x5;
	G[6] = g6 ^ x6;
	G[7] = g7 ^ x7;
	G[8] = g8 ^ x8;
	G[9] = g9 ^ x9;
}

void EC25519::Fe25519Sub(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	// H = f - g
	// Can overlap h with f or g.
	// Preconditions:
	// *|f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	// |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	// Postconditions:
	// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	H[0] = F[0] - G[0];
	H[1] = F[1] - G[1];
	H[2] = F[2] - G[2];
	H[3] = F[3] - G[3];
	H[4] = F[4] - G[4];
	H[5] = F[5] - G[5];
	H[6] = F[6] - G[6];
	H[7] = F[7] - G[7];
	H[8] = F[8] - G[8];
	H[9] = F[9] - G[9];
}

void EC25519::Fe25519Neg(fe25519 &H, const fe25519 &F)
{
	H[0] = -F[0];
	H[1] = -F[1];
	H[2] = -F[2];
	H[3] = -F[3];
	H[4] = -F[4];
	H[5] = -F[5];
	H[6] = -F[6];
	H[7] = -F[7];
	H[8] = -F[8];
	H[9] = -F[9];
}

void EC25519::Fe25519cMov(fe25519 &F, const fe25519 &G, uint32_t B)
{
	const uint32_t MASK = ~B + 1;
	int32_t f0;
	int32_t f1;
	int32_t f2;
	int32_t f3;
	int32_t f4;
	int32_t f5;
	int32_t f6;
	int32_t f7;
	int32_t f8;
	int32_t f9;

	f0 = F[0];
	f1 = F[1];
	f2 = F[2];
	f3 = F[3];
	f4 = F[4];
	f5 = F[5];
	f6 = F[6];
	f7 = F[7];
	f8 = F[8];
	f9 = F[9];

	f0 ^= (f0 ^ G[0]) & MASK;
	f1 ^= (f1 ^ G[1]) & MASK;
	f2 ^= (f2 ^ G[2]) & MASK;
	f3 ^= (f3 ^ G[3]) & MASK;
	f4 ^= (f4 ^ G[4]) & MASK;
	f5 ^= (f5 ^ G[5]) & MASK;
	f6 ^= (f6 ^ G[6]) & MASK;
	f7 ^= (f7 ^ G[7]) & MASK;
	f8 ^= (f8 ^ G[8]) & MASK;
	f9 ^= (f9 ^ G[9]) & MASK;

	F[0] = f0;
	F[1] = f1;
	F[2] = f2;
	F[3] = f3;
	F[4] = f4;
	F[5] = f5;
	F[6] = f6;
	F[7] = f7;
	F[8] = f8;
	F[9] = f9;
}

void EC25519::Fe25519Copy(fe25519 &H, const fe25519 &F)
{
	MemoryTools::Copy(F, 0, H, 0, F.size() * sizeof(int32_t));
}

int32_t EC25519::Fe25519IsNegative(const fe25519 &F)
{
	std::vector<uint8_t> s(32);

	Fe25519ToBytes(s, F);

	return s[0] & 1;
}

int32_t EC25519::Fe25519IsZero(const fe25519 &F)
{
	std::vector<uint8_t> s(32);

	Fe25519ToBytes(s, F);

	return EcdsaBaseIsZero(s, 32);
}

void EC25519::Fe25519Mul(fe25519 &H, const fe25519 &F, const fe25519 &G)
{
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f1x2;
	int64_t f3x2;
	int64_t f5x2;
	int64_t f7x2;
	int64_t f9x2;
	int64_t g0;
	int64_t g1;
	int64_t g2;
	int64_t g3;
	int64_t g4;
	int64_t g5;
	int64_t g6;
	int64_t g7;
	int64_t g8;
	int64_t g9;
	int64_t g1x19;
	int64_t g2x19;
	int64_t g3x19;
	int64_t g4x19;
	int64_t g5x19;
	int64_t g6x19;
	int64_t g7x19;
	int64_t g8x19;
	int64_t g9x19;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = static_cast<int64_t>(F[0]);
	f1 = static_cast<int64_t>(F[1]);
	f2 = static_cast<int64_t>(F[2]);
	f3 = static_cast<int64_t>(F[3]);
	f4 = static_cast<int64_t>(F[4]);
	f5 = static_cast<int64_t>(F[5]);
	f6 = static_cast<int64_t>(F[6]);
	f7 = static_cast<int64_t>(F[7]);
	f8 = static_cast<int64_t>(F[8]);
	f9 = static_cast<int64_t>(F[9]);
	g0 = static_cast<int64_t>(G[0]);
	g1 = static_cast<int64_t>(G[1]);
	g2 = static_cast<int64_t>(G[2]);
	g3 = static_cast<int64_t>(G[3]);
	g4 = static_cast<int64_t>(G[4]);
	g5 = static_cast<int64_t>(G[5]);
	g6 = static_cast<int64_t>(G[6]);
	g7 = static_cast<int64_t>(G[7]);
	g8 = static_cast<int64_t>(G[8]);
	g9 = static_cast<int64_t>(G[9]);

	// 1.959375*2^29
	g1x19 = 19 * g1;
	// 1.959375*2^30; still ok
	g2x19 = 19 * g2;
	g3x19 = 19 * g3;
	g4x19 = 19 * g4;
	g5x19 = 19 * g5;
	g6x19 = 19 * g6;
	g7x19 = 19 * g7;
	g8x19 = 19 * g8;
	g9x19 = 19 * g9;
	f1x2 = 2 * f1;
	f3x2 = 2 * f3;
	f5x2 = 2 * f5;
	f7x2 = 2 * f7;
	f9x2 = 2 * f9;

	h0 = (f0 * g0) + (f1x2 * g9x19) + (f2 * g8x19) + (f3x2 * g7x19) + (f4 * g6x19) + (f5x2 * g5x19) + (f6 * g4x19) + (f7x2 * g3x19) + (f8 * g2x19) + (f9x2 * g1x19);
	h1 = (f0 * g1) + (f1 * g0) + (f2 * g9x19) + (f3 * g8x19) + (f4 * g7x19) + (f5 * g6x19) + (f6 * g5x19) + (f7 * g4x19) + (f8 * g3x19) + (f9 * g2x19);
	h2 = (f0 * g2) + (f1x2 * g1) + (f2 * g0) + (f3x2 * g9x19) + (f4 * g8x19) + (f5x2 * g7x19) + (f6 * g6x19) + (f7x2 * g5x19) + (f8 * g4x19) + (f9x2 * g3x19);
	h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4 * g9x19) + (f5 * g8x19) + (f6 * g7x19) + (f7 * g6x19) + (f8 * g5x19) + (f9 * g4x19);
	h4 = (f0 * g4) + (f1x2 * g3) + (f2 * g2) + (f3x2 * g1) + (f4 * g0) + (f5x2 * g9x19) + (f6 * g8x19) + (f7x2 * g7x19) + (f8 * g6x19) + (f9x2 * g5x19);
	h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0) + (f6 * g9x19) + (f7 * g8x19) + (f8 * g7x19) + (f9 * g6x19);
	h6 = (f0 * g6) + (f1x2 * g5) + (f2 * g4) + (f3x2 * g3) + (f4 * g2) + (f5x2 * g1) + (f6 * g0) + (f7x2 * g9x19) + (f8 * g8x19) + (f9x2 * g7x19);
	h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0) + (f8 * g9x19) + (f9 * g8x19);
	h8 = (f0 * g8) + (f1x2 * g7) + (f2 * g6) + (f3x2 * g5) + (f4 * g4) + (f5x2 * g3) + (f6 * g2) + (f7x2 * g1) + (f8 * g0) + (f9x2 * g9x19);
	h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);

	// |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
	// i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
	// |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
	// i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);
	// |h0| <= 2^25
	// |h4| <= 2^25
	// |h1| <= 1.71*2^59
	// |h5| <= 1.71*2^59
	carry = (h1 + (1LL << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1ULL << 25);
	carry = (h5 + (1LL << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1ULL << 25);
	// |h1| <= 2^24; from now on fits into int32
	// |h5| <= 2^24; from now on fits into int32
	// |h2| <= 1.41*2^60
	// |h6| <= 1.41*2^60
	carry = (h2 + (1LL << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1ULL << 26);
	carry = (h6 + (1LL << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1ULL << 26);
	// |h2| <= 2^25; from now on fits into int32 unchanged
	// |h6| <= 2^25; from now on fits into int32 unchanged
	// |h3| <= 1.71*2^59
	// |h7| <= 1.71*2^59
	carry = (h3 + (1LL << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1ULL << 25);
	carry = (h7 + (1LL << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1ULL << 25);
	// |h3| <= 2^24; from now on fits into int32 unchanged
	// |h7| <= 2^24; from now on fits into int32 unchanged
	// |h4| <= 1.72*2^34
	// |h8| <= 1.41*2^60
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);
	carry = (h8 + (1LL << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1ULL << 26);
	// |h4| <= 2^25; from now on fits into int32 unchanged
	// |h8| <= 2^25; from now on fits into int32 unchanged
	// |h5| <= 1.01*2^24
	// |h9| <= 1.71*2^59
	carry = (h9 + (1LL << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1ULL << 25);
	// |h9| <= 2^24; from now on fits into int32 unchanged
	// |h0| <= 1.1*2^39
	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);
	// |h0| <= 2^25; from now on fits into int32 unchanged
	// |h1| <= 1.01*2^24

	H[0] = static_cast<int32_t>(h0);
	H[1] = static_cast<int32_t>(h1);
	H[2] = static_cast<int32_t>(h2);
	H[3] = static_cast<int32_t>(h3);
	H[4] = static_cast<int32_t>(h4);
	H[5] = static_cast<int32_t>(h5);
	H[6] = static_cast<int32_t>(h6);
	H[7] = static_cast<int32_t>(h7);
	H[8] = static_cast<int32_t>(h8);
	H[9] = static_cast<int32_t>(h9);
}

void EC25519::Fe25519Mul32(fe25519 &H, const fe25519 &F, uint32_t N)
{
	int64_t carry;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;
	int64_t sn;

	sn = static_cast<int64_t>(N);
	h0 = F[0] * sn;
	h1 = F[1] * sn;
	h2 = F[2] * sn;
	h3 = F[3] * sn;
	h4 = F[4] * sn;
	h5 = F[5] * sn;
	h6 = F[6] * sn;
	h7 = F[7] * sn;
	h8 = F[8] * sn;
	h9 = F[9] * sn;

	carry = (h9 + (1LL << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1LL << 25);
	carry = (h1 + (1LL << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1LL << 25);
	carry = (h3 + (1LL << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1LL << 25);
	carry = (h5 + (1LL << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1LL << 25);
	carry = (h7 + (1LL << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1LL << 25);

	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1LL << 26);
	carry = (h2 + (1LL << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1LL << 26);
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1LL << 26);
	carry = (h6 + (1LL << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1LL << 26);
	carry = (h8 + (1LL << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1LL << 26);

	H[0] = static_cast<int32_t>(h0);
	H[1] = static_cast<int32_t>(h1);
	H[2] = static_cast<int32_t>(h2);
	H[3] = static_cast<int32_t>(h3);
	H[4] = static_cast<int32_t>(h4);
	H[5] = static_cast<int32_t>(h5);
	H[6] = static_cast<int32_t>(h6);
	H[7] = static_cast<int32_t>(h7);
	H[8] = static_cast<int32_t>(h8);
	H[9] = static_cast<int32_t>(h9);
}

void EC25519::Fe25519Sq(fe25519 &H, const fe25519 &F)
{
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f0x2;
	int64_t f1x2;
	int64_t f2x2;
	int64_t f3x2;
	int64_t f4x2;
	int64_t f5x2;
	int64_t f6x2;
	int64_t f7x2;
	int64_t f5x38;
	int64_t f6x19;
	int64_t f7x38;
	int64_t f8x19;
	int64_t f9x38;
	int64_t f0f0;
	int64_t f0f1x2;
	int64_t f0f2x2;
	int64_t f0f3x2;
	int64_t f0f4x2;
	int64_t f0f5x2;
	int64_t f0f6x2;
	int64_t f0f7x2;
	int64_t f0f8x2;
	int64_t f0f9x2;
	int64_t f1f1x2;
	int64_t f1f2x2;
	int64_t f1f3x4;
	int64_t f1f4x2;
	int64_t f1f5x4;
	int64_t f1f6x2;
	int64_t f1f7x4;
	int64_t f1f8x2;
	int64_t f1f9x76;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = static_cast<int64_t>(F[0]);
	f1 = static_cast<int64_t>(F[1]);
	f2 = static_cast<int64_t>(F[2]);
	f3 = static_cast<int64_t>(F[3]);
	f4 = static_cast<int64_t>(F[4]);
	f5 = static_cast<int64_t>(F[5]);
	f6 = static_cast<int64_t>(F[6]);
	f7 = static_cast<int64_t>(F[7]);
	f8 = static_cast<int64_t>(F[8]);
	f9 = static_cast<int64_t>(F[9]);

	f0x2 = 2 * f0;
	f1x2 = 2 * f1;
	f2x2 = 2 * f2;
	f3x2 = 2 * f3;
	f4x2 = 2 * f4;
	f5x2 = 2 * f5;
	f6x2 = 2 * f6;
	f7x2 = 2 * f7;
	// 1.959375*2^30
	f5x38 = 38 * f5;
	// 1.959375*2^30
	f6x19 = 19 * f6;
	// 1.959375*2^30
	f7x38 = 38 * f7;
	// 1.959375*2^30
	f8x19 = 19 * f8;
	// 1.959375*2^30
	f9x38 = 38 * f9;

	f0f0 = f0 * f0;
	f0f1x2 = f0x2 * f1;
	f0f2x2 = f0x2 * f2;
	f0f3x2 = f0x2 * f3;
	f0f4x2 = f0x2 * f4;
	f0f5x2 = f0x2 * f5;
	f0f6x2 = f0x2 * f6;
	f0f7x2 = f0x2 * f7;
	f0f8x2 = f0x2 * f8;
	f0f9x2 = f0x2 * f9;
	f1f1x2 = f1x2 * f1;
	f1f2x2 = f1x2 * f2;
	f1f3x4 = f1x2 * f3x2;
	f1f4x2 = f1x2 * f4;
	f1f5x4 = f1x2 * f5x2;
	f1f6x2 = f1x2 * f6;
	f1f7x4 = f1x2 * f7x2;
	f1f8x2 = f1x2 * f8;
	f1f9x76 = f1x2 * f9x38;

	h0 = f0f0 + f1f9x76 + (f2x2 * f8x19) + (f3x2 * f7x38) + (f4x2 * f6x19) + (f5 * f5x38);
	h1 = f0f1x2 + (f2 * f9x38) + (f3x2 * f8x19) + (f4 * f7x38) + (f5x2 * f6x19);
	h2 = f0f2x2 + f1f1x2 + (f3x2 * f9x38) + (f4x2 * f8x19) + (f5x2 * f7x38) + (f6 * f6x19);
	h3 = f0f3x2 + f1f2x2 + (f4 * f9x38) + (f5x2 * f8x19) + (f6 * f7x38);
	h4 = f0f4x2 + f1f3x4 + (f2 * f2) + (f5x2 * f9x38) + (f6x2 * f8x19) + (f7 * f7x38);
	h5 = f0f5x2 + f1f4x2 + (f2x2 * f3) + (f6 * f9x38) + (f7x2 * f8x19);
	h6 = f0f6x2 + f1f5x4 + (f2x2 * f4) + (f3x2 * f3) + (f7x2 * f9x38) + (f8 * f8x19);
	h7 = f0f7x2 + f1f6x2 + (f2x2 * f5) + (f3x2 * f4) + (f8 * f9x38);
	h8 = f0f8x2 + f1f7x4 + (f2x2 * f6) + (f3x2 * f5x2) + (f4 * f4) + (f9 * f9x38);
	h9 = f0f9x2 + f1f8x2 + (f2x2 * f7) + (f3x2 * f6) + (f4x2 * f5);

	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);

	carry = (h1 + (1LL << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1ULL << 25);
	carry = (h5 + (1LL << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1ULL << 25);

	carry = (h2 + (1LL << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1ULL << 26);
	carry = (h6 + (1LL << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1ULL << 26);

	carry = (h3 + (1LL << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1ULL << 25);
	carry = (h7 + (1LL << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1ULL << 25);

	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);
	carry = (h8 + (1LL << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1ULL << 26);

	carry = (h9 + (1LL << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1ULL << 25);

	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);

	H[0] = static_cast<int32_t>(h0);
	H[1] = static_cast<int32_t>(h1);
	H[2] = static_cast<int32_t>(h2);
	H[3] = static_cast<int32_t>(h3);
	H[4] = static_cast<int32_t>(h4);
	H[5] = static_cast<int32_t>(h5);
	H[6] = static_cast<int32_t>(h6);
	H[7] = static_cast<int32_t>(h7);
	H[8] = static_cast<int32_t>(h8);
	H[9] = static_cast<int32_t>(h9);
}

void EC25519::Fe25519Sq2(fe25519 &H, const fe25519 &F)
{
	// h = 2 * f * f
	// Can overlap h with f.
	// Preconditions:
	// |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
	// Postconditions:
	// |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
	int64_t carry;
	int64_t f0;
	int64_t f1;
	int64_t f2;
	int64_t f3;
	int64_t f4;
	int64_t f5;
	int64_t f6;
	int64_t f7;
	int64_t f8;
	int64_t f9;
	int64_t f0x2;
	int64_t f1x2;
	int64_t f2x2;
	int64_t f3x2;
	int64_t f4x2;
	int64_t f5x2;
	int64_t f6x2;
	int64_t f7x2;
	int64_t f5x38;
	int64_t f6x19;
	int64_t f7x38;
	int64_t f8x19;
	int64_t f9x38;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	f0 = static_cast<int64_t>(F[0]);
	f1 = static_cast<int64_t>(F[1]);
	f2 = static_cast<int64_t>(F[2]);
	f3 = static_cast<int64_t>(F[3]);
	f4 = static_cast<int64_t>(F[4]);
	f5 = static_cast<int64_t>(F[5]);
	f6 = static_cast<int64_t>(F[6]);
	f7 = static_cast<int64_t>(F[7]);
	f8 = static_cast<int64_t>(F[8]);
	f9 = static_cast<int64_t>(F[9]);

	f0x2 = 2 * f0;
	f1x2 = 2 * f1;
	f2x2 = 2 * f2;
	f3x2 = 2 * f3;
	f4x2 = 2 * f4;
	f5x2 = 2 * f5;
	f6x2 = 2 * f6;
	f7x2 = 2 * f7;
	// 1.959375*2^30
	f5x38 = 38 * f5;
	// 1.959375*2^30
	f6x19 = 19 * f6;
	// 1.959375*2^30
	f7x38 = 38 * f7;
	// 1.959375*2^30
	f8x19 = 19 * f8;
	// 1.959375*2^30
	f9x38 = 38 * f9;

	h0 = (f0 * f0) + (f1x2 * f9x38) + (f2x2 * f8x19) + (f3x2 * f7x38) + (f4x2 * f6x19) + (f5 * f5x38);
	h1 = (f0x2 * f1) + (f2 * f9x38) + (f3x2 * f8x19) + (f4 * f7x38) + (f5x2 * f6x19);
	h2 = (f0x2 * f2) + (f1x2 * f1) + (f3x2 * f9x38) + (f4x2 * f8x19) + (f5x2 * f7x38) + (f6 * f6x19);
	h3 = (f0x2 * f3) + (f1x2 * f2) + (f4 * f9x38) + (f5x2 * f8x19) + (f6 * f7x38);
	h4 = (f0x2 * f4) + (f1x2 * f3x2) + (f2 * f2) + (f5x2 * f9x38) + (f6x2 * f8x19) + (f7 * f7x38);
	h5 = (f0x2 * f5) + (f1x2 * f4) + (f2x2 * f3) + (f6 * f9x38) + (f7x2 * f8x19);
	h6 = (f0x2 * f6) + (f1x2 * f5x2) + (f2x2 * f4) + (f3x2 * f3) + (f7x2 * f9x38) + (f8 * f8x19);
	h7 = (f0x2 * f7) + (f1x2 * f6) + (f2x2 * f5) + (f3x2 * f4) + (f8 * f9x38);
	h8 = (f0x2 * f8) + (f1x2 * f7x2) + (f2x2 * f6) + (f3x2 * f5x2) + (f4 * f4) + (f9 * f9x38);
	h9 = (f0x2 * f9) + (f1x2 * f8) + (f2x2 * f7) + (f3x2 * f6) + (f4x2 * f5);

	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;

	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);

	carry = (h1 + (1LL << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1ULL << 25);
	carry = (h5 + (1LL << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1ULL << 25);

	carry = (h2 + (1LL << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1ULL << 26);
	carry = (h6 + (1LL << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1ULL << 26);

	carry = (h3 + (1LL << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1ULL << 25);
	carry = (h7 + (1LL << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1ULL << 25);

	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);
	carry = (h8 + (1LL << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1ULL << 26);

	carry = (h9 + (1LL << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1ULL << 25);

	carry = (h0 + (1LL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);

	H[0] = static_cast<int32_t>(h0);
	H[1] = static_cast<int32_t>(h1);
	H[2] = static_cast<int32_t>(h2);
	H[3] = static_cast<int32_t>(h3);
	H[4] = static_cast<int32_t>(h4);
	H[5] = static_cast<int32_t>(h5);
	H[6] = static_cast<int32_t>(h6);
	H[7] = static_cast<int32_t>(h7);
	H[8] = static_cast<int32_t>(h8);
	H[9] = static_cast<int32_t>(h9);
}

void EC25519::Fe25519FromBytes(fe25519 &H, const std::vector<uint8_t> &S)
{
	int64_t carry;
	int64_t h0;
	int64_t h1;
	int64_t h2;
	int64_t h3;
	int64_t h4;
	int64_t h5;
	int64_t h6;
	int64_t h7;
	int64_t h8;
	int64_t h9;

	h0 = EcdsaBaseLoad4(S, 0);
	h1 = EcdsaBaseLoad3(S, 4) << 6;
	h2 = EcdsaBaseLoad3(S, 7) << 5;
	h3 = EcdsaBaseLoad3(S, 10) << 3;
	h4 = EcdsaBaseLoad3(S, 13) << 2;
	h5 = EcdsaBaseLoad4(S, 16);
	h6 = EcdsaBaseLoad3(S, 20) << 7;
	h7 = EcdsaBaseLoad3(S, 23) << 5;
	h8 = EcdsaBaseLoad3(S, 26) << 4;
	h9 = (EcdsaBaseLoad3(S, 29) & 8388607) << 2;

	carry = (h9 + (1LL << 24)) >> 25;
	h0 += carry * 19;
	h9 -= carry * (1ULL << 25);
	carry = (h1 + (1LL << 24)) >> 25;
	h2 += carry;
	h1 -= carry * (1ULL << 25);
	carry = (h3 + (1LL << 24)) >> 25;
	h4 += carry;
	h3 -= carry * (1ULL << 25);
	carry = (h5 + (1LL << 24)) >> 25;
	h6 += carry;
	h5 -= carry * (1ULL << 25);
	carry = (h7 + (1LL << 24)) >> 25;
	h8 += carry;
	h7 -= carry * (1ULL << 25);

	carry = (h0 + (1ULL << 25)) >> 26;
	h1 += carry;
	h0 -= carry * (1ULL << 26);
	carry = (h2 + (1LL << 25)) >> 26;
	h3 += carry;
	h2 -= carry * (1ULL << 26);
	carry = (h4 + (1LL << 25)) >> 26;
	h5 += carry;
	h4 -= carry * (1ULL << 26);
	carry = (h6 + (1LL << 25)) >> 26;
	h7 += carry;
	h6 -= carry * (1ULL << 26);
	carry = (h8 + (1LL << 25)) >> 26;
	h9 += carry;
	h8 -= carry * (1ULL << 26);

	H[0] = static_cast<int32_t>(h0);
	H[1] = static_cast<int32_t>(h1);
	H[2] = static_cast<int32_t>(h2);
	H[3] = static_cast<int32_t>(h3);
	H[4] = static_cast<int32_t>(h4);
	H[5] = static_cast<int32_t>(h5);
	H[6] = static_cast<int32_t>(h6);
	H[7] = static_cast<int32_t>(h7);
	H[8] = static_cast<int32_t>(h8);
	H[9] = static_cast<int32_t>(h9);
}

void EC25519::Fe25519Reduce(fe25519 &H, const fe25519 &F)
{
	// Preconditions:
	// |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	// Write p=2^255-19; q=floor(h/p).
	// Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
	// Proof:
	// Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
	// Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
	// Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
	// Then 0<y<1.
	// Write r=h-pq.
	// Have 0<=r<=p-1=2^255-20.
	// Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
	// Write x=r+19(2^-255)r+y.
	// Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
	// Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
	// so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
	int32_t carry;
	int32_t h0;
	int32_t h1;
	int32_t h2;
	int32_t h3;
	int32_t h4;
	int32_t h5;
	int32_t h6;
	int32_t h7;
	int32_t h8;
	int32_t h9;
	int32_t q;

	h0 = F[0];
	h1 = F[1];
	h2 = F[2];
	h3 = F[3];
	h4 = F[4];
	h5 = F[5];
	h6 = F[6];
	h7 = F[7];
	h8 = F[8];
	h9 = F[9];

	q = (19 * h9 + (1UL << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;

	// Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20
	h0 += 19 * q;
	// Goal: Output h-2^255 q, which is between 0 and 2^255-20
	carry = h0 >> 26;
	h1 += carry;
	h0 -= carry * (1UL << 26);
	carry = h1 >> 25;
	h2 += carry;
	h1 -= carry * (1UL << 25);
	carry = h2 >> 26;
	h3 += carry;
	h2 -= carry * (1UL << 26);
	carry = h3 >> 25;
	h4 += carry;
	h3 -= carry * (1UL << 25);
	carry = h4 >> 26;
	h5 += carry;
	h4 -= carry * (1UL << 26);
	carry = h5 >> 25;
	h6 += carry;
	h5 -= carry * (1UL << 25);
	carry = h6 >> 26;
	h7 += carry;
	h6 -= carry * (1UL << 26);
	carry = h7 >> 25;
	h8 += carry;
	h7 -= carry * (1UL << 25);
	carry = h8 >> 26;
	h9 += carry;
	h8 -= carry * (1UL << 26);
	carry = h9 >> 25;
	h9 -= carry * (1UL << 25);

	H[0] = h0;
	H[1] = h1;
	H[2] = h2;
	H[3] = h3;
	H[4] = h4;
	H[5] = h5;
	H[6] = h6;
	H[7] = h7;
	H[8] = h8;
	H[9] = h9;
}

void EC25519::Fe25519ToBytes(std::vector<uint8_t> &S, const fe25519 &H)
{
	fe25519 t = { 0 };

	Fe25519Reduce(t, H);

	S[0] = static_cast<uint8_t>(t[0]);
	S[1] = static_cast<uint8_t>(t[0] >> 8);
	S[2] = static_cast<uint8_t>(t[0] >> 16);
	S[3] = static_cast<uint8_t>((t[0] >> 24) | (t[1] * (1UL << 2)));
	S[4] = static_cast<uint8_t>(t[1] >> 6);
	S[5] = static_cast<uint8_t>(t[1] >> 14);
	S[6] = static_cast<uint8_t>((t[1] >> 22) | (t[2] * (1UL << 3)));
	S[7] = static_cast<uint8_t>(t[2] >> 5);
	S[8] = static_cast<uint8_t>(t[2] >> 13);
	S[9] = static_cast<uint8_t>((t[2] >> 21) | (t[3] * (1UL << 5)));
	S[10] = static_cast<uint8_t>(t[3] >> 3);
	S[11] = static_cast<uint8_t>(t[3] >> 11);
	S[12] = static_cast<uint8_t>((t[3] >> 19) | (t[4] * (1UL << 6)));
	S[13] = static_cast<uint8_t>(t[4] >> 2);
	S[14] = static_cast<uint8_t>(t[4] >> 10);
	S[15] = static_cast<uint8_t>(t[4] >> 18);
	S[16] = static_cast<uint8_t>(t[5]);
	S[17] = static_cast<uint8_t>(t[5] >> 8);
	S[18] = static_cast<uint8_t>(t[5] >> 16);
	S[19] = static_cast<uint8_t>((t[5] >> 24) | (t[6] * (1UL << 1)));
	S[20] = static_cast<uint8_t>(t[6] >> 7);
	S[21] = static_cast<uint8_t>(t[6] >> 15);
	S[22] = static_cast<uint8_t>((t[6] >> 23) | (t[7] * (1UL << 3)));
	S[23] = static_cast<uint8_t>(t[7] >> 5);
	S[24] = static_cast<uint8_t>(t[7] >> 13);
	S[25] = static_cast<uint8_t>((t[7] >> 21) | (t[8] * (1UL << 4)));
	S[26] = static_cast<uint8_t>(t[8] >> 4);
	S[27] = static_cast<uint8_t>(t[8] >> 12);
	S[28] = static_cast<uint8_t>((t[8] >> 20) | (t[9] * (1UL << 6)));
	S[29] = static_cast<uint8_t>(t[9] >> 2);
	S[30] = static_cast<uint8_t>(t[9] >> 10);
	S[31] = static_cast<uint8_t>(t[9] >> 18);
}

#endif

void EC25519::Fe25519Pow22523(fe25519 &Output, const fe25519 &Z)
{
	fe25519 t0 = { 0 };
	fe25519 t1 = { 0 };
	fe25519 t2 = { 0 };
	size_t i;

	Fe25519Sq(t0, Z);
	Fe25519Sq(t1, t0);
	Fe25519Sq(t1, t1);
	Fe25519Mul(t1, Z, t1);
	Fe25519Mul(t0, t0, t1);
	Fe25519Sq(t0, t0);
	Fe25519Mul(t0, t1, t0);
	Fe25519Sq(t1, t0);

	for (i = 1; i < 5; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(t0, t1, t0);
	Fe25519Sq(t1, t0);

	for (i = 1; i < 10; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(t1, t1, t0);
	Fe25519Sq(t2, t1);

	for (i = 1; i < 20; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t1, t2, t1);

	for (i = 1; i < 11; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(t0, t1, t0);
	Fe25519Sq(t1, t0);

	for (i = 1; i < 50; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(t1, t1, t0);
	Fe25519Sq(t2, t1);

	for (i = 1; i < 100; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t1, t2, t1);

	for (i = 1; i < 51; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(t0, t1, t0);
	Fe25519Sq(t0, t0);
	Fe25519Sq(t0, t0);
	Fe25519Mul(Output, t0, Z);
}

void EC25519::Fe25519Invert(fe25519 &Output, const fe25519 &Z)
{
	// Inversion - returns 0 if z=0
	fe25519 t0 = { 0 };
	fe25519 t1 = { 0 };
	fe25519 t2 = { 0 };
	fe25519 t3 = { 0 };
	size_t i;

	Fe25519Sq(t0, Z);
	Fe25519Sq(t1, t0);
	Fe25519Sq(t1, t1);
	Fe25519Mul(t1, Z, t1);
	Fe25519Mul(t0, t0, t1);
	Fe25519Sq(t2, t0);
	Fe25519Mul(t1, t1, t2);
	Fe25519Sq(t2, t1);

	for (i = 1; i < 5; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t1, t2, t1);
	Fe25519Sq(t2, t1);

	for (i = 1; i < 10; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t2, t2, t1);
	Fe25519Sq(t3, t2);

	for (i = 1; i < 20; ++i)
	{
		Fe25519Sq(t3, t3);
	}

	Fe25519Mul(t2, t3, t2);

	for (i = 1; i < 11; ++i)
	{
		Fe25519Sq(t2, t2);
	}
	Fe25519Mul(t1, t2, t1);
	Fe25519Sq(t2, t1);

	for (i = 1; i < 50; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t2, t2, t1);
	Fe25519Sq(t3, t2);

	for (i = 1; i < 100; ++i)
	{
		Fe25519Sq(t3, t3);
	}

	Fe25519Mul(t2, t3, t2);

	for (i = 1; i < 51; ++i)
	{
		Fe25519Sq(t2, t2);
	}

	Fe25519Mul(t1, t2, t1);

	for (i = 1; i < 6; ++i)
	{
		Fe25519Sq(t1, t1);
	}

	Fe25519Mul(Output, t1, t0);
}

void EC25519::Fe25519AddPrecomp(ge25519p1p1 &R, const ge25519p3 &P, const ge25519precomp &Q)
{
	fe25519 t0 = { 0 };

	Fe25519Add(R.x, P.y, P.x);
	Fe25519Sub(R.y, P.y, P.x);
	Fe25519Mul(R.z, R.x, Q.yplusx);
	Fe25519Mul(R.y, R.y, Q.yminusx);
	Fe25519Mul(R.t, Q.xy2d, P.t);
	Fe25519Add(t0, P.z, P.z);
	Fe25519Sub(R.x, R.z, R.y);
	Fe25519Add(R.y, R.z, R.y);
	Fe25519Add(R.z, t0, R.t);
	Fe25519Sub(R.t, t0, R.t);
}

void EC25519::Ge25519P3Zero(ge25519p3 &H)
{
	Fe25519Zero(H.x);
	Fe25519One(H.y);
	Fe25519One(H.z);
	Fe25519Zero(H.t);
}

void EC25519::Ge25519PrecompZero(ge25519precomp &H)
{
	Fe25519One(H.yplusx);
	Fe25519One(H.yminusx);
	Fe25519Zero(H.xy2d);
}

void EC25519::Ge25519cMov(ge25519precomp &T, const ge25519precomp &U, uint8_t B)
{
	Fe25519cMov(T.yplusx, U.yplusx, B);
	Fe25519cMov(T.yminusx, U.yminusx, B);
	Fe25519cMov(T.xy2d, U.xy2d, B);
}

uint8_t EC25519::Ge25519Equal(int8_t B, int8_t C)
{
	uint8_t ub;
	uint8_t uc;
	uint8_t x;
	uint32_t y;

	ub = B;
	uc = C;
	x = ub ^ uc;
	y = static_cast<uint32_t>(x);
	y -= 1;
	y >>= 31;

	return y;
}

void EC25519::Ge25519cMov8(ge25519precomp &T, const std::vector<ge25519precomp> &PreComp, const int8_t B)
{
	ge25519precomp minust = { 0 };
	const uint8_t BNEG = EcdsaBaseNegative(B);
	const uint8_t BABS = B - (((~BNEG + 1) & B) * (1 << 1));

	Ge25519PrecompZero(T);

	Ge25519cMov(T, PreComp[0], Ge25519Equal(BABS, 1));
	Ge25519cMov(T, PreComp[1], Ge25519Equal(BABS, 2));
	Ge25519cMov(T, PreComp[2], Ge25519Equal(BABS, 3));
	Ge25519cMov(T, PreComp[3], Ge25519Equal(BABS, 4));
	Ge25519cMov(T, PreComp[4], Ge25519Equal(BABS, 5));
	Ge25519cMov(T, PreComp[5], Ge25519Equal(BABS, 6));
	Ge25519cMov(T, PreComp[6], Ge25519Equal(BABS, 7));
	Ge25519cMov(T, PreComp[7], Ge25519Equal(BABS, 8));

	Fe25519Copy(minust.yplusx, T.yminusx);
	Fe25519Copy(minust.yminusx, T.yplusx);
	Fe25519Neg(minust.xy2d, T.xy2d);
	Ge25519cMov(T, minust, BNEG);
}

void EC25519::Ge25519cMov8Base(ge25519precomp &T, const int32_t Position, const int8_t B)
{
	// base[i][j] = (j+1)*256^i*B
	static const std::vector<std::vector<ge25519precomp>> base =
	{
#if defined(CEX_SYSTEM_NATIVE_UINT128)
		{ // 0/31
		  {
			{ 1288382639258501, 245678601348599, 269427782077623, 1462984067271730, 137412439391563 },
			{ 62697248952638, 204681361388450, 631292143396476, 338455783676468, 1213667448819585 },
			{ 301289933810280, 1259582250014073, 1422107436869536, 796239922652654, 1953934009299142 }
		  },
		  {
			{ 1380971894829527, 790832306631236, 2067202295274102, 1995808275510000, 1566530869037010 },
			{ 463307831301544, 432984605774163, 1610641361907204, 750899048855000, 1894842303421586 },
			{ 748439484463711, 1033211726465151, 1396005112841647, 1611506220286469, 1972177495910992 }
		  },
		  {
			{ 1601611775252272, 1720807796594148, 1132070835939856, 1260455018889551, 2147779492816911 },
			{ 316559037616741, 2177824224946892, 1459442586438991, 1461528397712656, 751590696113597 },
			{ 1850748884277385, 1200145853858453, 1068094770532492, 672251375690438, 1586055907191707 }
		  },
		  {
			{ 934282339813791, 1846903124198670, 1172395437954843, 1007037127761661, 1830588347719256 },
			{ 1694390458783935, 1735906047636159, 705069562067493, 648033061693059, 696214010414170 },
			{ 1121406372216585, 192876649532226, 190294192191717, 1994165897297032, 2245000007398739 }
		  },
		  {
			{ 769950342298419, 132954430919746, 844085933195555, 974092374476333, 726076285546016 },
			{ 425251763115706, 608463272472562, 442562545713235, 837766094556764, 374555092627893 },
			{ 1086255230780037, 274979815921559, 1960002765731872, 929474102396301, 1190409889297339 }
		  },
		  {
			{ 1388594989461809, 316767091099457, 394298842192982, 1230079486801005, 1440737038838979 },
			{ 7380825640100, 146210432690483, 304903576448906, 1198869323871120, 997689833219095 },
			{ 1181317918772081, 114573476638901, 262805072233344, 265712217171332, 294181933805782 }
		  },
		  {
			{ 665000864555967, 2065379846933859, 370231110385876, 350988370788628, 1233371373142985 },
			{ 2019367628972465, 676711900706637, 110710997811333, 1108646842542025, 517791959672113 },
			{ 965130719900578, 247011430587952, 526356006571389, 91986625355052, 2157223321444601 }
		  },
		  {
			{ 2068619540119183, 1966274918058806, 957728544705549, 729906502578991, 159834893065166 },
			{ 2073601412052185, 31021124762708, 264500969797082, 248034690651703, 1030252227928288 },
			{ 551790716293402, 1989538725166328, 801169423371717, 2052451893578887, 678432056995012 }
		  }
		},
		{ // 1/31 
		  {
			{ 1368953770187805, 790347636712921, 437508475667162, 2142576377050580, 1932081720066286 },
			{ 953638594433374, 1092333936795051, 1419774766716690, 805677984380077, 859228993502513 },
			{ 1200766035879111, 20142053207432, 1465634435977050, 1645256912097844, 295121984874596 }
		  },
		  {
			{ 1735718747031557, 1248237894295956, 1204753118328107, 976066523550493, 65943769534592 },
			{ 1060098822528990, 1586825862073490, 212301317240126, 1975302711403555, 666724059764335 },
			{ 1091990273418756, 1572899409348578, 80968014455247, 306009358661350, 1520450739132526 }
		  },
		  {
			{ 1480517209436112, 1511153322193952, 1244343858991172, 304788150493241, 369136856496443 },
			{ 2151330273626164, 762045184746182, 1688074332551515, 823046109005759, 907602769079491 },
			{ 2047386910586836, 168470092900250, 1552838872594810, 340951180073789, 360819374702533 }
		  },
		  {
			{ 1982622644432056, 2014393600336956, 128909208804214, 1617792623929191, 105294281913815 },
			{ 980234343912898, 1712256739246056, 588935272190264, 204298813091998, 841798321043288 },
			{ 197561292938973, 454817274782871, 1963754960082318, 2113372252160468, 971377527342673 }
		  },
		  {
			{ 164699448829328, 3127451757672, 1199504971548753, 1766155447043652, 1899238924683527 },
			{ 732262946680281, 1674412764227063, 2182456405662809, 1350894754474250, 558458873295247 },
			{ 2103305098582922, 1960809151316468, 715134605001343, 1454892949167181, 40827143824949 }
		  },
		  {
			{ 1239289043050212, 1744654158124578, 758702410031698, 1796762995074688, 1603056663766 },
			{ 2232056027107988, 987343914584615, 2115594492994461, 1819598072792159, 1119305654014850 },
			{ 320153677847348, 939613871605645, 641883205761567, 1930009789398224, 329165806634126 }
		  },
		  {
			{ 980930490474130, 1242488692177893, 1251446316964684, 1086618677993530, 1961430968465772 },
			{ 276821765317453, 1536835591188030, 1305212741412361, 61473904210175, 2051377036983058 },
			{ 833449923882501, 1750270368490475, 1123347002068295, 185477424765687, 278090826653186 }
		  },
		  {
			{ 794524995833413, 1849907304548286, 53348672473145, 1272368559505217, 1147304168324779 },
			{ 1504846112759364, 1203096289004681, 562139421471418, 274333017451844, 1284344053775441 },
			{ 483048732424432, 2116063063343382, 30120189902313, 292451576741007, 1156379271702225 }
		  }
		},
		{ // 2/31
		  {
			{ 928372153029038, 2147692869914564, 1455665844462196, 1986737809425946, 185207050258089 },
			{ 137732961814206, 706670923917341, 1387038086865771, 1965643813686352, 1384777115696347 },
			{ 481144981981577, 2053319313589856, 2065402289827512, 617954271490316, 1106602634668125 }
		  },
		  {
			{ 696298019648792, 893299659040895, 1148636718636009, 26734077349617, 2203955659340681 },
			{ 657390353372855, 998499966885562, 991893336905797, 810470207106761, 343139804608786 },
			{ 791736669492960, 934767652997115, 824656780392914, 1759463253018643, 361530362383518 }
		  },
		  {
			{ 2022541353055597, 2094700262587466, 1551008075025686, 242785517418164, 695985404963562 },
			{ 1287487199965223, 2215311941380308, 1552928390931986, 1664859529680196, 1125004975265243 },
			{ 677434665154918, 989582503122485, 1817429540898386, 1052904935475344, 1143826298169798 }
		  },
		  {
			{ 367266328308408, 318431188922404, 695629353755355, 634085657580832, 24581612564426 },
			{ 773360688841258, 1815381330538070, 363773437667376, 539629987070205, 783280434248437 },
			{ 180820816194166, 168937968377394, 748416242794470, 1227281252254508, 1567587861004268 }
		  },
		  {
			{ 478775558583645, 2062896624554807, 699391259285399, 358099408427873, 1277310261461761 },
			{ 1984740906540026, 1079164179400229, 1056021349262661, 1659958556483663, 1088529069025527 },
			{ 580736401511151, 1842931091388998, 1177201471228238, 2075460256527244, 1301133425678027 }
		  },
		  {
			{ 1515728832059182, 1575261009617579, 1510246567196186, 191078022609704, 116661716289141 },
			{ 1295295738269652, 1714742313707026, 545583042462581, 2034411676262552, 1513248090013606 },
			{ 230710545179830, 30821514358353, 760704303452229, 390668103790604, 573437871383156 }
		  },
		  {
			{ 1169380107545646, 263167233745614, 2022901299054448, 819900753251120, 2023898464874585 },
			{ 2102254323485823, 1570832666216754, 34696906544624, 1993213739807337, 70638552271463 },
			{ 894132856735058, 548675863558441, 845349339503395, 1942269668326667, 1615682209874691 }
		  },
		  {
			{ 1287670217537834, 1222355136884920, 1846481788678694, 1150426571265110, 1613523400722047 },
			{ 793388516527298, 1315457083650035, 1972286999342417, 1901825953052455, 338269477222410 },
			{ 550201530671806, 778605267108140, 2063911101902983, 115500557286349, 2041641272971022 }
		  }
		},
		{ // 3/31
		  {
			{ 717255318455100, 519313764361315, 2080406977303708, 541981206705521, 774328150311600 },
			{ 261715221532238, 1795354330069993, 1496878026850283, 499739720521052, 389031152673770 },
			{ 1997217696294013, 1717306351628065, 1684313917746180, 1644426076011410, 1857378133465451 }
		  },
		  {
			{ 1475434724792648, 76931896285979, 1116729029771667, 2002544139318042, 725547833803938 },
			{ 2022306639183567, 726296063571875, 315345054448644, 1058733329149221, 1448201136060677 },
			{ 1710065158525665, 1895094923036397, 123988286168546, 1145519900776355, 1607510767693874 }
		  },
		  {
			{ 561605375422540, 1071733543815037, 131496498800990, 1946868434569999, 828138133964203 },
			{ 1548495173745801, 442310529226540, 998072547000384, 553054358385281, 644824326376171 },
			{ 1445526537029440, 2225519789662536, 914628859347385, 1064754194555068, 1660295614401091 }
		  },
		  {
			{ 1199690223111956, 24028135822341, 66638289244341, 57626156285975, 565093967979607 },
			{ 876926774220824, 554618976488214, 1012056309841565, 839961821554611, 1414499340307677 },
			{ 703047626104145, 1266841406201770, 165556500219173, 486991595001879, 1011325891650656 }
		  },
		  {
			{ 1622861044480487, 1156394801573634, 1869132565415504, 327103985777730, 2095342781472284 },
			{ 334886927423922, 489511099221528, 129160865966726, 1720809113143481, 619700195649254 },
			{ 1646545795166119, 1758370782583567, 714746174550637, 1472693650165135, 898994790308209 }
		  },
		  {
			{ 333403773039279, 295772542452938, 1693106465353610, 912330357530760, 471235657950362 },
			{ 1811196219982022, 1068969825533602, 289602974833439, 1988956043611592, 863562343398367 },
			{ 906282429780072, 2108672665779781, 432396390473936, 150625823801893, 1708930497638539 }
		  },
		  {
			{ 925664675702328, 21416848568684, 1831436641861340, 601157008940113, 371818055044496 },
			{ 1479786007267725, 1738881859066675, 68646196476567, 2146507056100328, 1247662817535471 },
			{ 52035296774456, 939969390708103, 312023458773250, 59873523517659, 1231345905848899 }
		  },
		  {
			{ 643355106415761, 290186807495774, 2013561737429023, 319648069511546, 393736678496162 },
			{ 129358342392716, 1932811617704777, 1176749390799681, 398040349861790, 1170779668090425 },
			{ 2051980782668029, 121859921510665, 2048329875753063, 1235229850149665, 519062146124755 }
		  }
		},
		{ // 4/31
		  {
			{ 1608170971973096, 415809060360428, 1350468408164766, 2038620059057678, 1026904485989112 },
			{ 1837656083115103, 1510134048812070, 906263674192061, 1821064197805734, 565375124676301 },
			{ 578027192365650, 2034800251375322, 2128954087207123, 478816193810521, 2196171989962750 }
		  },
		  {
			{ 1633188840273139, 852787172373708, 1548762607215796, 1266275218902681, 1107218203325133 },
			{ 462189358480054, 1784816734159228, 1611334301651368, 1303938263943540, 707589560319424 },
			{ 1038829280972848, 38176604650029, 753193246598573, 1136076426528122, 595709990562434 }
		  },
		  {
			{ 1408451820859834, 2194984964010833, 2198361797561729, 1061962440055713, 1645147963442934 },
			{ 4701053362120, 1647641066302348, 1047553002242085, 1923635013395977, 206970314902065 },
			{ 1750479161778571, 1362553355169293, 1891721260220598, 966109370862782, 1024913988299801 }
		  },
		  {
			{ 212699049131723, 1117950018299775, 1873945661751056, 1403802921984058, 130896082652698 },
			{ 636808533673210, 1262201711667560, 390951380330599, 1663420692697294, 561951321757406 },
			{ 520731594438141, 1446301499955692, 273753264629267, 1565101517999256, 1019411827004672 }
		  },
		  {
			{ 926527492029409, 1191853477411379, 734233225181171, 184038887541270, 1790426146325343 },
			{ 1464651961852572, 1483737295721717, 1519450561335517, 1161429831763785, 405914998179977 },
			{ 996126634382301, 796204125879525, 127517800546509, 344155944689303, 615279846169038 }
		  },
		  {
			{ 738724080975276, 2188666632415296, 1961313708559162, 1506545807547587, 1151301638969740 },
			{ 622917337413835, 1218989177089035, 1284857712846592, 970502061709359, 351025208117090 },
			{ 2067814584765580, 1677855129927492, 2086109782475197, 235286517313238, 1416314046739645 }
		  },
		  {
			{ 586844262630358, 307444381952195, 458399356043426, 602068024507062, 1028548203415243 },
			{ 678489922928203, 2016657584724032, 90977383049628, 1026831907234582, 615271492942522 },
			{ 301225714012278, 1094837270268560, 1202288391010439, 644352775178361, 1647055902137983 }
		  },
		  {
			{ 1210746697896478, 1416608304244708, 686487477217856, 1245131191434135, 1051238336855737 },
			{ 1135604073198207, 1683322080485474, 769147804376683, 2086688130589414, 900445683120379 },
			{ 1971518477615628, 401909519527336, 448627091057375, 1409486868273821, 1214789035034363 }
		  }
		},
		{ // 5/31
		  {
			{ 1364039144731711, 1897497433586190, 2203097701135459, 145461396811251, 1349844460790699 },
			{ 1045230323257973, 818206601145807, 630513189076103, 1672046528998132, 807204017562437 },
			{ 439961968385997, 386362664488986, 1382706320807688, 309894000125359, 2207801346498567 }
		  },
		  {
			{ 1229004686397588, 920643968530863, 123975893911178, 681423993215777, 1400559197080973 },
			{ 2003766096898049, 170074059235165, 1141124258967971, 1485419893480973, 1573762821028725 },
			{ 729905708611432, 1270323270673202, 123353058984288, 426460209632942, 2195574535456672 }
		  },
		  {
			{ 1271140255321235, 2044363183174497, 52125387634689, 1445120246694705, 942541986339084 },
			{ 1761608437466135, 583360847526804, 1586706389685493, 2157056599579261, 1170692369685772 },
			{ 871476219910823, 1878769545097794, 2241832391238412, 548957640601001, 690047440233174 }
		  },
		  {
			{ 297194732135507, 1366347803776820, 1301185512245601, 561849853336294, 1533554921345731 },
			{ 999628998628371, 1132836708493400, 2084741674517453, 469343353015612, 678782988708035 },
			{ 2189427607417022, 699801937082607, 412764402319267, 1478091893643349, 2244675696854460 }
		  },
		  {
			{ 1712292055966563, 204413590624874, 1405738637332841, 408981300829763, 861082219276721 },
			{ 508561155940631, 966928475686665, 2236717801150132, 424543858577297, 2089272956986143 },
			{ 221245220129925, 1156020201681217, 491145634799213, 542422431960839, 828100817819207 }
		  },
		  {
			{ 153756971240384, 1299874139923977, 393099165260502, 1058234455773022, 996989038681183 },
			{ 559086812798481, 573177704212711, 1629737083816402, 1399819713462595, 1646954378266038 },
			{ 1887963056288059, 228507035730124, 1468368348640282, 930557653420194, 613513962454686 }
		  },
		  {
			{ 1224529808187553, 1577022856702685, 2206946542980843, 625883007765001, 279930793512158 },
			{ 1076287717051609, 1114455570543035, 187297059715481, 250446884292121, 1885187512550540 },
			{ 902497362940219, 76749815795675, 1657927525633846, 1420238379745202, 1340321636548352 }
		  },
		  {
			{ 1129576631190784, 1281994010027327, 996844254743018, 257876363489249, 1150850742055018 },
			{ 628740660038789, 1943038498527841, 467786347793886, 1093341428303375, 235413859513003 },
			{ 237425418909360, 469614029179605, 1512389769174935, 1241726368345357, 441602891065214 }
		  }
		},
		{ // 6/31
		  {
			{ 1736417953058555, 726531315520508, 1833335034432527, 1629442561574747, 624418919286085 },
			{ 1960754663920689, 497040957888962, 1909832851283095, 1271432136996826, 2219780368020940 },
			{ 1537037379417136, 1358865369268262, 2130838645654099, 828733687040705, 1999987652890901 }
		  },
		  {
			{ 629042105241814, 1098854999137608, 887281544569320, 1423102019874777, 7911258951561 },
			{ 1811562332665373, 1501882019007673, 2213763501088999, 359573079719636, 36370565049116 },
			{ 218907117361280, 1209298913016966, 1944312619096112, 1130690631451061, 1342327389191701 }
		  },
		  {
			{ 1369976867854704, 1396479602419169, 1765656654398856, 2203659200586299, 998327836117241 },
			{ 2230701885562825, 1348173180338974, 2172856128624598, 1426538746123771, 444193481326151 },
			{ 784210426627951, 918204562375674, 1284546780452985, 1324534636134684, 1872449409642708 }
		  },
		  {
			{ 319638829540294, 596282656808406, 2037902696412608, 1557219121643918, 341938082688094 },
			{ 1901860206695915, 2004489122065736, 1625847061568236, 973529743399879, 2075287685312905 },
			{ 1371853944110545, 1042332820512553, 1949855697918254, 1791195775521505, 37487364849293 }
		  },
		  {
			{ 687200189577855, 1082536651125675, 644224940871546, 340923196057951, 343581346747396 },
			{ 2082717129583892, 27829425539422, 145655066671970, 1690527209845512, 1865260509673478 },
			{ 1059729620568824, 2163709103470266, 1440302280256872, 1769143160546397, 869830310425069 }
		  },
		  {
			{ 1609516219779025, 777277757338817, 2101121130363987, 550762194946473, 1905542338659364 },
			{ 2024821921041576, 426948675450149, 595133284085473, 471860860885970, 600321679413000 },
			{ 598474602406721, 1468128276358244, 1191923149557635, 1501376424093216, 1281662691293476 }
		  },
		  {
			{ 1721138489890707, 1264336102277790, 433064545421287, 1359988423149466, 1561871293409447 },
			{ 719520245587143, 393380711632345, 132350400863381, 1543271270810729, 1819543295798660 },
			{ 396397949784152, 1811354474471839, 1362679985304303, 2117033964846756, 498041172552279 }
		  },
		  {
			{ 1812471844975748, 1856491995543149, 126579494584102, 1036244859282620, 1975108050082550 },
			{ 650623932407995, 1137551288410575, 2125223403615539, 1725658013221271, 2134892965117796 },
			{ 522584000310195, 1241762481390450, 1743702789495384, 2227404127826575, 1686746002148897 }
		  }
		},
		{ // 7/31
		  {
			{ 427904865186312, 1703211129693455, 1585368107547509, 1436984488744336, 761188534613978 },
			{ 318101947455002, 248138407995851, 1481904195303927, 309278454311197, 1258516760217879 },
			{ 1275068538599310, 513726919533379, 349926553492294, 688428871968420, 1702400196000666 }
		  },
		  {
			{ 1061864036265233, 961611260325381, 321859632700838, 1045600629959517, 1985130202504038 },
			{ 1558816436882417, 1962896332636523, 1337709822062152, 1501413830776938, 294436165831932 },
			{ 818359826554971, 1862173000996177, 626821592884859, 573655738872376, 1749691246745455 }
		  },
		  {
			{ 1988022651432119, 1082111498586040, 1834020786104821, 1454826876423687, 692929915223122 },
			{ 2146513703733331, 584788900394667, 464965657279958, 2183973639356127, 238371159456790 },
			{ 1129007025494441, 2197883144413266, 265142755578169, 971864464758890, 1983715884903702 }
		  },
		  {
			{ 1291366624493075, 381456718189114, 1711482489312444, 1815233647702022, 892279782992467 },
			{ 444548969917454, 1452286453853356, 2113731441506810, 645188273895859, 810317625309512 },
			{ 2242724082797924, 1373354730327868, 1006520110883049, 2147330369940688, 1151816104883620 }
		  },
		  {
			{ 1745720200383796, 1911723143175317, 2056329390702074, 355227174309849, 879232794371100 },
			{ 163723479936298, 115424889803150, 1156016391581227, 1894942220753364, 1970549419986329 },
			{ 681981452362484, 267208874112496, 1374683991933094, 638600984916117, 646178654558546 }
		  },
		  {
			{ 13378654854251, 106237307029567, 1944412051589651, 1841976767925457, 230702819835573 },
			{ 260683893467075, 854060306077237, 913639551980112, 4704576840123, 280254810808712 },
			{ 715374893080287, 1173334812210491, 1806524662079626, 1894596008000979, 398905715033393 }
		  },
		  {
			{ 500026409727661, 1596431288195371, 1420380351989370, 985211561521489, 392444930785633 },
			{ 2096421546958141, 1922523000950363, 789831022876840, 427295144688779, 320923973161730 },
			{ 1927770723575450, 1485792977512719, 1850996108474547, 551696031508956, 2126047405475647 }
		  },
		  {
			{ 2112099158080148, 742570803909715, 6484558077432, 1951119898618916, 93090382703416 },
			{ 383905201636970, 859946997631870, 855623867637644, 1017125780577795, 794250831877809 },
			{ 77571826285752, 999304298101753, 487841111777762, 1038031143212339, 339066367948762 }
		  }
		},
		{ // 8/31
		  {
			{ 674994775520533, 266035846330789, 826951213393478, 1405007746162285, 1781791018620876 },
			{ 1001412661522686, 348196197067298, 1666614366723946, 888424995032760, 580747687801357 },
			{ 1939560076207777, 1409892634407635, 552574736069277, 383854338280405, 190706709864139 }
		  },
		  {
			{ 2177087163428741, 1439255351721944, 1208070840382793, 2230616362004769, 1396886392021913 },
			{ 676962063230039, 1880275537148808, 2046721011602706, 888463247083003, 1318301552024067 },
			{ 1466980508178206, 617045217998949, 652303580573628, 757303753529064, 207583137376902 }
		  },
		  {
			{ 1511056752906902, 105403126891277, 493434892772846, 1091943425335976, 1802717338077427 },
			{ 1853982405405128, 1878664056251147, 1528011020803992, 1019626468153565, 1128438412189035 },
			{ 1963939888391106, 293456433791664, 697897559513649, 985882796904380, 796244541237972 }
		  },
		  {
			{ 416770998629779, 389655552427054, 1314476859406756, 1749382513022778, 1161905598739491 },
			{ 1428358296490651, 1027115282420478, 304840698058337, 441410174026628, 1819358356278573 },
			{ 204943430200135, 1554861433819175, 216426658514651, 264149070665950, 2047097371738319 }
		  },
		  {
			{ 1934415182909034, 1393285083565062, 516409331772960, 1157690734993892, 121039666594268 },
			{ 662035583584445, 286736105093098, 1131773000510616, 818494214211439, 472943792054479 },
			{ 665784778135882, 1893179629898606, 808313193813106, 276797254706413, 1563426179676396 }
		  },
		  {
			{ 945205108984232, 526277562959295, 1324180513733566, 1666970227868664, 153547609289173 },
			{ 2031433403516252, 203996615228162, 170487168837083, 981513604791390, 843573964916831 },
			{ 1476570093962618, 838514669399805, 1857930577281364, 2017007352225784, 317085545220047 }
		  },
		  {
			{ 1461557121912842, 1600674043318359, 2157134900399597, 1670641601940616, 127765583803283 },
			{ 1293543509393474, 2143624609202546, 1058361566797508, 214097127393994, 946888515472729 },
			{ 357067959932916, 1290876214345711, 521245575443703, 1494975468601005, 800942377643885 }
		  },
		  {
			{ 566116659100033, 820247422481740, 994464017954148, 327157611686365, 92591318111744 },
			{ 617256647603209, 1652107761099439, 1857213046645471, 1085597175214970, 817432759830522 },
			{ 771808161440705, 1323510426395069, 680497615846440, 851580615547985, 1320806384849017 }
		  }
		},
		{ // 9/31
		  {
			{ 1219260086131915, 647169006596815, 79601124759706, 2161724213426748, 404861897060198 },
			{ 1327968293887866, 1335500852943256, 1401587164534264, 558137311952440, 1551360549268902 },
			{ 417621685193956, 1429953819744454, 396157358457099, 1940470778873255, 214000046234152 }
		  },
		  {
			{ 1268047918491973, 2172375426948536, 1533916099229249, 1761293575457130, 1590622667026765 },
			{ 1627072914981959, 2211603081280073, 1912369601616504, 1191770436221309, 2187309757525860 },
			{ 1149147819689533, 378692712667677, 828475842424202, 2218619146419342, 70688125792186 }
		  },
		  {
			{ 1299739417079761, 1438616663452759, 1536729078504412, 2053896748919838, 1008421032591246 },
			{ 2040723824657366, 399555637875075, 632543375452995, 872649937008051, 1235394727030233 },
			{ 2211311599327900, 2139787259888175, 938706616835350, 12609661139114, 2081897930719789 }
		  },
		  {
			{ 1324994503390450, 336982330582631, 1183998925654177, 1091654665913274, 48727673971319 },
			{ 1845522914617879, 1222198248335542, 150841072760134, 1927029069940982, 1189913404498011 },
			{ 1079559557592645, 2215338383666441, 1903569501302605, 49033973033940, 305703433934152 }
		  },
		  {
			{ 94653405416909, 1386121349852999, 1062130477891762, 36553947479274, 833669648948846 },
			{ 1432015813136298, 440364795295369, 1395647062821501, 1976874522764578, 934452372723352 },
			{ 1296625309219774, 2068273464883862, 1858621048097805, 1492281814208508, 2235868981918946 }
		  },
		  {
			{ 1490330266465570, 1858795661361448, 1436241134969763, 294573218899647, 1208140011028933 },
			{ 1282462923712748, 741885683986255, 2027754642827561, 518989529541027, 1826610009555945 },
			{ 1525827120027511, 723686461809551, 1597702369236987, 244802101764964, 1502833890372311 }
		  },
		  {
			{ 113622036244513, 1233740067745854, 674109952278496, 2114345180342965, 166764512856263 },
			{ 2041668749310338, 2184405322203901, 1633400637611036, 2110682505536899, 2048144390084644 },
			{ 503058759232932, 760293024620937, 2027152777219493, 666858468148475, 1539184379870952 }
		  },
		  {
			{ 1916168475367211, 915626432541343, 883217071712575, 363427871374304, 1976029821251593 },
			{ 678039535434506, 570587290189340, 1605302676614120, 2147762562875701, 1706063797091704 },
			{ 1439489648586438, 2194580753290951, 832380563557396, 561521973970522, 584497280718389 }
		  }
		},
		{ // 10/31
		  {
			{ 187989455492609, 681223515948275, 1933493571072456, 1872921007304880, 488162364135671 },
			{ 1413466089534451, 410844090765630, 1397263346404072, 408227143123410, 1594561803147811 },
			{ 2102170800973153, 719462588665004, 1479649438510153, 1097529543970028, 1302363283777685 }
		  },
		  {
			{ 942065717847195, 1069313679352961, 2007341951411051, 70973416446291, 1419433790163706 },
			{ 1146565545556377, 1661971299445212, 406681704748893, 564452436406089, 1109109865829139 },
			{ 2214421081775077, 1165671861210569, 1890453018796184, 3556249878661, 442116172656317 }
		  },
		  {
			{ 753830546620811, 1666955059895019, 1530775289309243, 1119987029104146, 2164156153857580 },
			{ 615171919212796, 1523849404854568, 854560460547503, 2067097370290715, 1765325848586042 },
			{ 1094538949313667, 1796592198908825, 870221004284388, 2025558921863561, 1699010892802384 }
		  },
		  {
			{ 1951351290725195, 1916457206844795, 198025184438026, 1909076887557595, 1938542290318919 },
			{ 1014323197538413, 869150639940606, 1756009942696599, 1334952557375672, 1544945379082874 },
			{ 764055910920305, 1603590757375439, 146805246592357, 1843313433854297, 954279890114939 }
		  },
		  {
			{ 80113526615750, 764536758732259, 1055139345100233, 469252651759390, 617897512431515 },
			{ 74497112547268, 740094153192149, 1745254631717581, 727713886503130, 1283034364416928 },
			{ 525892105991110, 1723776830270342, 1476444848991936, 573789489857760, 133864092632978 }
		  },
		  {
			{ 542611720192581, 1986812262899321, 1162535242465837, 481498966143464, 544600533583622 },
			{ 64123227344372, 1239927720647794, 1360722983445904, 222610813654661, 62429487187991 },
			{ 1793193323953132, 91096687857833, 70945970938921, 2158587638946380, 1537042406482111 }
		  },
		  {
			{ 1895854577604609, 1394895708949416, 1728548428495944, 1140864900240149, 563645333603061 },
			{ 141358280486863, 91435889572504, 1087208572552643, 1829599652522921, 1193307020643647 },
			{ 1611230858525381, 950720175540785, 499589887488610, 2001656988495019, 88977313255908 }
		  },
		  {
			{ 1189080501479658, 2184348804772597, 1040818725742319, 2018318290311834, 1712060030915354 },
			{ 873966876953756, 1090638350350440, 1708559325189137, 672344594801910, 1320437969700239 },
			{ 1508590048271766, 1131769479776094, 101550868699323, 428297785557897, 561791648661744 }
		  }
		},
		{ // 11/31
		  {
			{ 756417570499462, 237882279232602, 2136263418594016, 1701968045454886, 703713185137472 },
			{ 1781187809325462, 1697624151492346, 1381393690939988, 175194132284669, 1483054666415238 },
			{ 2175517777364616, 708781536456029, 955668231122942, 1967557500069555, 2021208005604118 }
		  },
		  {
			{ 1115135966606887, 224217372950782, 915967306279222, 593866251291540, 561747094208006 },
			{ 1443163092879439, 391875531646162, 2180847134654632, 464538543018753, 1594098196837178 },
			{ 850858855888869, 319436476624586, 327807784938441, 740785849558761, 17128415486016 }
		  },
		  {
			{ 2132756334090067, 536247820155645, 48907151276867, 608473197600695, 1261689545022784 },
			{ 1525176236978354, 974205476721062, 293436255662638, 148269621098039, 137961998433963 },
			{ 1121075518299410, 2071745529082111, 1265567917414828, 1648196578317805, 496232102750820 }
		  },
		  {
			{ 122321229299801, 1022922077493685, 2001275453369484, 2017441881607947, 993205880778002 },
			{ 654925550560074, 1168810995576858, 575655959430926, 905758704861388, 496774564663534 },
			{ 1954109525779738, 2117022646152485, 338102630417180, 1194140505732026, 107881734943492 }
		  },
		  {
			{ 1714785840001267, 2036500018681589, 1876380234251966, 2056717182974196, 1645855254384642 },
			{ 106431476499341, 62482972120563, 1513446655109411, 807258751769522, 538491469114 },
			{ 2002850762893643, 1243624520538135, 1486040410574605, 2184752338181213, 378495998083531 }
		  },
		  {
			{ 922510868424903, 1089502620807680, 402544072617374, 1131446598479839, 1290278588136533 },
			{ 1867998812076769, 715425053580701, 39968586461416, 2173068014586163, 653822651801304 },
			{ 162892278589453, 182585796682149, 75093073137630, 497037941226502, 133871727117371 }
		  },
		  {
			{ 1914596576579670, 1608999621851578, 1987629837704609, 1519655314857977, 1819193753409464 },
			{ 1949315551096831, 1069003344994464, 1939165033499916, 1548227205730856, 1933767655861407 },
			{ 1730519386931635, 1393284965610134, 1597143735726030, 416032382447158, 1429665248828629 }
		  },
		  {
			{ 360275475604565, 547835731063078, 215360904187529, 596646739879007, 332709650425085 },
			{ 47602113726801, 1522314509708010, 437706261372925, 814035330438027, 335930650933545 },
			{ 1291597595523886, 1058020588994081, 402837842324045, 1363323695882781, 2105763393033193 }
		  }
		},
		{ // 12/31
		  {
			{ 109521982566564, 1715257748585139, 1112231216891516, 2046641005101484, 134249157157013 },
			{ 2156991030936798, 2227544497153325, 1869050094431622, 754875860479115, 1754242344267058 },
			{ 1846089562873800, 98894784984326, 1412430299204844, 171351226625762, 1100604760929008 }
		  },
		  {
			{ 84172382130492, 499710970700046, 425749630620778, 1762872794206857, 612842602127960 },
			{ 868309334532756, 1703010512741873, 1952690008738057, 4325269926064, 2071083554962116 },
			{ 523094549451158, 401938899487815, 1407690589076010, 2022387426254453, 158660516411257 }
		  },
		  {
			{ 612867287630009, 448212612103814, 571629077419196, 1466796750919376, 1728478129663858 },
			{ 1723848973783452, 2208822520534681, 1718748322776940, 1974268454121942, 1194212502258141 },
			{ 1254114807944608, 977770684047110, 2010756238954993, 1783628927194099, 1525962994408256 }
		  },
		  {
			{ 232464058235826, 1948628555342434, 1835348780427694, 1031609499437291, 64472106918373 },
			{ 767338676040683, 754089548318405, 1523192045639075, 435746025122062, 512692508440385 },
			{ 1255955808701983, 1700487367990941, 1166401238800299, 1175121994891534, 1190934801395380 }
		  },
		  {
			{ 349144008168292, 1337012557669162, 1475912332999108, 1321618454900458, 47611291904320 },
			{ 877519947135419, 2172838026132651, 272304391224129, 1655143327559984, 886229406429814 },
			{ 375806028254706, 214463229793940, 572906353144089, 572168269875638, 697556386112979 }
		  },
		  {
			{ 1168827102357844, 823864273033637, 2071538752104697, 788062026895924, 599578340743362 },
			{ 1948116082078088, 2054898304487796, 2204939184983900, 210526805152138, 786593586607626 },
			{ 1915320147894736, 156481169009469, 655050471180417, 592917090415421, 2165897438660879 }
		  },
		  {
			{ 1726336468579724, 1119932070398949, 1929199510967666, 33918788322959, 1836837863503150 },
			{ 829996854845988, 217061778005138, 1686565909803640, 1346948817219846, 1723823550730181 },
			{ 384301494966394, 687038900403062, 2211195391021739, 254684538421383, 1245698430589680 }
		  },
		  {
			{ 1247567493562688, 1978182094455847, 183871474792955, 806570235643435, 288461518067916 },
			{ 1449077384734201, 38285445457996, 2136537659177832, 2146493000841573, 725161151123125 },
			{ 1201928866368855, 800415690605445, 1703146756828343, 997278587541744, 1858284414104014 }
		  }
		},
		{ // 13/31
		  {
			{ 356468809648877, 782373916933152, 1718002439402870, 1392222252219254, 663171266061951 },
			{ 759628738230460, 1012693474275852, 353780233086498, 246080061387552, 2030378857679162 },
			{ 2040672435071076, 888593182036908, 1298443657189359, 1804780278521327, 354070726137060 }
		  },
		  {
			{ 1894938527423184, 1463213041477277, 474410505497651, 247294963033299, 877975941029128 },
			{ 207937160991127, 12966911039119, 820997788283092, 1010440472205286, 1701372890140810 },
			{ 218882774543183, 533427444716285, 1233243976733245, 435054256891319, 1509568989549904 }
		  },
		  {
			{ 1888838535711826, 1052177758340622, 1213553803324135, 169182009127332, 463374268115872 },
			{ 299137589460312, 1594371588983567, 868058494039073, 257771590636681, 1805012993142921 },
			{ 1806842755664364, 2098896946025095, 1356630998422878, 1458279806348064, 347755825962072 }
		  },
		  {
			{ 1402334161391744, 1560083671046299, 1008585416617747, 1147797150908892, 1420416683642459 },
			{ 665506704253369, 273770475169863, 799236974202630, 848328990077558, 1811448782807931 },
			{ 1468412523962641, 771866649897997, 1931766110147832, 799561180078482, 524837559150077 }
		  },
		  {
			{ 2223212657821850, 630416247363666, 2144451165500328, 816911130947791, 1024351058410032 },
			{ 1266603897524861, 156378408858100, 1275649024228779, 447738405888420, 253186462063095 },
			{ 2022215964509735, 136144366993649, 1800716593296582, 1193970603800203, 871675847064218 }
		  },
		  {
			{ 1862751661970328, 851596246739884, 1519315554814041, 1542798466547449, 1417975335901520 },
			{ 1228168094547481, 334133883362894, 587567568420081, 433612590281181, 603390400373205 },
			{ 121893973206505, 1843345804916664, 1703118377384911, 497810164760654, 101150811654673 }
		  },
		  {
			{ 458346255946468, 290909935619344, 1452768413850679, 550922875254215, 1537286854336538 },
			{ 584322311184395, 380661238802118, 114839394528060, 655082270500073, 2111856026034852 },
			{ 996965581008991, 2148998626477022, 1012273164934654, 1073876063914522, 1688031788934939 }
		  },
		  {
			{ 923487018849600, 2085106799623355, 528082801620136, 1606206360876188, 735907091712524 },
			{ 1697697887804317, 1335343703828273, 831288615207040, 949416685250051, 288760277392022 },
			{ 1419122478109648, 1325574567803701, 602393874111094, 2107893372601700, 1314159682671307 }
		  }
		},
		{ // 14/31
		  {
			{ 2201150872731804, 2180241023425241, 97663456423163, 1633405770247824, 848945042443986 },
			{ 1173339555550611, 818605084277583, 47521504364289, 924108720564965, 735423405754506 },
			{ 830104860549448, 1886653193241086, 1600929509383773, 1475051275443631, 286679780900937 }
		  },
		  {
			{ 1577111294832995, 1030899169768747, 144900916293530, 1964672592979567, 568390100955250 },
			{ 278388655910247, 487143369099838, 927762205508727, 181017540174210, 1616886700741287 },
			{ 1191033906638969, 940823957346562, 1606870843663445, 861684761499847, 658674867251089 }
		  },
		  {
			{ 1875032594195546, 1427106132796197, 724736390962158, 901860512044740, 635268497268760 },
			{ 622869792298357, 1903919278950367, 1922588621661629, 1520574711600434, 1087100760174640 },
			{ 25465949416618, 1693639527318811, 1526153382657203, 125943137857169, 145276964043999 }
		  },
		  {
			{ 214739857969358, 920212862967915, 1939901550972269, 1211862791775221, 85097515720120 },
			{ 2006245852772938, 734762734836159, 254642929763427, 1406213292755966, 239303749517686 },
			{ 1619678837192149, 1919424032779215, 1357391272956794, 1525634040073113, 1310226789796241 }
		  },
		  {
			{ 1040763709762123, 1704449869235352, 605263070456329, 1998838089036355, 1312142911487502 },
			{ 1996723311435669, 1844342766567060, 985455700466044, 1165924681400960, 311508689870129 },
			{ 43173156290518, 2202883069785309, 1137787467085917, 1733636061944606, 1394992037553852 }
		  },
		  {
			{ 670078326344559, 555655025059356, 471959386282438, 2141455487356409, 849015953823125 },
			{ 2197214573372804, 794254097241315, 1030190060513737, 267632515541902, 2040478049202624 },
			{ 1812516004670529, 1609256702920783, 1706897079364493, 258549904773295, 996051247540686 }
		  },
		  {
			{ 1540374301420584, 1764656898914615, 1810104162020396, 923808779163088, 664390074196579 },
			{ 1323460699404750, 1262690757880991, 871777133477900, 1060078894988977, 1712236889662886 },
			{ 1696163952057966, 1391710137550823, 608793846867416, 1034391509472039, 1780770894075012 }
		  },
		  {
			{ 1367603834210841, 2131988646583224, 890353773628144, 1908908219165595, 270836895252891 },
			{ 597536315471731, 40375058742586, 1942256403956049, 1185484645495932, 312666282024145 },
			{ 1919411405316294, 1234508526402192, 1066863051997083, 1008444703737597, 1348810787701552 }
		  }
		},
		{ // 15/31
		  {
			{ 2102881477513865, 1570274565945361, 1573617900503708, 18662635732583, 2232324307922098 },
			{ 1853931367696942, 8107973870707, 350214504129299, 775206934582587, 1752317649166792 },
			{ 1417148368003523, 721357181628282, 505725498207811, 373232277872983, 261634707184480 }
		  },
		  {
			{ 2186733281493267, 2250694917008620, 1014829812957440, 479998161452389, 83566193876474 },
			{ 1268116367301224, 560157088142809, 802626839600444, 2210189936605713, 1129993785579988 },
			{ 615183387352312, 917611676109240, 878893615973325, 978940963313282, 938686890583575 }
		  },
		  {
			{ 522024729211672, 1045059315315808, 1892245413707790, 1907891107684253, 2059998109500714 },
			{ 1799679152208884, 912132775900387, 25967768040979, 432130448590461, 274568990261996 },
			{ 98698809797682, 2144627600856209, 1907959298569602, 811491302610148, 1262481774981493 }
		  },
		  {
			{ 1791451399743152, 1713538728337276, 118349997257490, 1882306388849954, 158235232210248 },
			{ 1217809823321928, 2173947284933160, 1986927836272325, 1388114931125539, 12686131160169 },
			{ 1650875518872272, 1136263858253897, 1732115601395988, 734312880662190, 1252904681142109 }
		  },
		  {
			{ 372986456113865, 525430915458171, 2116279931702135, 501422713587815, 1907002872974925 },
			{ 803147181835288, 868941437997146, 316299302989663, 943495589630550, 571224287904572 },
			{ 227742695588364, 1776969298667369, 628602552821802, 457210915378118, 2041906378111140 }
		  },
		  {
			{ 815000523470260, 913085688728307, 1052060118271173, 1345536665214223, 541623413135555 },
			{ 1580216071604333, 1877997504342444, 857147161260913, 703522726778478, 2182763974211603 },
			{ 1870080310923419, 71988220958492, 1783225432016732, 615915287105016, 1035570475990230 }
		  },
		  {
			{ 730987750830150, 857613889540280, 1083813157271766, 1002817255970169, 1719228484436074 },
			{ 377616581647602, 1581980403078513, 804044118130621, 2034382823044191, 643844048472185 },
			{ 176957326463017, 1573744060478586, 528642225008045, 1816109618372371, 1515140189765006 }
		  },
		  {
			{ 1888911448245718, 1387110895611080, 1924503794066429, 1731539523700949, 2230378382645454 },
			{ 443392177002051, 233793396845137, 2199506622312416, 1011858706515937, 974676837063129 },
			{ 1846351103143623, 1949984838808427, 671247021915253, 1946756846184401, 1929296930380217 }
		  }
		},
		{ // 16/31
		  {
			{ 849646212452002, 1410198775302919, 73767886183695, 1641663456615812, 762256272452411 },
			{ 692017667358279, 723305578826727, 1638042139863265, 748219305990306, 334589200523901 },
			{ 22893968530686, 2235758574399251, 1661465835630252, 925707319443452, 1203475116966621 }
		  },
		  {
			{ 801299035785166, 1733292596726131, 1664508947088596, 467749120991922, 1647498584535623 },
			{ 903105258014366, 427141894933047, 561187017169777, 1884330244401954, 1914145708422219 },
			{ 1344191060517578, 1960935031767890, 1518838929955259, 1781502350597190, 1564784025565682 }
		  },
		  {
			{ 673723351748086, 1979969272514923, 1175287312495508, 1187589090978666, 1881897672213940 },
			{ 1917185587363432, 1098342571752737, 5935801044414, 2000527662351839, 1538640296181569 },
			{ 2495540013192, 678856913479236, 224998292422872, 219635787698590, 1972465269000940 }
		  },
		  {
			{ 271413961212179, 1353052061471651, 344711291283483, 2014925838520662, 2006221033113941 },
			{ 194583029968109, 514316781467765, 829677956235672, 1676415686873082, 810104584395840 },
			{ 1980510813313589, 1948645276483975, 152063780665900, 129968026417582, 256984195613935 }
		  },
		  {
			{ 1860190562533102, 1936576191345085, 461100292705964, 1811043097042830, 957486749306835 },
			{ 796664815624365, 1543160838872951, 1500897791837765, 1667315977988401, 599303877030711 },
			{ 1151480509533204, 2136010406720455, 738796060240027, 319298003765044, 1150614464349587 }
		  },
		  {
			{ 1731069268103150, 735642447616087, 1364750481334268, 417232839982871, 927108269127661 },
			{ 1017222050227968, 1987716148359, 2234319589635701, 621282683093392, 2132553131763026 },
			{ 1567828528453324, 1017807205202360, 565295260895298, 829541698429100, 307243822276582 }
		  },
		  {
			{ 249079270936248, 1501514259790706, 947909724204848, 944551802437487, 552658763982480 },
			{ 2089966982947227, 1854140343916181, 2151980759220007, 2139781292261749, 158070445864917 },
			{ 1338766321464554, 1906702607371284, 1519569445519894, 115384726262267, 1393058953390992 }
		  },
		  {
			{ 1364621558265400, 1512388234908357, 1926731583198686, 2041482526432505, 920401122333774 },
			{ 1884844597333588, 601480070269079, 620203503079537, 1079527400117915, 1202076693132015 },
			{ 840922919763324, 727955812569642, 1303406629750194, 522898432152867, 294161410441865 }
		  }
		},
		{ // 17/31
		  {
			{ 353760790835310, 1598361541848743, 1122905698202299, 1922533590158905, 419107700666580 },
			{ 359856369838236, 180914355488683, 861726472646627, 218807937262986, 575626773232501 },
			{ 755467689082474, 909202735047934, 730078068932500, 936309075711518, 2007798262842972 }
		  },
		  {
			{ 1609384177904073, 362745185608627, 1335318541768201, 800965770436248, 547877979267412 },
			{ 984339177776787, 815727786505884, 1645154585713747, 1659074964378553, 1686601651984156 },
			{ 1697863093781930, 599794399429786, 1104556219769607, 830560774794755, 12812858601017 }
		  },
		  {
			{ 1168737550514982, 897832437380552, 463140296333799, 302564600022547, 2008360505135501 },
			{ 1856930662813910, 678090852002597, 1920179140755167, 1259527833759868, 55540971895511 },
			{ 1158643631044921, 476554103621892, 178447851439725, 1305025542653569, 103433927680625 }
		  },
		  {
			{ 2176793111709008, 1576725716350391, 2009350167273523, 2012390194631546, 2125297410909580 },
			{ 825403285195098, 2144208587560784, 1925552004644643, 1915177840006985, 1015952128947864 },
			{ 1807108316634472, 1534392066433717, 347342975407218, 1153820745616376, 7375003497471 }
		  },
		  {
			{ 983061001799725, 431211889901241, 2201903782961093, 817393911064341, 2214616493042167 },
			{ 228567918409756, 865093958780220, 358083886450556, 159617889659320, 1360637926292598 },
			{ 234147501399755, 2229469128637390, 2175289352258889, 1397401514549353, 1885288963089922 }
		  },
		  {
			{ 1111762412951562, 252849572507389, 1048714233823341, 146111095601446, 1237505378776770 },
			{ 1113790697840279, 1051167139966244, 1045930658550944, 2011366241542643, 1686166824620755 },
			{ 1054097349305049, 1872495070333352, 182121071220717, 1064378906787311, 100273572924182 }
		  },
		  {
			{ 1306410853171605, 1627717417672447, 50983221088417, 1109249951172250, 870201789081392 },
			{ 104233794644221, 1548919791188248, 2224541913267306, 2054909377116478, 1043803389015153 },
			{ 216762189468802, 707284285441622, 190678557969733, 973969342604308, 1403009538434867 }
		  },
		  {
			{ 1279024291038477, 344776835218310, 273722096017199, 1834200436811442, 634517197663804 },
			{ 343805853118335, 1302216857414201, 566872543223541, 2051138939539004, 321428858384280 },
			{ 470067171324852, 1618629234173951, 2000092177515639, 7307679772789, 1117521120249968 }
		  }
		},
		{ // 18/31
		  {
			{ 278151578291475, 1810282338562947, 1771599529530998, 1383659409671631, 685373414471841 },
			{ 577009397403102, 1791440261786291, 2177643735971638, 174546149911960, 1412505077782326 },
			{ 893719721537457, 1201282458018197, 1522349501711173, 58011597740583, 1130406465887139 }
		  },
		  {
			{ 412607348255453, 1280455764199780, 2233277987330768, 14180080401665, 331584698417165 },
			{ 262483770854550, 990511055108216, 526885552771698, 571664396646158, 354086190278723 },
			{ 1820352417585487, 24495617171480, 1547899057533253, 10041836186225, 480457105094042 }
		  },
		  {
			{ 2023310314989233, 637905337525881, 2106474638900687, 557820711084072, 1687858215057826 },
			{ 1144168702609745, 604444390410187, 1544541121756138, 1925315550126027, 626401428894002 },
			{ 1922168257351784, 2018674099908659, 1776454117494445, 956539191509034, 36031129147635 }
		  },
		  {
			{ 544644538748041, 1039872944430374, 876750409130610, 710657711326551, 1216952687484972 },
			{ 58242421545916, 2035812695641843, 2118491866122923, 1191684463816273, 46921517454099 },
			{ 272268252444639, 1374166457774292, 2230115177009552, 1053149803909880, 1354288411641016 }
		  },
		  {
			{ 1857910905368338, 1754729879288912, 885945464109877, 1516096106802166, 1602902393369811 },
			{ 1193437069800958, 901107149704790, 999672920611411, 477584824802207, 364239578697845 },
			{ 886299989548838, 1538292895758047, 1590564179491896, 1944527126709657, 837344427345298 }
		  },
		  {
			{ 754558365378305, 1712186480903618, 1703656826337531, 750310918489786, 518996040250900 },
			{ 1309847803895382, 1462151862813074, 211370866671570, 1544595152703681, 1027691798954090 },
			{ 803217563745370, 1884799722343599, 1357706345069218, 2244955901722095, 730869460037413 }
		  },
		  {
			{ 689299471295966, 1831210565161071, 1375187341585438, 1106284977546171, 1893781834054269 },
			{ 696351368613042, 1494385251239250, 738037133616932, 636385507851544, 927483222611406 },
			{ 1949114198209333, 1104419699537997, 783495707664463, 1747473107602770, 2002634765788641 }
		  },
		  {
			{ 1607325776830197, 530883941415333, 1451089452727895, 1581691157083423, 496100432831154 },
			{ 1068900648804224, 2006891997072550, 1134049269345549, 1638760646180091, 2055396084625778 },
			{ 2222475519314561, 1870703901472013, 1884051508440561, 1344072275216753, 1318025677799069 }
		  }
		},
		{ // 19/31
		  {
			{ 155711679280656, 681100400509288, 389811735211209, 2135723811340709, 408733211204125 },
			{ 7813206966729, 194444201427550, 2071405409526507, 1065605076176312, 1645486789731291 },
			{ 16625790644959, 1647648827778410, 1579910185572704, 436452271048548, 121070048451050 }
		  },
		  {
			{ 1037263028552531, 568385780377829, 297953104144430, 1558584511931211, 2238221839292471 },
			{ 190565267697443, 672855706028058, 338796554369226, 337687268493904, 853246848691734 },
			{ 1763863028400139, 766498079432444, 1321118624818005, 69494294452268, 858786744165651 }
		  },
		  {
			{ 1292056768563024, 1456632109855638, 1100631247050184, 1386133165675321, 1232898350193752 },
			{ 366253102478259, 525676242508811, 1449610995265438, 1183300845322183, 185960306491545 },
			{ 28315355815982, 460422265558930, 1799675876678724, 1969256312504498, 1051823843138725 }
		  },
		  {
			{ 156914999361983, 1606148405719949, 1665208410108430, 317643278692271, 1383783705665320 },
			{ 54684536365732, 2210010038536222, 1194984798155308, 535239027773705, 1516355079301361 },
			{ 1484387703771650, 198537510937949, 2186282186359116, 617687444857508, 647477376402122 }
		  },
		  {
			{ 2147715541830533, 500032538445817, 646380016884826, 352227855331122, 1488268620408052 },
			{ 159386186465542, 1877626593362941, 618737197060512, 1026674284330807, 1158121760792685 },
			{ 1744544377739822, 1964054180355661, 1685781755873170, 2169740670377448, 1286112621104591 }
		  },
		  {
			{ 81977249784993, 1667943117713086, 1668983819634866, 1605016835177615, 1353960708075544 },
			{ 1602253788689063, 439542044889886, 2220348297664483, 657877410752869, 157451572512238 },
			{ 1029287186166717, 65860128430192, 525298368814832, 1491902500801986, 1461064796385400 }
		  },
		  {
			{ 408216988729246, 2121095722306989, 913562102267595, 1879708920318308, 241061448436731 },
			{ 1185483484383269, 1356339572588553, 584932367316448, 102132779946470, 1792922621116791 },
			{ 1966196870701923, 2230044620318636, 1425982460745905, 261167817826569, 46517743394330 }
		  },
		  {
			{ 107077591595359, 884959942172345, 27306869797400, 2224911448949390, 964352058245223 },
			{ 1730194207717538, 431790042319772, 1831515233279467, 1372080552768581, 1074513929381760 },
			{ 1450880638731607, 1019861580989005, 1229729455116861, 1174945729836143, 826083146840706 }
		  }
		},
		{ // 20/31
		  {
			{ 1899935429242705, 1602068751520477, 940583196550370, 82431069053859, 1540863155745696 },
			{ 2136688454840028, 2099509000964294, 1690800495246475, 1217643678575476, 828720645084218 },
			{ 765548025667841, 462473984016099, 998061409979798, 546353034089527, 2212508972466858 }
		  },
		  {
			{ 46575283771160, 892570971573071, 1281983193144090, 1491520128287375, 75847005908304 },
			{ 1801436127943107, 1734436817907890, 1268728090345068, 167003097070711, 2233597765834956 },
			{ 1997562060465113, 1048700225534011, 7615603985628, 1855310849546841, 2242557647635213 }
		  },
		  {
			{ 1161017320376250, 492624580169043, 2169815802355237, 976496781732542, 1770879511019629 },
			{ 1357044908364776, 729130645262438, 1762469072918979, 1365633616878458, 181282906404941 },
			{ 1080413443139865, 1155205815510486, 1848782073549786, 622566975152580, 124965574467971 }
		  },
		  {
			{ 1184526762066993, 247622751762817, 692129017206356, 820018689412496, 2188697339828085 },
			{ 2020536369003019, 202261491735136, 1053169669150884, 2056531979272544, 778165514694311 },
			{ 237404399610207, 1308324858405118, 1229680749538400, 720131409105291, 1958958863624906 }
		  },
		  {
			{ 515583508038846, 17656978857189, 1717918437373989, 1568052070792483, 46975803123923 },
			{ 281527309158085, 36970532401524, 866906920877543, 2222282602952734, 1289598729589882 },
			{ 1278207464902042, 494742455008756, 1262082121427081, 1577236621659884, 1888786707293291 }
		  },
		  {
			{ 353042527954210, 1830056151907359, 1111731275799225, 174960955838824, 404312815582675 },
			{ 2064251142068628, 1666421603389706, 1419271365315441, 468767774902855, 191535130366583 },
			{ 1716987058588002, 1859366439773457, 1767194234188234, 64476199777924, 1117233614485261 }
		  },
		  {
			{ 984292135520292, 135138246951259, 2220652137473167, 1722843421165029, 190482558012909 },
			{ 298845952651262, 1166086588952562, 1179896526238434, 1347812759398693, 1412945390096208 },
			{ 1143239552672925, 906436640714209, 2177000572812152, 2075299936108548, 325186347798433 }
		  },
		  {
			{ 721024854374772, 684487861263316, 1373438744094159, 2193186935276995, 1387043709851261 },
			{ 418098668140962, 715065997721283, 1471916138376055, 2168570337288357, 937812682637044 },
			{ 1043584187226485, 2143395746619356, 2209558562919611, 482427979307092, 847556718384018 }
		  }
		},
		{ // 21/31
		  {
			{ 1248731221520759, 1465200936117687, 540803492710140, 52978634680892, 261434490176109 },
			{ 1057329623869501, 620334067429122, 461700859268034, 2012481616501857, 297268569108938 },
			{ 1055352180870759, 1553151421852298, 1510903185371259, 1470458349428097, 1226259419062731 }
		  },
		  {
			{ 1492988790301668, 790326625573331, 1190107028409745, 1389394752159193, 1620408196604194 },
			{ 47000654413729, 1004754424173864, 1868044813557703, 173236934059409, 588771199737015 },
			{ 30498470091663, 1082245510489825, 576771653181956, 806509986132686, 1317634017056939 }
		  },
		  {
			{ 420308055751555, 1493354863316002, 165206721528088, 1884845694919786, 2065456951573059 },
			{ 1115636332012334, 1854340990964155, 83792697369514, 1972177451994021, 457455116057587 },
			{ 1698968457310898, 1435137169051090, 1083661677032510, 938363267483709, 340103887207182 }
		  },
		  {
			{ 1995325341336574, 911500251774648, 164010755403692, 855378419194762, 1573601397528842 },
			{ 241719380661528, 310028521317150, 1215881323380194, 1408214976493624, 2141142156467363 },
			{ 1315157046163473, 727368447885818, 1363466668108618, 1668921439990361, 1398483384337907 }
		  },
		  {
			{ 75029678299646, 1015388206460473, 1849729037055212, 1939814616452984, 444404230394954 },
			{ 2053597130993710, 2024431685856332, 2233550957004860, 2012407275509545, 872546993104440 },
			{ 1217269667678610, 599909351968693, 1390077048548598, 1471879360694802, 739586172317596 }
		  },
		  {
			{ 1718318639380794, 1560510726633958, 904462881159922, 1418028351780052, 94404349451937 },
			{ 2132502667405250, 214379346175414, 1502748313768060, 1960071701057800, 1353971822643138 },
			{ 319394212043702, 2127459436033571, 717646691535162, 663366796076914, 318459064945314 }
		  },
		  {
			{ 405989424923593, 1960452633787083, 667349034401665, 1492674260767112, 1451061489880787 },
			{ 947085906234007, 323284730494107, 1485778563977200, 728576821512394, 901584347702286 },
			{ 1575783124125742, 2126210792434375, 1569430791264065, 1402582372904727, 1891780248341114 }
		  },
		  {
			{ 838432205560695, 1997703511451664, 1018791879907867, 1662001808174331, 78328132957753 },
			{ 739152638255629, 2074935399403557, 505483666745895, 1611883356514088, 628654635394878 },
			{ 1822054032121349, 643057948186973, 7306757352712, 577249257962099, 284735863382083 }
		  }
		},
		{ // 22/31
		  {
			{ 1366558556363930, 1448606567552086, 1478881020944768, 165803179355898, 1115718458123498 },
			{ 204146226972102, 1630511199034723, 2215235214174763, 174665910283542, 956127674017216 },
			{ 1562934578796716, 1070893489712745, 11324610642270, 958989751581897, 2172552325473805 }
		  },
		  {
			{ 1770564423056027, 735523631664565, 1326060113795289, 1509650369341127, 65892421582684 },
			{ 623682558650637, 1337866509471512, 990313350206649, 1314236615762469, 1164772974270275 },
			{ 223256821462517, 723690150104139, 1000261663630601, 933280913953265, 254872671543046 }
		  },
		  {
			{ 1969087237026041, 624795725447124, 1335555107635969, 2069986355593023, 1712100149341902 },
			{ 1236103475266979, 1837885883267218, 1026072585230455, 1025865513954973, 1801964901432134 },
			{ 1115241013365517, 1712251818829143, 2148864332502771, 2096001471438138, 2235017246626125 }
		  },
		  {
			{ 1299268198601632, 2047148477845621, 2165648650132450, 1612539282026145, 514197911628890 },
			{ 118352772338543, 1067608711804704, 1434796676193498, 1683240170548391, 230866769907437 },
			{ 1850689576796636, 1601590730430274, 1139674615958142, 1954384401440257, 76039205311 }
		  },
		  {
			{ 1723387471374172, 997301467038410, 533927635123657, 20928644693965, 1756575222802513 },
			{ 2146711623855116, 503278928021499, 625853062251406, 1109121378393107, 1033853809911861 },
			{ 571005965509422, 2005213373292546, 1016697270349626, 56607856974274, 914438579435146 }
		  },
		  {
			{ 1346698876211176, 2076651707527589, 1084761571110205, 265334478828406, 1068954492309671 },
			{ 1769967932677654, 1695893319756416, 1151863389675920, 1781042784397689, 400287774418285 },
			{ 1851867764003121, 403841933237558, 820549523771987, 761292590207581, 1743735048551143 }
		  },
		  {
			{ 410915148140008, 2107072311871739, 1004367461876503, 99684895396761, 1180818713503224 },
			{ 285945406881439, 648174397347453, 1098403762631981, 1366547441102991, 1505876883139217 },
			{ 672095903120153, 1675918957959872, 636236529315028, 1569297300327696, 2164144194785875 }
		  },
		  {
			{ 1902708175321798, 1035343530915438, 1178560808893263, 301095684058146, 1280977479761118 },
			{ 1615357281742403, 404257611616381, 2160201349780978, 1160947379188955, 1578038619549541 },
			{ 2013087639791217, 822734930507457, 1785668418619014, 1668650702946164, 389450875221715 }
		  }
		},
		{ // 23/31
		  {
			{ 453918449698368, 106406819929001, 2072540975937135, 308588860670238, 1304394580755385 },
			{ 1295082798350326, 2091844511495996, 1851348972587817, 3375039684596, 789440738712837 },
			{ 2083069137186154, 848523102004566, 993982213589257, 1405313299916317, 1532824818698468 }
		  },
		  {
			{ 1495961298852430, 1397203457344779, 1774950217066942, 139302743555696, 66603584342787 },
			{ 1782411379088302, 1096724939964781, 27593390721418, 542241850291353, 1540337798439873 },
			{ 693543956581437, 171507720360750, 1557908942697227, 1074697073443438, 1104093109037196 }
		  },
		  {
			{ 345288228393419, 1099643569747172, 134881908403743, 1740551994106740, 248212179299770 },
			{ 231429562203065, 1526290236421172, 2021375064026423, 1520954495658041, 806337791525116 },
			{ 1079623667189886, 872403650198613, 766894200588288, 2163700860774109, 2023464507911816 }
		  },
		  {
			{ 854645372543796, 1936406001954827, 151460662541253, 825325739271555, 1554306377287556 },
			{ 1497138821904622, 1044820250515590, 1742593886423484, 1237204112746837, 849047450816987 },
			{ 667962773375330, 1897271816877105, 1399712621683474, 1143302161683099, 2081798441209593 }
		  },
		  {
			{ 127147851567005, 1936114012888110, 1704424366552046, 856674880716312, 716603621335359 },
			{ 1072409664800960, 2146937497077528, 1508780108920651, 935767602384853, 1112800433544068 },
			{ 333549023751292, 280219272863308, 2104176666454852, 1036466864875785, 536135186520207 }
		  },
		  {
			{ 373666279883137, 146457241530109, 304116267127857, 416088749147715, 1258577131183391 },
			{ 1186115062588401, 2251609796968486, 1098944457878953, 1153112761201374, 1791625503417267 },
			{ 1870078460219737, 2129630962183380, 852283639691142, 292865602592851, 401904317342226 }
		  },
		  {
			{ 1361070124828035, 815664541425524, 1026798897364671, 1951790935390647, 555874891834790 },
			{ 1546301003424277, 459094500062839, 1097668518375311, 1780297770129643, 720763293687608 },
			{ 1212405311403990, 1536693382542438, 61028431067459, 1863929423417129, 1223219538638038 }
		  },
		  {
			{ 1294303766540260, 1183557465955093, 882271357233093, 63854569425375, 2213283684565087 },
			{ 339050984211414, 601386726509773, 413735232134068, 966191255137228, 1839475899458159 },
			{ 235605972169408, 2174055643032978, 1538335001838863, 1281866796917192, 1815940222628465 }
		  }
		},
		{ // 24/31
		  {
			{ 1632352921721536, 1833328609514701, 2092779091951987, 1923956201873226, 2210068022482919 },
			{ 35271216625062, 1712350667021807, 983664255668860, 98571260373038, 1232645608559836 },
			{ 1998172393429622, 1798947921427073, 784387737563581, 1589352214827263, 1589861734168180 }
		  },
		  {
			{ 1733739258725305, 31715717059538, 201969945218860, 992093044556990, 1194308773174556 },
			{ 846415389605137, 746163495539180, 829658752826080, 592067705956946, 957242537821393 },
			{ 1758148849754419, 619249044817679, 168089007997045, 1371497636330523, 1867101418880350 }
		  },
		  {
			{ 326633984209635, 261759506071016, 1700682323676193, 1577907266349064, 1217647663383016 },
			{ 1714182387328607, 1477856482074168, 574895689942184, 2159118410227270, 1555532449716575 },
			{ 853828206885131, 998498946036955, 1835887550391235, 207627336608048, 258363815956050 }
		  },
		  {
			{ 141141474651677, 1236728744905256, 643101419899887, 1646615130509173, 1208239602291765 },
			{ 1501663228068911, 1354879465566912, 1444432675498247, 897812463852601, 855062598754348 },
			{ 714380763546606, 1032824444965790, 1774073483745338, 1063840874947367, 1738680636537158 }
		  },
		  {
			{ 1640635546696252, 633168953192112, 2212651044092396, 30590958583852, 368515260889378 },
			{ 1171650314802029, 1567085444565577, 1453660792008405, 757914533009261, 1619511342778196 },
			{ 420958967093237, 971103481109486, 2169549185607107, 1301191633558497, 1661514101014240 }
		  },
		  {
			{ 907123651818302, 1332556122804146, 1824055253424487, 1367614217442959, 1982558335973172 },
			{ 1121533090144639, 1021251337022187, 110469995947421, 1511059774758394, 2110035908131662 },
			{ 303213233384524, 2061932261128138, 352862124777736, 40828818670255, 249879468482660 }
		  },
		  {
			{ 856559257852200, 508517664949010, 1378193767894916, 1723459126947129, 1962275756614521 },
			{ 1445691340537320, 40614383122127, 402104303144865, 485134269878232, 1659439323587426 },
			{ 20057458979482, 1183363722525800, 2140003847237215, 2053873950687614, 2112017736174909 }
		  },
		  {
			{ 2228654250927986, 1483591363415267, 1368661293910956, 1076511285177291, 526650682059608 },
			{ 709481497028540, 531682216165724, 316963769431931, 1814315888453765, 258560242424104 },
			{ 1053447823660455, 1955135194248683, 1010900954918985, 1182614026976701, 1240051576966610 }
		  }
		},
		{ // 25/31
		  {
			{ 1957943897155497, 1788667368028035, 137692910029106, 1039519607062, 826404763313028 },
			{ 1848942433095597, 1582009882530495, 1849292741020143, 1068498323302788, 2001402229799484 },
			{ 1528282417624269, 2142492439828191, 2179662545816034, 362568973150328, 1591374675250271 }
		  },
		  {
			{ 160026679434388, 232341189218716, 2149181472355545, 598041771119831, 183859001910173 },
			{ 2013278155187349, 662660471354454, 793981225706267, 411706605985744, 804490933124791 },
			{ 2051892037280204, 488391251096321, 2230187337030708, 930221970662692, 679002758255210 }
		  },
		  {
			{ 1530723630438670, 875873929577927, 341560134269988, 449903119530753, 1055551308214179 },
			{ 1461835919309432, 1955256480136428, 180866187813063, 1551979252664528, 557743861963950 },
			{ 359179641731115, 1324915145732949, 902828372691474, 294254275669987, 1887036027752957 }
		  },
		  {
			{ 2043271609454323, 2038225437857464, 1317528426475850, 1398989128982787, 2027639881006861 },
			{ 2072902725256516, 312132452743412, 309930885642209, 996244312618453, 1590501300352303 },
			{ 1397254305160710, 695734355138021, 2233992044438756, 1776180593969996, 1085588199351115 }
		  },
		  {
			{ 440567051331029, 254894786356681, 493869224930222, 1556322069683366, 1567456540319218 },
			{ 1950722461391320, 1907845598854797, 1822757481635527, 2121567704750244, 73811931471221 },
			{ 387139307395758, 2058036430315676, 1220915649965325, 1794832055328951, 1230009312169328 }
		  },
		  {
			{ 1765973779329517, 659344059446977, 19821901606666, 1301928341311214, 1116266004075885 },
			{ 1127572801181483, 1224743760571696, 1276219889847274, 1529738721702581, 1589819666871853 },
			{ 2181229378964934, 2190885205260020, 1511536077659137, 1246504208580490, 668883326494241 }
		  },
		  {
			{ 437866655573314, 669026411194768, 81896997980338, 523874406393178, 245052060935236 },
			{ 1975438052228868, 1071801519999806, 594652299224319, 1877697652668809, 1489635366987285 },
			{ 958592545673770, 233048016518599, 851568750216589, 567703851596087, 1740300006094761 }
		  },
		  {
			{ 2014540178270324, 192672779514432, 213877182641530, 2194819933853411, 1716422829364835 },
			{ 1540769606609725, 2148289943846077, 1597804156127445, 1230603716683868, 815423458809453 },
			{ 1738560251245018, 1779576754536888, 1783765347671392, 1880170990446751, 1088225159617541 }
		  }
		},
		{ // 26/31
		  {
			{ 659303913929492, 1956447718227573, 1830568515922666, 841069049744408, 1669607124206368 },
			{ 1143465490433355, 1532194726196059, 1093276745494697, 481041706116088, 2121405433561163 },
			{ 1686424298744462, 1451806974487153, 266296068846582, 1834686947542675, 1720762336132256 }
		  },
		  {
			{ 889217026388959, 1043290623284660, 856125087551909, 1669272323124636, 1603340330827879 },
			{ 1206396181488998, 333158148435054, 1402633492821422, 1120091191722026, 1945474114550509 },
			{ 766720088232571, 1512222781191002, 1189719893490790, 2091302129467914, 2141418006894941 }
		  },
		  {
			{ 419663647306612, 1998875112167987, 1426599870253707, 1154928355379510, 486538532138187 },
			{ 938160078005954, 1421776319053174, 1941643234741774, 180002183320818, 1414380336750546 },
			{ 398001940109652, 1577721237663248, 1012748649830402, 1540516006905144, 1011684812884559 }
		  },
		  {
			{ 1653276489969630, 6081825167624, 1921777941170836, 1604139841794531, 861211053640641 },
			{ 996661541407379, 1455877387952927, 744312806857277, 139213896196746, 1000282908547789 },
			{ 1450817495603008, 1476865707053229, 1030490562252053, 620966950353376, 1744760161539058 }
		  },
		  {
			{ 559728410002599, 37056661641185, 2038622963352006, 1637244893271723, 1026565352238948 },
			{ 962165956135846, 1116599660248791, 182090178006815, 1455605467021751, 196053588803284 },
			{ 796863823080135, 1897365583584155, 420466939481601, 2165972651724672, 932177357788289 }
		  },
		  {
			{ 877047233620632, 1375632631944375, 643773611882121, 660022738847877, 19353932331831 },
			{ 2216943882299338, 394841323190322, 2222656898319671, 558186553950529, 1077236877025190 },
			{ 801118384953213, 1914330175515892, 574541023311511, 1471123787903705, 1526158900256288 }
		  },
		  {
			{ 949617889087234, 2207116611267331, 912920039141287, 501158539198789, 62362560771472 },
			{ 1474518386765335, 1760793622169197, 1157399790472736, 1622864308058898, 165428294422792 },
			{ 1961673048027128, 102619413083113, 1051982726768458, 1603657989805485, 1941613251499678 }
		  },
		  {
			{ 1401939116319266, 335306339903072, 72046196085786, 862423201496006, 850518754531384 },
			{ 1234706593321979, 1083343891215917, 898273974314935, 1640859118399498, 157578398571149 },
			{ 1143483057726416, 1992614991758919, 674268662140796, 1773370048077526, 674318359920189 }
		  }
		},
		{ // 27/31
		  {
			{ 1835401379538542, 173900035308392, 818247630716732, 1762100412152786, 1021506399448291 },
			{ 1506632088156630, 2127481795522179, 513812919490255, 140643715928370, 442476620300318 },
			{ 2056683376856736, 219094741662735, 2193541883188309, 1841182310235800, 556477468664293 }
		  },
		  {
			{ 1315019427910827, 1049075855992603, 2066573052986543, 266904467185534, 2040482348591520 },
			{ 94096246544434, 922482381166992, 24517828745563, 2139430508542503, 2097139044231004 },
			{ 537697207950515, 1399352016347350, 1563663552106345, 2148749520888918, 549922092988516 }
		  },
		  {
			{ 1747985413252434, 680511052635695, 1809559829982725, 594274250930054, 201673170745982 },
			{ 323583936109569, 1973572998577657, 1192219029966558, 79354804385273, 1374043025560347 },
			{ 213277331329947, 416202017849623, 1950535221091783, 1313441578103244, 2171386783823658 }
		  },
		  {
			{ 189088804229831, 993969372859110, 895870121536987, 1547301535298256, 1477373024911350 },
			{ 1620578418245010, 541035331188469, 2235785724453865, 2154865809088198, 1974627268751826 },
			{ 1346805451740245, 1350981335690626, 942744349501813, 2155094562545502, 1012483751693409 }
		  },
		  {
			{ 2107080134091762, 1132567062788208, 1824935377687210, 769194804343737, 1857941799971888 },
			{ 1074666112436467, 249279386739593, 1174337926625354, 1559013532006480, 1472287775519121 },
			{ 1872620123779532, 1892932666768992, 1921559078394978, 1270573311796160, 1438913646755037 }
		  },
		  {
			{ 837390187648199, 1012253300223599, 989780015893987, 1351393287739814, 328627746545550 },
			{ 1028328827183114, 1711043289969857, 1350832470374933, 1923164689604327, 1495656368846911 },
			{ 1900828492104143, 430212361082163, 687437570852799, 832514536673512, 1685641495940794 }
		  },
		  {
			{ 842632847936398, 605670026766216, 290836444839585, 163210774892356, 2213815011799645 },
			{ 1176336383453996, 1725477294339771, 12700622672454, 678015708818208, 162724078519879 },
			{ 1448049969043497, 1789411762943521, 385587766217753, 90201620913498, 832999441066823 }
		  },
		  {
			{ 516086333293313, 2240508292484616, 1351669528166508, 1223255565316488, 750235824427138 },
			{ 1263624896582495, 1102602401673328, 526302183714372, 2152015839128799, 1483839308490010 },
			{ 442991718646863, 1599275157036458, 1925389027579192, 899514691371390, 350263251085160 }
		  }
		},
		{ // 28/31
		  {
			{ 1689713572022143, 593854559254373, 978095044791970, 1985127338729499, 1676069120347625 },
			{ 1557207018622683, 340631692799603, 1477725909476187, 614735951619419, 2033237123746766 },
			{ 968764929340557, 1225534776710944, 662967304013036, 1155521416178595, 791142883466590 }
		  },
		  {
			{ 1487081286167458, 993039441814934, 1792378982844640, 698652444999874, 2153908693179754 },
			{ 1123181311102823, 685575944875442, 507605465509927, 1412590462117473, 568017325228626 },
			{ 560258797465417, 2193971151466401, 1824086900849026, 579056363542056, 1690063960036441 }
		  },
		  {
			{ 1918407319222416, 353767553059963, 1930426334528099, 1564816146005724, 1861342381708096 },
			{ 2131325168777276, 1176636658428908, 1756922641512981, 1390243617176012, 1966325177038383 },
			{ 2063958120364491, 2140267332393533, 699896251574968, 273268351312140, 375580724713232 }
		  },
		  {
			{ 2024297515263178, 416959329722687, 1079014235017302, 171612225573183, 1031677520051053 },
			{ 2033900009388450, 1744902869870788, 2190580087917640, 1949474984254121, 231049754293748 },
			{ 343868674606581, 550155864008088, 1450580864229630, 481603765195050, 896972360018042 }
		  },
		  {
			{ 2151139328380127, 314745882084928, 59756825775204, 1676664391494651, 2048348075599360 },
			{ 1528930066340597, 1605003907059576, 1055061081337675, 1458319101947665, 1234195845213142 },
			{ 830430507734812, 1780282976102377, 1425386760709037, 362399353095425, 2168861579799910 }
		  },
		  {
			{ 1155762232730333, 980662895504006, 2053766700883521, 490966214077606, 510405877041357 },
			{ 1683750316716132, 652278688286128, 1221798761193539, 1897360681476669, 319658166027343 },
			{ 618808732869972, 72755186759744, 2060379135624181, 1730731526741822, 48862757828238 }
		  },
		  {
			{ 1463171970593505, 1143040711767452, 614590986558883, 1409210575145591, 1882816996436803 },
			{ 2230133264691131, 563950955091024, 2042915975426398, 827314356293472, 672028980152815 },
			{ 264204366029760, 1654686424479449, 2185050199932931, 2207056159091748, 506015669043634 }
		  },
		  {
			{ 1784446333136569, 1973746527984364, 334856327359575, 1156769775884610, 1023950124675478 },
			{ 2065270940578383, 31477096270353, 306421879113491, 181958643936686, 1907105536686083 },
			{ 1496516440779464, 1748485652986458, 872778352227340, 818358834654919, 97932669284220 }
		  }
		},
		{ // 29/31
		  {
			{ 471636015770351, 672455402793577, 1804995246884103, 1842309243470804, 1501862504981682 },
			{ 1013216974933691, 538921919682598, 1915776722521558, 1742822441583877, 1886550687916656 },
			{ 2094270000643336, 303971879192276, 40801275554748, 649448917027930, 1818544418535447 }
		  },
		  {
			{ 2241737709499165, 549397817447461, 838180519319392, 1725686958520781, 1705639080897747 },
			{ 1216074541925116, 50120933933509, 1565829004133810, 721728156134580, 349206064666188 },
			{ 948617110470858, 346222547451945, 1126511960599975, 1759386906004538, 493053284802266 }
		  },
		  {
			{ 1454933046815146, 874696014266362, 1467170975468588, 1432316382418897, 2111710746366763 },
			{ 2105387117364450, 1996463405126433, 1303008614294500, 851908115948209, 1353742049788635 },
			{ 750300956351719, 1487736556065813, 15158817002104, 1511998221598392, 971739901354129 }
		  },
		  {
			{ 1874648163531693, 2124487685930551, 1810030029384882, 918400043048335, 586348627300650 },
			{ 1235084464747900, 1166111146432082, 1745394857881591, 1405516473883040, 4463504151617 },
			{ 1663810156463827, 327797390285791, 1341846161759410, 1964121122800605, 1747470312055380 }
		  },
		  {
			{ 660005247548233, 2071860029952887, 1358748199950107, 911703252219107, 1014379923023831 },
			{ 2206641276178231, 1690587809721504, 1600173622825126, 2156096097634421, 1106822408548216 },
			{ 1344788193552206, 1949552134239140, 1735915881729557, 675891104100469, 1834220014427292 }
		  },
		  {
			{ 1920949492387964, 158885288387530, 70308263664033, 626038464897817, 1468081726101009 },
			{ 622221042073383, 1210146474039168, 1742246422343683, 1403839361379025, 417189490895736 },
			{ 22727256592983, 168471543384997, 1324340989803650, 1839310709638189, 504999476432775 }
		  },
		  {
			{ 1313240518756327, 1721896294296942, 52263574587266, 2065069734239232, 804910473424630 },
			{ 1337466662091884, 1287645354669772, 2018019646776184, 652181229374245, 898011753211715 },
			{ 1969792547910734, 779969968247557, 2011350094423418, 1823964252907487, 1058949448296945 }
		  },
		  {
			{ 207343737062002, 1118176942430253, 758894594548164, 806764629546266, 1157700123092949 },
			{ 1273565321399022, 1638509681964574, 759235866488935, 666015124346707, 897983460943405 },
			{ 1717263794012298, 1059601762860786, 1837819172257618, 1054130665797229, 680893204263559 }
		  }
		},
		{ // 30/31
		  {
			{ 2237039662793603, 2249022333361206, 2058613546633703, 149454094845279, 2215176649164582 },
			{ 79472182719605, 1851130257050174, 1825744808933107, 821667333481068, 781795293511946 },
			{ 755822026485370, 152464789723500, 1178207602290608, 410307889503239, 156581253571278 }
		  },
		  {
			{ 1418185496130297, 484520167728613, 1646737281442950, 1401487684670265, 1349185550126961 },
			{ 1495380034400429, 325049476417173, 46346894893933, 1553408840354856, 828980101835683 },
			{ 1280337889310282, 2070832742866672, 1640940617225222, 2098284908289951, 450929509534434 }
		  },
		  {
			{ 407703353998781, 126572141483652, 286039827513621, 1999255076709338, 2030511179441770 },
			{ 1254958221100483, 1153235960999843, 942907704968834, 637105404087392, 1149293270147267 },
			{ 894249020470196, 400291701616810, 406878712230981, 1599128793487393, 1145868722604026 }
		  },
		  {
			{ 1497955250203334, 110116344653260, 1128535642171976, 1900106496009660, 129792717460909 },
			{ 452487513298665, 1352120549024569, 1173495883910956, 1999111705922009, 367328130454226 },
			{ 1717539401269642, 1475188995688487, 891921989653942, 836824441505699, 1885988485608364 }
		  },
		  {
			{ 1241784121422547, 187337051947583, 1118481812236193, 428747751936362, 30358898927325 },
			{ 2022432361201842, 1088816090685051, 1977843398539868, 1854834215890724, 564238862029357 },
			{ 938868489100585, 1100285072929025, 1017806255688848, 1957262154788833, 152787950560442 }
		  },
		  {
			{ 867319417678923, 620471962942542, 226032203305716, 342001443957629, 1761675818237336 },
			{ 1295072362439987, 931227904689414, 1355731432641687, 922235735834035, 892227229410209 },
			{ 1680989767906154, 535362787031440, 2136691276706570, 1942228485381244, 1267350086882274 }
		  },
		  {
			{ 366018233770527, 432660629755596, 126409707644535, 1973842949591662, 645627343442376 },
			{ 535509430575217, 546885533737322, 1524675609547799, 2138095752851703, 1260738089896827 },
			{ 1159906385590467, 2198530004321610, 714559485023225, 81880727882151, 1484020820037082 }
		  },
		  {
			{ 1377485731340769, 2046328105512000, 1802058637158797, 62146136768173, 1356993908853901 },
			{ 2013612215646735, 1830770575920375, 536135310219832, 609272325580394, 270684344495013 },
			{ 1237542585982777, 2228682050256790, 1385281931622824, 593183794882890, 493654978552689 }
		  }
		},
		{ /// 31/31
		  {
			{ 47341488007760, 1891414891220257, 983894663308928, 176161768286818, 1126261115179708 },
			{ 1694030170963455, 502038567066200, 1691160065225467, 949628319562187, 275110186693066 },
			{ 1124515748676336, 1661673816593408, 1499640319059718, 1584929449166988, 558148594103306 }
		  },
		  {
			{ 1784525599998356, 1619698033617383, 2097300287550715, 258265458103756, 1905684794832758 },
			{ 1288941072872766, 931787902039402, 190731008859042, 2006859954667190, 1005931482221702 },
			{ 1465551264822703, 152905080555927, 680334307368453, 173227184634745, 666407097159852 }
		  },
		  {
			{ 2111017076203943, 1378760485794347, 1248583954016456, 1352289194864422, 1895180776543896 },
			{ 171348223915638, 662766099800389, 462338943760497, 466917763340314, 656911292869115 },
			{ 488623681976577, 866497561541722, 1708105560937768, 1673781214218839, 1506146329818807 }
		  },
		  {
			{ 160425464456957, 950394373239689, 430497123340934, 711676555398832, 320964687779005 },
			{ 988979367990485, 1359729327576302, 1301834257246029, 294141160829308, 29348272277475 },
			{ 1434382743317910, 100082049942065, 221102347892623, 186982837860588, 1305765053501834 }
		  },
		  {
			{ 2205916462268190, 499863829790820, 961960554686616, 158062762756985, 1841471168298305 },
			{ 1191737341426592, 1847042034978363, 1382213545049056, 1039952395710448, 788812858896859 },
			{ 1346965964571152, 1291881610839830, 2142916164336056, 786821641205979, 1571709146321039 }
		  },
		  {
			{ 787164375951248, 202869205373189, 1356590421032140, 1431233331032510, 786341368775957 },
			{ 492448143532951, 304105152670757, 1761767168301056, 233782684697790, 1981295323106089 },
			{ 665807507761866, 1343384868355425, 895831046139653, 439338948736892, 1986828765695105 }
		  },
		  {
			{ 756096210874553, 1721699973539149, 258765301727885, 1390588532210645, 1212530909934781 },
			{ 852891097972275, 1816988871354562, 1543772755726524, 1174710635522444, 202129090724628 },
			{ 1205281565824323, 22430498399418, 992947814485516, 1392458699738672, 688441466734558 }
		  },
		  {
			{ 1050627428414972, 1955849529137135, 2171162376368357, 91745868298214, 447733118757826 },
			{ 1287181461435438, 622722465530711, 880952150571872, 741035693459198, 311565274989772 },
			{ 1003649078149734, 545233927396469, 1849786171789880, 1318943684880434, 280345687170552 }
		  }
		}
#else
		{ // 0/31
		  {
			{ 25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605 },
			{ -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378 },
			{ -8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546 }
		  },
		  {
			{ -12815894, -12976347, -21581243, 11784320, -25355658, -2750717, -11717903, -3814571, -358445, -10211303 },
			{ -21703237, 6903825, 27185491, 6451973, -29577724, -9554005, -15616551, 11189268, -26829678, -5319081 },
			{ 26966642, 11152617, 32442495, 15396054, 14353839, -12752335, -3128826, -9541118, -15472047, -4166697 }
		  },
		  {
			{ 15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024 },
			{ 16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574 },
			{ 30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357 }
		  },
		  {
			{ -17036878, 13921892, 10945806, -6033431, 27105052, -16084379, -28926210, 15006023, 3284568, -6276540 },
			{ 23599295, -8306047, -11193664, -7687416, 13236774, 10506355, 7464579, 9656445, 13059162, 10374397 },
			{ 7798556, 16710257, 3033922, 2874086, 28997861, 2835604, 32406664, -3839045, -641708, -101325 }
		  },
		  {
			{ 10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380 },
			{ 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306 },
			{ 19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942 }
		  },
		  {
			{ -15371964, -12862754, 32573250, 4720197, -26436522, 5875511, -19188627, -15224819, -9818940, -12085777 },
			{ -8549212, 109983, 15149363, 2178705, 22900618, 4543417, 3044240, -15689887, 1762328, 14866737 },
			{ -18199695, -15951423, -10473290, 1707278, -17185920, 3916101, -28236412, 3959421, 27914454, 4383652 }
		  },
		  {
			{ 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766 },
			{ -30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701 },
			{ 28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300 }
		  },
		  {
			{ 14499471, -2729599, -33191113, -4254652, 28494862, 14271267, 30290735, 10876454, -33154098, 2381726 },
			{ -7195431, -2655363, -14730155, 462251, -27724326, 3941372, -6236617, 3696005, -32300832, 15351955 },
			{ 27431194, 8222322, 16448760, -3907995, -18707002, 11938355, -32961401, -2970515, 29551813, 10109425 }
		  }
		},
		{ // 1/31
		  {
			{ -13657040, -13155431, -31283750, 11777098, 21447386, 6519384, -2378284, -1627556, 10092783, -4764171 },
			{ 27939166, 14210322, 4677035, 16277044, -22964462, -12398139, -32508754, 12005538, -17810127, 12803510 },
			{ 17228999, -15661624, -1233527, 300140, -1224870, -11714777, 30364213, -9038194, 18016357, 4397660 }
		  },
		  {
			{ -10958843, -7690207, 4776341, -14954238, 27850028, -15602212, -26619106, 14544525, -17477504, 982639 },
			{ 29253598, 15796703, -2863982, -9908884, 10057023, 3163536, 7332899, -4120128, -21047696, 9934963 },
			{ 5793303, 16271923, -24131614, -10116404, 29188560, 1206517, -14747930, 4559895, -30123922, -10897950 }
		  },
		  {
			{ -27643952, -11493006, 16282657, -11036493, 28414021, -15012264, 24191034, 4541697, -13338309, 5500568 },
			{ 12650548, -1497113, 9052871, 11355358, -17680037, -8400164, -17430592, 12264343, 10874051, 13524335 },
			{ 25556948, -3045990, 714651, 2510400, 23394682, -10415330, 33119038, 5080568, -22528059, 5376628 }
		  },
		  {
			{ -26088264, -4011052, -17013699, -3537628, -6726793, 1920897, -22321305, -9447443, 4535768, 1569007 },
			{ -2255422, 14606630, -21692440, -8039818, 28430649, 8775819, -30494562, 3044290, 31848280, 12543772 },
			{ -22028579, 2943893, -31857513, 6777306, 13784462, -4292203, -27377195, -2062731, 7718482, 14474653 }
		  },
		  {
			{ 2385315, 2454213, -22631320, 46603, -4437935, -15680415, 656965, -7236665, 24316168, -5253567 },
			{ 13741529, 10911568, -33233417, -8603737, -20177830, -1033297, 33040651, -13424532, -20729456, 8321686 },
			{ 21060490, -2212744, 15712757, -4336099, 1639040, 10656336, 23845965, -11874838, -9984458, 608372 }
		  },
		  {
			{ -13672732, -15087586, -10889693, -7557059, -6036909, 11305547, 1123968, -6780577, 27229399, 23887 },
			{ -23244140, -294205, -11744728, 14712571, -29465699, -2029617, 12797024, -6440308, -1633405, 16678954 },
			{ -29500620, 4770662, -16054387, 14001338, 7830047, 9564805, -1508144, -4795045, -17169265, 4904953 }
		  },
		  {
			{ 24059557, 14617003, 19037157, -15039908, 19766093, -14906429, 5169211, 16191880, 2128236, -4326833 },
			{ -16981152, 4124966, -8540610, -10653797, 30336522, -14105247, -29806336, 916033, -6882542, -2986532 },
			{ -22630907, 12419372, -7134229, -7473371, -16478904, 16739175, 285431, 2763829, 15736322, 4143876 }
		  },
		  {
			{ 2379352, 11839345, -4110402, -5988665, 11274298, 794957, 212801, -14594663, 23527084, -16458268 },
			{ 33431127, -11130478, -17838966, -15626900, 8909499, 8376530, -32625340, 4087881, -15188911, -14416214 },
			{ 1767683, 7197987, -13205226, -2022635, -13091350, 448826, 5799055, 4357868, -4774191, -16323038 }
		  }
		},
		{ // 2/31
		  {
			{ 6721966, 13833823, -23523388, -1551314, 26354293, -11863321, 23365147, -3949732, 7390890, 2759800 },
			{ 4409041, 2052381, 23373853, 10530217, 7676779, -12885954, 21302353, -4264057, 1244380, -12919645 },
			{ -4421239, 7169619, 4982368, -2957590, 30256825, -2777540, 14086413, 9208236, 15886429, 16489664 }
		  },
		  {
			{ 1996075, 10375649, 14346367, 13311202, -6874135, -16438411, -13693198, 398369, -30606455, -712933 },
			{ -25307465, 9795880, -2777414, 14878809, -33531835, 14780363, 13348553, 12076947, -30836462, 5113182 },
			{ -17770784, 11797796, 31950843, 13929123, -25888302, 12288344, -30341101, -7336386, 13847711, 5387222 }
		  },
		  {
			{ -18582163, -3416217, 17824843, -2340966, 22744343, -10442611, 8763061, 3617786, -19600662, 10370991 },
			{ 20246567, -14369378, 22358229, -543712, 18507283, -10413996, 14554437, -8746092, 32232924, 16763880 },
			{ 9648505, 10094563, 26416693, 14745928, -30374318, -6472621, 11094161, 15689506, 3140038, -16510092 }
		  },
		  {
			{ -16160072, 5472695, 31895588, 4744994, 8823515, 10365685, -27224800, 9448613, -28774454, 366295 },
			{ 19153450, 11523972, -11096490, -6503142, -24647631, 5420647, 28344573, 8041113, 719605, 11671788 },
			{ 8678025, 2694440, -6808014, 2517372, 4964326, 11152271, -15432916, -15266516, 27000813, -10195553 }
		  },
		  {
			{ -15157904, 7134312, 8639287, -2814877, -7235688, 10421742, 564065, 5336097, 6750977, -14521026 },
			{ 11836410, -3979488, 26297894, 16080799, 23455045, 15735944, 1695823, -8819122, 8169720, 16220347 },
			{ -18115838, 8653647, 17578566, -6092619, -8025777, -16012763, -11144307, -2627664, -5990708, -14166033 }
		  },
		  {
			{ -23308498, -10968312, 15213228, -10081214, -30853605, -11050004, 27884329, 2847284, 2655861, 1738395 },
			{ -27537433, -14253021, -25336301, -8002780, -9370762, 8129821, 21651608, -3239336, -19087449, -11005278 },
			{ 1533110, 3437855, 23735889, 459276, 29970501, 11335377, 26030092, 5821408, 10478196, 8544890 }
		  },
		  {
			{ 32173121, -16129311, 24896207, 3921497, 22579056, -3410854, 19270449, 12217473, 17789017, -3395995 },
			{ -30552961, -2228401, -15578829, -10147201, 13243889, 517024, 15479401, -3853233, 30460520, 1052596 },
			{ -11614875, 13323618, 32618793, 8175907, -15230173, 12596687, 27491595, -4612359, 3179268, -9478891 }
		  },
		  {
			{ 31947069, -14366651, -4640583, -15339921, -15125977, -6039709, -14756777, -16411740, 19072640, -9511060 },
			{ 11685058, 11822410, 3158003, -13952594, 33402194, -4165066, 5977896, -5215017, 473099, 5040608 },
			{ -20290863, 8198642, -27410132, 11602123, 1290375, -2799760, 28326862, 1721092, -19558642, -3131606 }
		  }
		},
		{ // 3/31
		  {
			{ 7881532, 10687937, 7578723, 7738378, -18951012, -2553952, 21820786, 8076149, -27868496, 11538389 },
			{ -19935666, 3899861, 18283497, -6801568, -15728660, -11249211, 8754525, 7446702, -5676054, 5797016 },
			{ -11295600, -3793569, -15782110, -7964573, 12708869, -8456199, 2014099, -9050574, -2369172, -5877341 }
		  },
		  {
			{ -22472376, -11568741, -27682020, 1146375, 18956691, 16640559, 1192730, -3714199, 15123619, 10811505 },
			{ 14352098, -3419715, -18942044, 10822655, 32750596, 4699007, -70363, 15776356, -28886779, -11974553 },
			{ -28241164, -8072475, -4978962, -5315317, 29416931, 1847569, -20654173, -16484855, 4714547, -9600655 }
		  },
		  {
			{ 15200332, 8368572, 19679101, 15970074, -31872674, 1959451, 24611599, -4543832, -11745876, 12340220 },
			{ 12876937, -10480056, 33134381, 6590940, -6307776, 14872440, 9613953, 8241152, 15370987, 9608631 },
			{ -4143277, -12014408, 8446281, -391603, 4407738, 13629032, -7724868, 15866074, -28210621, -8814099 }
		  },
		  {
			{ 26660628, -15677655, 8393734, 358047, -7401291, 992988, -23904233, 858697, 20571223, 8420556 },
			{ 14620715, 13067227, -15447274, 8264467, 14106269, 15080814, 33531827, 12516406, -21574435, -12476749 },
			{ 236881, 10476226, 57258, -14677024, 6472998, 2466984, 17258519, 7256740, 8791136, 15069930 }
		  },
		  {
			{ 1276410, -9371918, 22949635, -16322807, -23493039, -5702186, 14711875, 4874229, -30663140, -2331391 },
			{ 5855666, 4990204, -13711848, 7294284, -7804282, 1924647, -1423175, -7912378, -33069337, 9234253 },
			{ 20590503, -9018988, 31529744, -7352666, -2706834, 10650548, 31559055, -11609587, 18979186, 13396066 }
		  },
		  {
			{ 24474287, 4968103, 22267082, 4407354, 24063882, -8325180, -18816887, 13594782, 33514650, 7021958 },
			{ -11566906, -6565505, -21365085, 15928892, -26158305, 4315421, -25948728, -3916677, -21480480, 12868082 },
			{ -28635013, 13504661, 19988037, -2132761, 21078225, 6443208, -21446107, 2244500, -12455797, -8089383 }
		  },
		  {
			{ -30595528, 13793479, -5852820, 319136, -25723172, -6263899, 33086546, 8957937, -15233648, 5540521 },
			{ -11630176, -11503902, -8119500, -7643073, 2620056, 1022908, -23710744, -1568984, -16128528, -14962807 },
			{ 23152971, 775386, 27395463, 14006635, -9701118, 4649512, 1689819, 892185, -11513277, -15205948 }
		  },
		  {
			{ 9770129, 9586738, 26496094, 4324120, 1556511, -3550024, 27453819, 4763127, -19179614, 5867134 },
			{ -32765025, 1927590, 31726409, -4753295, 23962434, -16019500, 27846559, 5931263, -29749703, -16108455 },
			{ 27461885, -2977536, 22380810, 1815854, -23033753, -3031938, 7283490, -15148073, -19526700, 7734629 }
		  }
		},
		{ // 4/31
		  {
			{ -8010264, -9590817, -11120403, 6196038, 29344158, -13430885, 7585295, -3176626, 18549497, 15302069 },
			{ -32658337, -6171222, -7672793, -11051681, 6258878, 13504381, 10458790, -6418461, -8872242, 8424746 },
			{ 24687205, 8613276, -30667046, -3233545, 1863892, -1830544, 19206234, 7134917, -11284482, -828919 }
		  },
		  {
			{ 11334899, -9218022, 8025293, 12707519, 17523892, -10476071, 10243738, -14685461, -5066034, 16498837 },
			{ 8911542, 6887158, -9584260, -6958590, 11145641, -9543680, 17303925, -14124238, 6536641, 10543906 },
			{ -28946384, 15479763, -17466835, 568876, -1497683, 11223454, -2669190, -16625574, -27235709, 8876771 }
		  },
		  {
			{ -25742899, -12566864, -15649966, -846607, -33026686, -796288, -33481822, 15824474, -604426, -9039817 },
			{ 10330056, 70051, 7957388, -9002667, 9764902, 15609756, 27698697, -4890037, 1657394, 3084098 },
			{ 10477963, -7470260, 12119566, -13250805, 29016247, -5365589, 31280319, 14396151, -30233575, 15272409 }
		  },
		  {
			{ -12288309, 3169463, 28813183, 16658753, 25116432, -5630466, -25173957, -12636138, -25014757, 1950504 },
			{ -26180358, 9489187, 11053416, -14746161, -31053720, 5825630, -8384306, -8767532, 15341279, 8373727 },
			{ 28685821, 7759505, -14378516, -12002860, -31971820, 4079242, 298136, -10232602, -2878207, 15190420 }
		  },
		  {
			{ -32932876, 13806336, -14337485, -15794431, -24004620, 10940928, 8669718, 2742393, -26033313, -6875003 },
			{ -1580388, -11729417, -25979658, -11445023, -17411874, -10912854, 9291594, -16247779, -12154742, 6048605 },
			{ -30305315, 14843444, 1539301, 11864366, 20201677, 1900163, 13934231, 5128323, 11213262, 9168384 }
		  },
		  {
			{ -26280513, 11007847, 19408960, -940758, -18592965, -4328580, -5088060, -11105150, 20470157, -16398701 },
			{ -23136053, 9282192, 14855179, -15390078, -7362815, -14408560, -22783952, 14461608, 14042978, 5230683 },
			{ 29969567, -2741594, -16711867, -8552442, 9175486, -2468974, 21556951, 3506042, -5933891, -12449708 }
		  },
		  {
			{ -3144746, 8744661, 19704003, 4581278, -20430686, 6830683, -21284170, 8971513, -28539189, 15326563 },
			{ -19464629, 10110288, -17262528, -3503892, -23500387, 1355669, -15523050, 15300988, -20514118, 9168260 },
			{ -5353335, 4488613, -23803248, 16314347, 7780487, -15638939, -28948358, 9601605, 33087103, -9011387 }
		  },
		  {
			{ -19443170, -15512900, -20797467, -12445323, -29824447, 10229461, -27444329, -15000531, -5996870, 15664672 },
			{ 23294591, -16632613, -22650781, -8470978, 27844204, 11461195, 13099750, -2460356, 18151676, 13417686 },
			{ -24722913, -4176517, -31150679, 5988919, -26858785, 6685065, 1661597, -12551441, 15271676, -15452665 }
		  }
		},
		{ // 5/31
		  {
			{ 11433042, -13228665, 8239631, -5279517, -1985436, -725718, -18698764, 2167544, -6921301, -13440182 },
			{ -31436171, 15575146, 30436815, 12192228, -22463353, 9395379, -9917708, -8638997, 12215110, 12028277 },
			{ 14098400, 6555944, 23007258, 5757252, -15427832, -12950502, 30123440, 4617780, -16900089, -655628 }
		  },
		  {
			{ -4026201, -15240835, 11893168, 13718664, -14809462, 1847385, -15819999, 10154009, 23973261, -12684474 },
			{ -26531820, -3695990, -1908898, 2534301, -31870557, -16550355, 18341390, -11419951, 32013174, -10103539 },
			{ -25479301, 10876443, -11771086, -14625140, -12369567, 1838104, 21911214, 6354752, 4425632, -837822 }
		  },
		  {
			{ -10433389, -14612966, 22229858, -3091047, -13191166, 776729, -17415375, -12020462, 4725005, 14044970 },
			{ 19268650, -7304421, 1555349, 8692754, -21474059, -9910664, 6347390, -1411784, -19522291, -16109756 },
			{ -24864089, 12986008, -10898878, -5558584, -11312371, -148526, 19541418, 8180106, 9282262, 10282508 }
		  },
		  {
			{ -26205082, 4428547, -8661196, -13194263, 4098402, -14165257, 15522535, 8372215, 5542595, -10702683 },
			{ -10562541, 14895633, 26814552, -16673850, -17480754, -2489360, -2781891, 6993761, -18093885, 10114655 },
			{ -20107055, -929418, 31422704, 10427861, -7110749, 6150669, -29091755, -11529146, 25953725, -106158 }
		  },
		  {
			{ -4234397, -8039292, -9119125, 3046000, 2101609, -12607294, 19390020, 6094296, -3315279, 12831125 },
			{ -15998678, 7578152, 5310217, 14408357, -33548620, -224739, 31575954, 6326196, 7381791, -2421839 },
			{ -20902779, 3296811, 24736065, -16328389, 18374254, 7318640, 6295303, 8082724, -15362489, 12339664 }
		  },
		  {
			{ 27724736, 2291157, 6088201, -14184798, 1792727, 5857634, 13848414, 15768922, 25091167, 14856294 },
			{ -18866652, 8331043, 24373479, 8541013, -701998, -9269457, 12927300, -12695493, -22182473, -9012899 },
			{ -11423429, -5421590, 11632845, 3405020, 30536730, -11674039, -27260765, 13866390, 30146206, 9142070 }
		  },
		  {
			{ 3924129, -15307516, -13817122, -10054960, 12291820, -668366, -27702774, 9326384, -8237858, 4171294 },
			{ -15921940, 16037937, 6713787, 16606682, -21612135, 2790944, 26396185, 3731949, 345228, -5462949 },
			{ -21327538, 13448259, 25284571, 1143661, 20614966, -8849387, 2031539, -12391231, -16253183, -13582083 }
		  },
		  {
			{ 31016211, -16722429, 26371392, -14451233, -5027349, 14854137, 17477601, 3842657, 28012650, -16405420 },
			{ -5075835, 9368966, -8562079, -4600902, -15249953, 6970560, -9189873, 16292057, -8867157, 3507940 },
			{ 29439664, 3537914, 23333589, 6997794, -17555561, -11018068, -15209202, -15051267, -9164929, 6580396 }
		  }
		},
		{ // 6/31
		  {
			{ -12185861, -7679788, 16438269, 10826160, -8696817, -6235611, 17860444, -9273846, -2095802, 9304567 },
			{ 20714564, -4336911, 29088195, 7406487, 11426967, -5095705, 14792667, -14608617, 5289421, -477127 },
			{ -16665533, -10650790, -6160345, -13305760, 9192020, -1802462, 17271490, 12349094, 26939669, -3752294 }
		  },
		  {
			{ -12889898, 9373458, 31595848, 16374215, 21471720, 13221525, -27283495, -12348559, -3698806, 117887 },
			{ 22263325, -6560050, 3984570, -11174646, -15114008, -566785, 28311253, 5358056, -23319780, 541964 },
			{ 16259219, 3261970, 2309254, -15534474, -16885711, -4581916, 24134070, -16705829, -13337066, -13552195 }
		  },
		  {
			{ 9378160, -13140186, -22845982, -12745264, 28198281, -7244098, -2399684, -717351, 690426, 14876244 },
			{ 24977353, -314384, -8223969, -13465086, 28432343, -1176353, -13068804, -12297348, -22380984, 6618999 },
			{ -1538174, 11685646, 12944378, 13682314, -24389511, -14413193, 8044829, -13817328, 32239829, -5652762 }
		  },
		  {
			{ -18603066, 4762990, -926250, 8885304, -28412480, -3187315, 9781647, -10350059, 32779359, 5095274 },
			{ -33008130, -5214506, -32264887, -3685216, 9460461, -9327423, -24601656, 14506724, 21639561, -2630236 },
			{ -16400943, -13112215, 25239338, 15531969, 3987758, -4499318, -1289502, -6863535, 17874574, 558605 }
		  },
		  {
			{ -13600129, 10240081, 9171883, 16131053, -20869254, 9599700, 33499487, 5080151, 2085892, 5119761 },
			{ -22205145, -2519528, -16381601, 414691, -25019550, 2170430, 30634760, -8363614, -31999993, -5759884 },
			{ -6845704, 15791202, 8550074, -1312654, 29928809, -12092256, 27534430, -7192145, -22351378, 12961482 }
		  },
		  {
			{ -24492060, -9570771, 10368194, 11582341, -23397293, -2245287, 16533930, 8206996, -30194652, -5159638 },
			{ -11121496, -3382234, 2307366, 6362031, -135455, 8868177, -16835630, 7031275, 7589640, 8945490 },
			{ -32152748, 8917967, 6661220, -11677616, -1192060, -15793393, 7251489, -11182180, 24099109, -14456170 }
		  },
		  {
			{ 5019558, -7907470, 4244127, -14714356, -26933272, 6453165, -19118182, -13289025, -6231896, -10280736 },
			{ 10853594, 10721687, 26480089, 5861829, -22995819, 1972175, -1866647, -10557898, -3363451, -6441124 },
			{ -17002408, 5906790, 221599, -6563147, 7828208, -13248918, 24362661, -2008168, -13866408, 7421392 }
		  },
		  {
			{ 8139927, -6546497, 32257646, -5890546, 30375719, 1886181, -21175108, 15441252, 28826358, -4123029 },
			{ 6267086, 9695052, 7709135, -16603597, -32869068, -1886135, 14795160, -7840124, 13746021, -1742048 },
			{ 28584902, 7787108, -6732942, -15050729, 22846041, -7571236, -3181936, -363524, 4771362, -8419958 }
		  }
		},
		{ // 7/31
		  {
			{ 24949256, 6376279, -27466481, -8174608, -18646154, -9930606, 33543569, -12141695, 3569627, 11342593 },
			{ 26514989, 4740088, 27912651, 3697550, 19331575, -11472339, 6809886, 4608608, 7325975, -14801071 },
			{ -11618399, -14554430, -24321212, 7655128, -1369274, 5214312, -27400540, 10258390, -17646694, -8186692 }
		  },
		  {
			{ 11431204, 15823007, 26570245, 14329124, 18029990, 4796082, -31446179, 15580664, 9280358, -3973687 },
			{ -160783, -10326257, -22855316, -4304997, -20861367, -13621002, -32810901, -11181622, -15545091, 4387441 },
			{ -20799378, 12194512, 3937617, -5805892, -27154820, 9340370, -24513992, 8548137, 20617071, -7482001 }
		  },
		  {
			{ -938825, -3930586, -8714311, 16124718, 24603125, -6225393, -13775352, -11875822, 24345683, 10325460 },
			{ -19855277, -1568885, -22202708, 8714034, 14007766, 6928528, 16318175, -1010689, 4766743, 3552007 },
			{ -21751364, -16730916, 1351763, -803421, -4009670, 3950935, 3217514, 14481909, 10988822, -3994762 }
		  },
		  {
			{ 15564307, -14311570, 3101243, 5684148, 30446780, -8051356, 12677127, -6505343, -8295852, 13296005 },
			{ -9442290, 6624296, -30298964, -11913677, -4670981, -2057379, 31521204, 9614054, -30000824, 12074674 },
			{ 4771191, -135239, 14290749, -13089852, 27992298, 14998318, -1413936, -1556716, 29832613, -16391035 }
		  },
		  {
			{ 7064884, -7541174, -19161962, -5067537, -18891269, -2912736, 25825242, 5293297, -27122660, 13101590 },
			{ -2298563, 2439670, -7466610, 1719965, -27267541, -16328445, 32512469, -5317593, -30356070, -4190957 },
			{ -30006540, 10162316, -33180176, 3981723, -16482138, -13070044, 14413974, 9515896, 19568978, 9628812 }
		  },
		  {
			{ 33053803, 199357, 15894591, 1583059, 27380243, -4580435, -17838894, -6106839, -6291786, 3437740 },
			{ -18978877, 3884493, 19469877, 12726490, 15913552, 13614290, -22961733, 70104, 7463304, 4176122 },
			{ -27124001, 10659917, 11482427, -16070381, 12771467, -6635117, -32719404, -5322751, 24216882, 5944158 }
		  },
		  {
			{ 8894125, 7450974, -2664149, -9765752, -28080517, -12389115, 19345746, 14680796, 11632993, 5847885 },
			{ 26942781, -2315317, 9129564, -4906607, 26024105, 11769399, -11518837, 6367194, -9727230, 4782140 },
			{ 19916461, -4828410, -22910704, -11414391, 25606324, -5972441, 33253853, 8220911, 6358847, -1873857 }
		  },
		  {
			{ 801428, -2081702, 16569428, 11065167, 29875704, 96627, 7908388, -4480480, -13538503, 1387155 },
			{ 19646058, 5720633, -11416706, 12814209, 11607948, 12749789, 14147075, 15156355, -21866831, 11835260 },
			{ 19299512, 1155910, 28703737, 14890794, 2925026, 7269399, 26121523, 15467869, -26560550, 5052483 }
		  }
		},
		{ // 8/31
		  {
			{ -3017432, 10058206, 1980837, 3964243, 22160966, 12322533, -6431123, -12618185, 12228557, -7003677 },
			{ 32944382, 14922211, -22844894, 5188528, 21913450, -8719943, 4001465, 13238564, -6114803, 8653815 },
			{ 22865569, -4652735, 27603668, -12545395, 14348958, 8234005, 24808405, 5719875, 28483275, 2841751 }
		  },
		  {
			{ -16420968, -1113305, -327719, -12107856, 21886282, -15552774, -1887966, -315658, 19932058, -12739203 },
			{ -11656086, 10087521, -8864888, -5536143, -19278573, -3055912, 3999228, 13239134, -4777469, -13910208 },
			{ 1382174, -11694719, 17266790, 9194690, -13324356, 9720081, 20403944, 11284705, -14013818, 3093230 }
		  },
		  {
			{ 16650921, -11037932, -1064178, 1570629, -8329746, 7352753, -302424, 16271225, -24049421, -6691850 },
			{ -21911077, -5927941, -4611316, -5560156, -31744103, -10785293, 24123614, 15193618, -21652117, -16739389 },
			{ -9935934, -4289447, -25279823, 4372842, 2087473, 10399484, 31870908, 14690798, 17361620, 11864968 }
		  },
		  {
			{ -11307610, 6210372, 13206574, 5806320, -29017692, -13967200, -12331205, -7486601, -25578460, -16240689 },
			{ 14668462, -12270235, 26039039, 15305210, 25515617, 4542480, 10453892, 6577524, 9145645, -6443880 },
			{ 5974874, 3053895, -9433049, -10385191, -31865124, 3225009, -7972642, 3936128, -5652273, -3050304 }
		  },
		  {
			{ 30625386, -4729400, -25555961, -12792866, -20484575, 7695099, 17097188, -16303496, -27999779, 1803632 },
			{ -3553091, 9865099, -5228566, 4272701, -5673832, -16689700, 14911344, 12196514, -21405489, 7047412 },
			{ 20093277, 9920966, -11138194, -5343857, 13161587, 12044805, -32856851, 4124601, -32343828, -10257566 }
		  },
		  {
			{ -20788824, 14084654, -13531713, 7842147, 19119038, -13822605, 4752377, -8714640, -21679658, 2288038 },
			{ -26819236, -3283715, 29965059, 3039786, -14473765, 2540457, 29457502, 14625692, -24819617, 12570232 },
			{ -1063558, -11551823, 16920318, 12494842, 1278292, -5869109, -21159943, -3498680, -11974704, 4724943 }
		  },
		  {
			{ 17960970, -11775534, -4140968, -9702530, -8876562, -1410617, -12907383, -8659932, -29576300, 1903856 },
			{ 23134274, -14279132, -10681997, -1611936, 20684485, 15770816, -12989750, 3190296, 26955097, 14109738 },
			{ 15308788, 5320727, -30113809, -14318877, 22902008, 7767164, 29425325, -11277562, 31960942, 11934971 }
		  },
		  {
			{ -27395711, 8435796, 4109644, 12222639, -24627868, 14818669, 20638173, 4875028, 10491392, 1379718 },
			{ -13159415, 9197841, 3875503, -8936108, -1383712, -5879801, 33518459, 16176658, 21432314, 12180697 },
			{ -11787308, 11500838, 13787581, -13832590, -22430679, 10140205, 1465425, 12689540, -10301319, -13872883 }
		  }
		},
		{ // 9/31
		  {
			{ 5414091, -15386041, -21007664, 9643570, 12834970, 1186149, -2622916, -1342231, 26128231, 6032912 },
			{ -26337395, -13766162, 32496025, -13653919, 17847801, -12669156, 3604025, 8316894, -25875034, -10437358 },
			{ 3296484, 6223048, 24680646, -12246460, -23052020, 5903205, -8862297, -4639164, 12376617, 3188849 }
		  },
		  {
			{ 29190488, -14659046, 27549113, -1183516, 3520066, -10697301, 32049515, -7309113, -16109234, -9852307 },
			{ -14744486, -9309156, 735818, -598978, -20407687, -5057904, 25246078, -15795669, 18640741, -960977 },
			{ -6928835, -16430795, 10361374, 5642961, 4910474, 12345252, -31638386, -494430, 10530747, 1053335 }
		  },
		  {
			{ -29265967, -14186805, -13538216, -12117373, -19457059, -10655384, -31462369, -2948985, 24018831, 15026644 },
			{ -22592535, -3145277, -2289276, 5953843, -13440189, 9425631, 25310643, 13003497, -2314791, -15145616 },
			{ -27419985, -603321, -8043984, -1669117, -26092265, 13987819, -27297622, 187899, -23166419, -2531735 }
		  },
		  {
			{ -21744398, -13810475, 1844840, 5021428, -10434399, -15911473, 9716667, 16266922, -5070217, 726099 },
			{ 29370922, -6053998, 7334071, -15342259, 9385287, 2247707, -13661962, -4839461, 30007388, -15823341 },
			{ -936379, 16086691, 23751945, -543318, -1167538, -5189036, 9137109, 730663, 9835848, 4555336 }
		  },
		  {
			{ -23376435, 1410446, -22253753, -12899614, 30867635, 15826977, 17693930, 544696, -11985298, 12422646 },
			{ 31117226, -12215734, -13502838, 6561947, -9876867, -12757670, -5118685, -4096706, 29120153, 13924425 },
			{ -17400879, -14233209, 19675799, -2734756, -11006962, -5858820, -9383939, -11317700, 7240931, -237388 }
		  },
		  {
			{ -31361739, -11346780, -15007447, -5856218, -22453340, -12152771, 1222336, 4389483, 3293637, -15551743 },
			{ -16684801, -14444245, 11038544, 11054958, -13801175, -3338533, -24319580, 7733547, 12796905, -6335822 },
			{ -8759414, -10817836, -25418864, 10783769, -30615557, -9746811, -28253339, 3647836, 3222231, -11160462 }
		  },
		  {
			{ 18606113, 1693100, -25448386, -15170272, 4112353, 10045021, 23603893, -2048234, -7550776, 2484985 },
			{ 9255317, -3131197, -12156162, -1004256, 13098013, -9214866, 16377220, -2102812, -19802075, -3034702 },
			{ -22729289, 7496160, -5742199, 11329249, 19991973, -3347502, -31718148, 9936966, -30097688, -10618797 }
		  },
		  {
			{ 21878590, -5001297, 4338336, 13643897, -3036865, 13160960, 19708896, 5415497, -7360503, -4109293 },
			{ 27736861, 10103576, 12500508, 8502413, -3413016, -9633558, 10436918, -1550276, -23659143, -8132100 },
			{ 19492550, -12104365, -29681976, -852630, -3208171, 12403437, 30066266, 8367329, 13243957, 8709688 }
		  }
		},
		{ // 10/31
		  {
			{ 12015105, 2801261, 28198131, 10151021, 24818120, -4743133, -11194191, -5645734, 5150968, 7274186 },
			{ 2831366, -12492146, 1478975, 6122054, 23825128, -12733586, 31097299, 6083058, 31021603, -9793610 },
			{ -2529932, -2229646, 445613, 10720828, -13849527, -11505937, -23507731, 16354465, 15067285, -14147707 }
		  },
		  {
			{ 7840942, 14037873, -33364863, 15934016, -728213, -3642706, 21403988, 1057586, -19379462, -12403220 },
			{ 915865, -16469274, 15608285, -8789130, -24357026, 6060030, -17371319, 8410997, -7220461, 16527025 },
			{ 32922597, -556987, 20336074, -16184568, 10903705, -5384487, 16957574, 52992, 23834301, 6588044 }
		  },
		  {
			{ 32752030, 11232950, 3381995, -8714866, 22652988, -10744103, 17159699, 16689107, -20314580, -1305992 },
			{ -4689649, 9166776, -25710296, -10847306, 11576752, 12733943, 7924251, -2752281, 1976123, -7249027 },
			{ 21251222, 16309901, -2983015, -6783122, 30810597, 12967303, 156041, -3371252, 12331345, -8237197 }
		  },
		  {
			{ 8651614, -4477032, -16085636, -4996994, 13002507, 2950805, 29054427, -5106970, 10008136, -4667901 },
			{ 31486080, 15114593, -14261250, 12951354, 14369431, -7387845, 16347321, -13662089, 8684155, -10532952 },
			{ 19443825, 11385320, 24468943, -9659068, -23919258, 2187569, -26263207, -6086921, 31316348, 14219878 }
		  },
		  {
			{ -28594490, 1193785, 32245219, 11392485, 31092169, 15722801, 27146014, 6992409, 29126555, 9207390 },
			{ 32382935, 1110093, 18477781, 11028262, -27411763, -7548111, -4980517, 10843782, -7957600, -14435730 },
			{ 2814918, 7836403, 27519878, -7868156, -20894015, -11553689, -21494559, 8550130, 28346258, 1994730 }
		  },
		  {
			{ -19578299, 8085545, -14000519, -3948622, 2785838, -16231307, -19516951, 7174894, 22628102, 8115180 },
			{ -30405132, 955511, -11133838, -15078069, -32447087, -13278079, -25651578, 3317160, -9943017, 930272 },
			{ -15303681, -6833769, 28856490, 1357446, 23421993, 1057177, 24091212, -1388970, -22765376, -10650715 }
		  },
		  {
			{ -22751231, -5303997, -12907607, -12768866, -15811511, -7797053, -14839018, -16554220, -1867018, 8398970 },
			{ -31969310, 2106403, -4736360, 1362501, 12813763, 16200670, 22981545, -6291273, 18009408, -15772772 },
			{ -17220923, -9545221, -27784654, 14166835, 29815394, 7444469, 29551787, -3727419, 19288549, 1325865 }
		  },
		  {
			{ 15100157, -15835752, -23923978, -1005098, -26450192, 15509408, 12376730, -3479146, 33166107, -8042750 },
			{ 20909231, 13023121, -9209752, 16251778, -5778415, -8094914, 12412151, 10018715, 2213263, -13878373 },
			{ 32529814, -11074689, 30361439, -16689753, -9135940, 1513226, 22922121, 6382134, -5766928, 8371348 }
		  }
		},
		{ // 11/31
		  {
			{ 9923462, 11271500, 12616794, 3544722, -29998368, -1721626, 12891687, -8193132, -26442943, 10486144 },
			{ -22597207, -7012665, 8587003, -8257861, 4084309, -12970062, 361726, 2610596, -23921530, -11455195 },
			{ 5408411, -1136691, -4969122, 10561668, 24145918, 14240566, 31319731, -4235541, 19985175, -3436086 }
		  },
		  {
			{ -13994457, 16616821, 14549246, 3341099, 32155958, 13648976, -17577068, 8849297, 65030, 8370684 },
			{ -8320926, -12049626, 31204563, 5839400, -20627288, -1057277, -19442942, 6922164, 12743482, -9800518 },
			{ -2361371, 12678785, 28815050, 4759974, -23893047, 4884717, 23783145, 11038569, 18800704, 255233 }
		  },
		  {
			{ -5269658, -1773886, 13957886, 7990715, 23132995, 728773, 13393847, 9066957, 19258688, -14753793 },
			{ -2936654, -10827535, -10432089, 14516793, -3640786, 4372541, -31934921, 2209390, -1524053, 2055794 },
			{ 580882, 16705327, 5468415, -2683018, -30926419, -14696000, -7203346, -8994389, -30021019, 7394435 }
		  },
		  {
			{ 23838809, 1822728, -15738443, 15242727, 8318092, -3733104, -21672180, -3492205, -4821741, 14799921 },
			{ 13345610, 9759151, 3371034, -16137791, 16353039, 8577942, 31129804, 13496856, -9056018, 7402518 },
			{ 2286874, -4435931, -20042458, -2008336, -13696227, 5038122, 11006906, -15760352, 8205061, 1607563 }
		  },
		  {
			{ 14414086, -8002132, 3331830, -3208217, 22249151, -5594188, 18364661, -2906958, 30019587, -9029278 },
			{ -27688051, 1585953, -10775053, 931069, -29120221, -11002319, -14410829, 12029093, 9944378, 8024 },
			{ 4368715, -3709630, 29874200, -15022983, -20230386, -11410704, -16114594, -999085, -8142388, 5640030 }
		  },
		  {
			{ 10299610, 13746483, 11661824, 16234854, 7630238, 5998374, 9809887, -16694564, 15219798, -14327783 },
			{ 27425505, -5719081, 3055006, 10660664, 23458024, 595578, -15398605, -1173195, -18342183, 9742717 },
			{ 6744077, 2427284, 26042789, 2720740, -847906, 1118974, 32324614, 7406442, 12420155, 1994844 }
		  },
		  {
			{ 14012521, -5024720, -18384453, -9578469, -26485342, -3936439, -13033478, -10909803, 24319929, -6446333 },
			{ 16412690, -4507367, 10772641, 15929391, -17068788, -4658621, 10555945, -10484049, -30102368, -4739048 },
			{ 22397382, -7767684, -9293161, -12792868, 17166287, -9755136, -27333065, 6199366, 21880021, -12250760 }
		  },
		  {
			{ -4283307, 5368523, -31117018, 8163389, -30323063, 3209128, 16557151, 8890729, 8840445, 4957760 },
			{ -15447727, 709327, -6919446, -10870178, -29777922, 6522332, -21720181, 12130072, -14796503, 5005757 },
			{ -2114751, -14308128, 23019042, 15765735, -25269683, 6002752, 10183197, -13239326, -16395286, -2176112 }
		  }
		},
		{ // 12/31
		  {
			{ -19025756, 1632005, 13466291, -7995100, -23640451, 16573537, -32013908, -3057104, 22208662, 2000468 },
			{ 3065073, -1412761, -25598674, -361432, -17683065, -5703415, -8164212, 11248527, -3691214, -7414184 },
			{ 10379208, -6045554, 8877319, 1473647, -29291284, -12507580, 16690915, 2553332, -3132688, 16400289 }
		  },
		  {
			{ 15716668, 1254266, -18472690, 7446274, -8448918, 6344164, -22097271, -7285580, 26894937, 9132066 },
			{ 24158887, 12938817, 11085297, -8177598, -28063478, -4457083, -30576463, 64452, -6817084, -2692882 },
			{ 13488534, 7794716, 22236231, 5989356, 25426474, -12578208, 2350710, -3418511, -4688006, 2364226 }
		  },
		  {
			{ 16335052, 9132434, 25640582, 6678888, 1725628, 8517937, -11807024, -11697457, 15445875, -7798101 },
			{ 29004207, -7867081, 28661402, -640412, -12794003, -7943086, 31863255, -4135540, -278050, -15759279 },
			{ -6122061, -14866665, -28614905, 14569919, -10857999, -3591829, 10343412, -6976290, -29828287, -10815811 }
		  },
		  {
			{ 27081650, 3463984, 14099042, -4517604, 1616303, -6205604, 29542636, 15372179, 17293797, 960709 },
			{ 20263915, 11434237, -5765435, 11236810, 13505955, -10857102, -16111345, 6493122, -19384511, 7639714 },
			{ -2830798, -14839232, 25403038, -8215196, -8317012, -16173699, 18006287, -16043750, 29994677, -15808121 }
		  },
		  {
			{ 9769828, 5202651, -24157398, -13631392, -28051003, -11561624, -24613141, -13860782, -31184575, 709464 },
			{ 12286395, 13076066, -21775189, -1176622, -25003198, 4057652, -32018128, -8890874, 16102007, 13205847 },
			{ 13733362, 5599946, 10557076, 3195751, -5557991, 8536970, -25540170, 8525972, 10151379, 10394400 }
		  },
		  {
			{ 4024660, -16137551, 22436262, 12276534, -9099015, -2686099, 19698229, 11743039, -33302334, 8934414 },
			{ -15879800, -4525240, -8580747, -2934061, 14634845, -698278, -9449077, 3137094, -11536886, 11721158 },
			{ 17555939, -5013938, 8268606, 2331751, -22738815, 9761013, 9319229, 8835153, -9205489, -1280045 }
		  },
		  {
			{ -461409, -7830014, 20614118, 16688288, -7514766, -4807119, 22300304, 505429, 6108462, -6183415 },
			{ -5070281, 12367917, -30663534, 3234473, 32617080, -8422642, 29880583, -13483331, -26898490, -7867459 },
			{ -31975283, 5726539, 26934134, 10237677, -3173717, -605053, 24199304, 3795095, 7592688, -14992079 }
		  },
		  {
			{ 21594432, -14964228, 17466408, -4077222, 32537084, 2739898, 6407723, 12018833, -28256052, 4298412 },
			{ -20650503, -11961496, -27236275, 570498, 3767144, -1717540, 13891942, -1569194, 13717174, 10805743 },
			{ -14676630, -15644296, 15287174, 11927123, 24177847, -8175568, -796431, 14860609, -26938930, -5863836 }
		  }
		},
		{ // 13/31
		  {
			{ 12962541, 5311799, -10060768, 11658280, 18855286, -7954201, 13286263, -12808704, -4381056, 9882022 },
			{ 18512079, 11319350, -20123124, 15090309, 18818594, 5271736, -22727904, 3666879, -23967430, -3299429 },
			{ -6789020, -3146043, 16192429, 13241070, 15898607, -14206114, -10084880, -6661110, -2403099, 5276065 }
		  },
		  {
			{ 30169808, -5317648, 26306206, -11750859, 27814964, 7069267, 7152851, 3684982, 1449224, 13082861 },
			{ 10342826, 3098505, 2119311, 193222, 25702612, 12233820, 23697382, 15056736, -21016438, -8202000 },
			{ -33150110, 3261608, 22745853, 7948688, 19370557, -15177665, -26171976, 6482814, -10300080, -11060101 }
		  },
		  {
			{ 32869458, -5408545, 25609743, 15678670, -10687769, -15471071, 26112421, 2521008, -22664288, 6904815 },
			{ 29506923, 4457497, 3377935, -9796444, -30510046, 12935080, 1561737, 3841096, -29003639, -6657642 },
			{ 10340844, -6630377, -18656632, -2278430, 12621151, -13339055, 30878497, -11824370, -25584551, 5181966 }
		  },
		  {
			{ 25940115, -12658025, 17324188, -10307374, -8671468, 15029094, 24396252, -16450922, -2322852, -12388574 },
			{ -21765684, 9916823, -1300409, 4079498, -1028346, 11909559, 1782390, 12641087, 20603771, -6561742 },
			{ -18882287, -11673380, 24849422, 11501709, 13161720, -4768874, 1925523, 11914390, 4662781, 7820689 }
		  },
		  {
			{ 12241050, -425982, 8132691, 9393934, 32846760, -1599620, 29749456, 12172924, 16136752, 15264020 },
			{ -10349955, -14680563, -8211979, 2330220, -17662549, -14545780, 10658213, 6671822, 19012087, 3772772 },
			{ 3753511, -3421066, 10617074, 2028709, 14841030, -6721664, 28718732, -15762884, 20527771, 12988982 }
		  },
		  {
			{ -14822485, -5797269, -3707987, 12689773, -898983, -10914866, -24183046, -10564943, 3299665, -12424953 },
			{ -16777703, -15253301, -9642417, 4978983, 3308785, 8755439, 6943197, 6461331, -25583147, 8991218 },
			{ -17226263, 1816362, -1673288, -6086439, 31783888, -8175991, -32948145, 7417950, -30242287, 1507265 }
		  },
		  {
			{ 29692663, 6829891, -10498800, 4334896, 20945975, -11906496, -28887608, 8209391, 14606362, -10647073 },
			{ -3481570, 8707081, 32188102, 5672294, 22096700, 1711240, -33020695, 9761487, 4170404, -2085325 },
			{ -11587470, 14855945, -4127778, -1531857, -26649089, 15084046, 22186522, 16002000, -14276837, -8400798 }
		  },
		  {
			{ -4811456, 13761029, -31703877, -2483919, -3312471, 7869047, -7113572, -9620092, 13240845, 10965870 },
			{ -7742563, -8256762, -14768334, -13656260, -23232383, 12387166, 4498947, 14147411, 29514390, 4302863 },
			{ -13413405, -12407859, 20757302, -13801832, 14785143, 8976368, -5061276, -2144373, 17846988, -13971927 }
		  }
		},
		{ // 14/31
		  {
			{ -2244452, -754728, -4597030, -1066309, -6247172, 1455299, -21647728, -9214789, -5222701, 12650267 },
			{ -9906797, -16070310, 21134160, 12198166, -27064575, 708126, 387813, 13770293, -19134326, 10958663 },
			{ 22470984, 12369526, 23446014, -5441109, -21520802, -9698723, -11772496, -11574455, -25083830, 4271862 }
		  },
		  {
			{ -25169565, -10053642, -19909332, 15361595, -5984358, 2159192, 75375, -4278529, -32526221, 8469673 },
			{ 15854970, 4148314, -8893890, 7259002, 11666551, 13824734, -30531198, 2697372, 24154791, -9460943 },
			{ 15446137, -15806644, 29759747, 14019369, 30811221, -9610191, -31582008, 12840104, 24913809, 9815020 }
		  },
		  {
			{ -4709286, -5614269, -31841498, -12288893, -14443537, 10799414, -9103676, 13438769, 18735128, 9466238 },
			{ 11933045, 9281483, 5081055, -5183824, -2628162, -4905629, -7727821, -10896103, -22728655, 16199064 },
			{ 14576810, 379472, -26786533, -8317236, -29426508, -10812974, -102766, 1876699, 30801119, 2164795 }
		  },
		  {
			{ 15995086, 3199873, 13672555, 13712240, -19378835, -4647646, -13081610, -15496269, -13492807, 1268052 },
			{ -10290614, -3659039, -3286592, 10948818, 23037027, 3794475, -3470338, -12600221, -17055369, 3565904 },
			{ 29210088, -9419337, -5919792, -4952785, 10834811, -13327726, -16512102, -10820713, -27162222, -14030531 }
		  },
		  {
			{ -13161890, 15508588, 16663704, -8156150, -28349942, 9019123, -29183421, -3769423, 2244111, -14001979 },
			{ -5152875, -3800936, -9306475, -6071583, 16243069, 14684434, -25673088, -16180800, 13491506, 4641841 },
			{ 10813417, 643330, -19188515, -728916, 30292062, -16600078, 27548447, -7721242, 14476989, -12767431 }
		  },
		  {
			{ 10292079, 9984945, 6481436, 8279905, -7251514, 7032743, 27282937, -1644259, -27912810, 12651324 },
			{ -31185513, -813383, 22271204, 11835308, 10201545, 15351028, 17099662, 3988035, 21721536, -3148940 },
			{ 10202177, -6545839, -31373232, -9574638, -32150642, -8119683, -12906320, 3852694, 13216206, 14842320 }
		  },
		  {
			{ -15815640, -10601066, -6538952, -7258995, -6984659, -6581778, -31500847, 13765824, -27434397, 9900184 },
			{ 14465505, -13833331, -32133984, -14738873, -27443187, 12990492, 33046193, 15796406, -7051866, -8040114 },
			{ 30924417, -8279620, 6359016, -12816335, 16508377, 9071735, -25488601, 15413635, 9524356, -7018878 }
		  },
		  {
			{ 12274201, -13175547, 32627641, -1785326, 6736625, 13267305, 5237659, -5109483, 15663516, 4035784 },
			{ -2951309, 8903985, 17349946, 601635, -16432815, -4612556, -13732739, -15889334, -22258478, 4659091 },
			{ -16916263, -4952973, -30393711, -15158821, 20774812, 15897498, 5736189, 15026997, -2178256, -13455585 }
		  }
		},
		{ // 15/31
		  {
			{ -8858980, -2219056, 28571666, -10155518, -474467, -10105698, -3801496, 278095, 23440562, -290208 },
			{ 10226241, -5928702, 15139956, 120818, -14867693, 5218603, 32937275, 11551483, -16571960, -7442864 },
			{ 17932739, -12437276, -24039557, 10749060, 11316803, 7535897, 22503767, 5561594, -3646624, 3898661 }
		  },
		  {
			{ 7749907, -969567, -16339731, -16464, -25018111, 15122143, -1573531, 7152530, 21831162, 1245233 },
			{ 26958459, -14658026, 4314586, 8346991, -5677764, 11960072, -32589295, -620035, -30402091, -16716212 },
			{ -12165896, 9166947, 33491384, 13673479, 29787085, 13096535, 6280834, 14587357, -22338025, 13987525 }
		  },
		  {
			{ -24349909, 7778775, 21116000, 15572597, -4833266, -5357778, -4300898, -5124639, -7469781, -2858068 },
			{ 9681908, -6737123, -31951644, 13591838, -6883821, 386950, 31622781, 6439245, -14581012, 4091397 },
			{ -8426427, 1470727, -28109679, -1596990, 3978627, -5123623, -19622683, 12092163, 29077877, -14741988 }
		  },
		  {
			{ 5269168, -6859726, -13230211, -8020715, 25932563, 1763552, -5606110, -5505881, -20017847, 2357889 },
			{ 32264008, -15407652, -5387735, -1160093, -2091322, -3946900, 23104804, -12869908, 5727338, 189038 },
			{ 14609123, -8954470, -6000566, -16622781, -14577387, -7743898, -26745169, 10942115, -25888931, -14884697 }
		  },
		  {
			{ 20513500, 5557931, -15604613, 7829531, 26413943, -2019404, -21378968, 7471781, 13913677, -5137875 },
			{ -25574376, 11967826, 29233242, 12948236, -6754465, 4713227, -8940970, 14059180, 12878652, 8511905 },
			{ -25656801, 3393631, -2955415, -7075526, -2250709, 9366908, -30223418, 6812974, 5568676, -3127656 }
		  },
		  {
			{ 11630004, 12144454, 2116339, 13606037, 27378885, 15676917, -17408753, -13504373, -14395196, 8070818 },
			{ 27117696, -10007378, -31282771, -5570088, 1127282, 12772488, -29845906, 10483306, -11552749, -1028714 },
			{ 10637467, -5688064, 5674781, 1072708, -26343588, -6982302, -1683975, 9177853, -27493162, 15431203 }
		  },
		  {
			{ 20525145, 10892566, -12742472, 12779443, -29493034, 16150075, -28240519, 14943142, -15056790, -7935931 },
			{ -30024462, 5626926, -551567, -9981087, 753598, 11981191, 25244767, -3239766, -3356550, 9594024 },
			{ -23752644, 2636870, -5163910, -10103818, 585134, 7877383, 11345683, -6492290, 13352335, -10977084 }
		  },
		  {
			{ -1931799, -5407458, 3304649, -12884869, 17015806, -4877091, -29783850, -7752482, -13215537, -319204 },
			{ 20239939, 6607058, 6203985, 3483793, -18386976, -779229, -20723742, 15077870, -22750759, 14523817 },
			{ 27406042, -6041657, 27423596, -4497394, 4996214, 10002360, -28842031, -4545494, -30172742, -4805667 }
		  }
		},
		{ // 16/31
		  {
			{ 11374242, 12660715, 17861383, -12540833, 10935568, 1099227, -13886076, -9091740, -27727044, 11358504 },
			{ -12730809, 10311867, 1510375, 10778093, -2119455, -9145702, 32676003, 11149336, -26123651, 4985768 },
			{ -19096303, 341147, -6197485, -239033, 15756973, -8796662, -983043, 13794114, -19414307, -15621255 }
		  },
		  {
			{ 6490081, 11940286, 25495923, -7726360, 8668373, -8751316, 3367603, 6970005, -1691065, -9004790 },
			{ 1656497, 13457317, 15370807, 6364910, 13605745, 8362338, -19174622, -5475723, -16796596, -5031438 },
			{ -22273315, -13524424, -64685, -4334223, -18605636, -10921968, -20571065, -7007978, -99853, -10237333 }
		  },
		  {
			{ 17747465, 10039260, 19368299, -4050591, -20630635, -16041286, 31992683, -15857976, -29260363, -5511971 },
			{ 31932027, -4986141, -19612382, 16366580, 22023614, 88450, 11371999, -3744247, 4882242, -10626905 },
			{ 29796507, 37186, 19818052, 10115756, -11829032, 3352736, 18551198, 3272828, -5190932, -4162409 }
		  },
		  {
			{ 12501286, 4044383, -8612957, -13392385, -32430052, 5136599, -19230378, -3529697, 330070, -3659409 },
			{ 6384877, 2899513, 17807477, 7663917, -2358888, 12363165, 25366522, -8573892, -271295, 12071499 },
			{ -8365515, -4042521, 25133448, -4517355, -6211027, 2265927, -32769618, 1936675, -5159697, 3829363 }
		  },
		  {
			{ 28425966, -5835433, -577090, -4697198, -14217555, 6870930, 7921550, -6567787, 26333140, 14267664 },
			{ -11067219, 11871231, 27385719, -10559544, -4585914, -11189312, 10004786, -8709488, -21761224, 8930324 },
			{ -21197785, -16396035, 25654216, -1725397, 12282012, 11008919, 1541940, 4757911, -26491501, -16408940 }
		  },
		  {
			{ 13537262, -7759490, -20604840, 10961927, -5922820, -13218065, -13156584, 6217254, -15943699, 13814990 },
			{ -17422573, 15157790, 18705543, 29619, 24409717, -260476, 27361681, 9257833, -1956526, -1776914 },
			{ -25045300, -10191966, 15366585, 15166509, -13105086, 8423556, -29171540, 12361135, -18685978, 4578290 }
		  },
		  {
			{ 24579768, 3711570, 1342322, -11180126, -27005135, 14124956, -22544529, 14074919, 21964432, 8235257 },
			{ -6528613, -2411497, 9442966, -5925588, 12025640, -1487420, -2981514, -1669206, 13006806, 2355433 },
			{ -16304899, -13605259, -6632427, -5142349, 16974359, -10911083, 27202044, 1719366, 1141648, -12796236 }
		  },
		  {
			{ -12863944, -13219986, -8318266, -11018091, -6810145, -4843894, 13475066, -3133972, 32674895, 13715045 },
			{ 11423335, -5468059, 32344216, 8962751, 24989809, 9241752, -13265253, 16086212, -28740881, -15642093 },
			{ -1409668, 12530728, -6368726, 10847387, 19531186, -14132160, -11709148, 7791794, -27245943, 4383347 }
		  }
		},
		{ // 17/31
		  {
			{ -28970898, 5271447, -1266009, -9736989, -12455236, 16732599, -4862407, -4906449, 27193557, 6245191 },
			{ -15193956, 5362278, -1783893, 2695834, 4960227, 12840725, 23061898, 3260492, 22510453, 8577507 },
			{ -12632451, 11257346, -32692994, 13548177, -721004, 10879011, 31168030, 13952092, -29571492, -3635906 }
		  },
		  {
			{ 3877321, -9572739, 32416692, 5405324, -11004407, -13656635, 3759769, 11935320, 5611860, 8164018 },
			{ -16275802, 14667797, 15906460, 12155291, -22111149, -9039718, 32003002, -8832289, 5773085, -8422109 },
			{ -23788118, -8254300, 1950875, 8937633, 18686727, 16459170, -905725, 12376320, 31632953, 190926 }
		  },
		  {
			{ -24593607, -16138885, -8423991, 13378746, 14162407, 6901328, -8288749, 4508564, -25341555, -3627528 },
			{ 8884438, -5884009, 6023974, 10104341, -6881569, -4941533, 18722941, -14786005, -1672488, 827625 },
			{ -32720583, -16289296, -32503547, 7101210, 13354605, 2659080, -1800575, -14108036, -24878478, 1541286 }
		  },
		  {
			{ 2901347, -1117687, 3880376, -10059388, -17620940, -3612781, -21802117, -3567481, 20456845, -1885033 },
			{ 27019610, 12299467, -13658288, -1603234, -12861660, -4861471, -19540150, -5016058, 29439641, 15138866 },
			{ 21536104, -6626420, -32447818, -10690208, -22408077, 5175814, -5420040, -16361163, 7779328, 109896 }
		  },
		  {
			{ 30279744, 14648750, -8044871, 6425558, 13639621, -743509, 28698390, 12180118, 23177719, -554075 },
			{ 26572847, 3405927, -31701700, 12890905, -19265668, 5335866, -6493768, 2378492, 4439158, -13279347 },
			{ -22716706, 3489070, -9225266, -332753, 18875722, -1140095, 14819434, -12731527, -17717757, -5461437 }
		  },
		  {
			{ -5056483, 16566551, 15953661, 3767752, -10436499, 15627060, -820954, 2177225, 8550082, -15114165 },
			{ -18473302, 16596775, -381660, 15663611, 22860960, 15585581, -27844109, -3582739, -23260460, -8428588 },
			{ -32480551, 15707275, -8205912, -5652081, 29464558, 2713815, -22725137, 15860482, -21902570, 1494193 }
		  },
		  {
			{ -19562091, -14087393, -25583872, -9299552, 13127842, 759709, 21923482, 16529112, 8742704, 12967017 },
			{ -28464899, 1553205, 32536856, -10473729, -24691605, -406174, -8914625, -2933896, -29903758, 15553883 },
			{ 21877909, 3230008, 9881174, 10539357, -4797115, 2841332, 11543572, 14513274, 19375923, -12647961 }
		  },
		  {
			{ 8832269, -14495485, 13253511, 5137575, 5037871, 4078777, 24880818, -6222716, 2862653, 9455043 },
			{ 29306751, 5123106, 20245049, -14149889, 9592566, 8447059, -2077124, -2990080, 15511449, 4789663 },
			{ -20679756, 7004547, 8824831, -9434977, -4045704, -3750736, -5754762, 108893, 23513200, 16652362 }
		  }
		},
		{ // 18/31
		  {
			{ -33256173, 4144782, -4476029, -6579123, 10770039, -7155542, -6650416, -12936300, -18319198, 10212860 },
			{ 2756081, 8598110, 7383731, -6859892, 22312759, -1105012, 21179801, 2600940, -9988298, -12506466 },
			{ -24645692, 13317462, -30449259, -15653928, 21365574, -10869657, 11344424, 864440, -2499677, -16710063 }
		  },
		  {
			{ -26432803, 6148329, -17184412, -14474154, 18782929, -275997, -22561534, 211300, 2719757, 4940997 },
			{ -1323882, 3911313, -6948744, 14759765, -30027150, 7851207, 21690126, 8518463, 26699843, 5276295 },
			{ -13149873, -6429067, 9396249, 365013, 24703301, -10488939, 1321586, 149635, -15452774, 7159369 }
		  },
		  {
			{ 9987780, -3404759, 17507962, 9505530, 9731535, -2165514, 22356009, 8312176, 22477218, -8403385 },
			{ 18155857, -16504990, 19744716, 9006923, 15154154, -10538976, 24256460, -4864995, -22548173, 9334109 },
			{ 2986088, -4911893, 10776628, -3473844, 10620590, -7083203, -21413845, 14253545, -22587149, 536906 }
		  },
		  {
			{ 4377756, 8115836, 24567078, 15495314, 11625074, 13064599, 7390551, 10589625, 10838060, -15420424 },
			{ -19342404, 867880, 9277171, -3218459, -14431572, -1986443, 19295826, -15796950, 6378260, 699185 },
			{ 7895026, 4057113, -7081772, -13077756, -17886831, -323126, -716039, 15693155, -5045064, -13373962 }
		  },
		  {
			{ -7737563, -5869402, -14566319, -7406919, 11385654, 13201616, 31730678, -10962840, -3918636, -9669325 },
			{ 10188286, -15770834, -7336361, 13427543, 22223443, 14896287, 30743455, 7116568, -21786507, 5427593 },
			{ 696102, 13206899, 27047647, -10632082, 15285305, -9853179, 10798490, -4578720, 19236243, 12477404 }
		  },
		  {
			{ -11229439, 11243796, -17054270, -8040865, -788228, -8167967, -3897669, 11180504, -23169516, 7733644 },
			{ 17800790, -14036179, -27000429, -11766671, 23887827, 3149671, 23466177, -10538171, 10322027, 15313801 },
			{ 26246234, 11968874, 32263343, -5468728, 6830755, -13323031, -15794704, -101982, -24449242, 10890804 }
		  },
		  {
			{ -31365647, 10271363, -12660625, -6267268, 16690207, -13062544, -14982212, 16484931, 25180797, -5334884 },
			{ -586574, 10376444, -32586414, -11286356, 19801893, 10997610, 2276632, 9482883, 316878, 13820577 },
			{ -9882808, -4510367, -2115506, 16457136, -11100081, 11674996, 30756178, -7515054, 30696930, -3712849 }
		  },
		  {
			{ 32988917, -9603412, 12499366, 7910787, -10617257, -11931514, -7342816, -9985397, -32349517, 7392473 },
			{ -8855661, 15927861, 9866406, -3649411, -2396914, -16655781, -30409476, -9134995, 25112947, -2926644 },
			{ -2504044, -436966, 25621774, -5678772, 15085042, -5479877, -24884878, -13526194, 5537438, -13914319 }
		  }
		},
		{ // 19/31
		  {
			{ -11225584, 2320285, -9584280, 10149187, -33444663, 5808648, -14876251, -1729667, 31234590, 6090599 },
			{ -9633316, 116426, 26083934, 2897444, -6364437, -2688086, 609721, 15878753, -6970405, -9034768 },
			{ -27757857, 247744, -15194774, -9002551, 23288161, -10011936, -23869595, 6503646, 20650474, 1804084 }
		  },
		  {
			{ -27589786, 15456424, 8972517, 8469608, 15640622, 4439847, 3121995, -10329713, 27842616, -202328 },
			{ -15306973, 2839644, 22530074, 10026331, 4602058, 5048462, 28248656, 5031932, -11375082, 12714369 },
			{ 20807691, -7270825, 29286141, 11421711, -27876523, -13868230, -21227475, 1035546, -19733229, 12796920 }
		  },
		  {
			{ 12076899, -14301286, -8785001, -11848922, -25012791, 16400684, -17591495, -12899438, 3480665, -15182815 },
			{ -32361549, 5457597, 28548107, 7833186, 7303070, -11953545, -24363064, -15921875, -33374054, 2771025 },
			{ -21389266, 421932, 26597266, 6860826, 22486084, -6737172, -17137485, -4210226, -24552282, 15673397 }
		  },
		  {
			{ -20184622, 2338216, 19788685, -9620956, -4001265, -8740893, -20271184, 4733254, 3727144, -12934448 },
			{ 6120119, 814863, -11794402, -622716, 6812205, -15747771, 2019594, 7975683, 31123697, -10958981 },
			{ 30069250, -11435332, 30434654, 2958439, 18399564, -976289, 12296869, 9204260, -16432438, 9648165 }
		  },
		  {
			{ 32705432, -1550977, 30705658, 7451065, -11805606, 9631813, 3305266, 5248604, -26008332, -11377501 },
			{ 17219865, 2375039, -31570947, -5575615, -19459679, 9219903, 294711, 15298639, 2662509, -16297073 },
			{ -1172927, -7558695, -4366770, -4287744, -21346413, -8434326, 32087529, -1222777, 32247248, -14389861 }
		  },
		  {
			{ 14312628, 1221556, 17395390, -8700143, -4945741, -8684635, -28197744, -9637817, -16027623, -13378845 },
			{ -1428825, -9678990, -9235681, 6549687, -7383069, -468664, 23046502, 9803137, 17597934, 2346211 },
			{ 18510800, 15337574, 26171504, 981392, -22241552, 7827556, -23491134, -11323352, 3059833, -11782870 }
		  },
		  {
			{ 10141598, 6082907, 17829293, -1947643, 9830092, 13613136, -25556636, -5544586, -33502212, 3592096 },
			{ 33114168, -15889352, -26525686, -13343397, 33076705, 8716171, 1151462, 1521897, -982665, -6837803 },
			{ -32939165, -4255815, 23947181, -324178, -33072974, -12305637, -16637686, 3891704, 26353178, 693168 }
		  },
		  {
			{ 30374239, 1595580, -16884039, 13186931, 4600344, 406904, 9585294, -400668, 31375464, 14369965 },
			{ -14370654, -7772529, 1510301, 6434173, -18784789, -6262728, 32732230, -13108839, 17901441, 16011505 },
			{ 18171223, -11934626, -12500402, 15197122, -11038147, -15230035, -19172240, -16046376, 8764035, 12309598 }
		  }
		},
		{ // 20/31
		  {
			{ 5975908, -5243188, -19459362, -9681747, -11541277, 14015782, -23665757, 1228319, 17544096, -10593782 },
			{ 5811932, -1715293, 3442887, -2269310, -18367348, -8359541, -18044043, -15410127, -5565381, 12348900 },
			{ -31399660, 11407555, 25755363, 6891399, -3256938, 14872274, -24849353, 8141295, -10632534, -585479 }
		  },
		  {
			{ -12675304, 694026, -5076145, 13300344, 14015258, -14451394, -9698672, -11329050, 30944593, 1130208 },
			{ 8247766, -6710942, -26562381, -7709309, -14401939, -14648910, 4652152, 2488540, 23550156, -271232 },
			{ 17294316, -3788438, 7026748, 15626851, 22990044, 113481, 2267737, -5908146, -408818, -137719 }
		  },
		  {
			{ 16091085, -16253926, 18599252, 7340678, 2137637, -1221657, -3364161, 14550936, 3260525, -7166271 },
			{ -4910104, -13332887, 18550887, 10864893, -16459325, -7291596, -23028869, -13204905, -12748722, 2701326 },
			{ -8574695, 16099415, 4629974, -16340524, -20786213, -6005432, -10018363, 9276971, 11329923, 1862132 }
		  },
		  {
			{ 14763076, -15903608, -30918270, 3689867, 3511892, 10313526, -21951088, 12219231, -9037963, -940300 },
			{ 8894987, -3446094, 6150753, 3013931, 301220, 15693451, -31981216, -2909717, -15438168, 11595570 },
			{ 15214962, 3537601, -26238722, -14058872, 4418657, -15230761, 13947276, 10730794, -13489462, -4363670 }
		  },
		  {
			{ -2538306, 7682793, 32759013, 263109, -29984731, -7955452, -22332124, -10188635, 977108, 699994 },
			{ -12466472, 4195084, -9211532, 550904, -15565337, 12917920, 19118110, -439841, -30534533, -14337913 },
			{ 31788461, -14507657, 4799989, 7372237, 8808585, -14747943, 9408237, -10051775, 12493932, -5409317 }
		  },
		  {
			{ -25680606, 5260744, -19235809, -6284470, -3695942, 16566087, 27218280, 2607121, 29375955, 6024730 },
			{ 842132, -2794693, -4763381, -8722815, 26332018, -12405641, 11831880, 6985184, -9940361, 2854096 },
			{ -4847262, -7969331, 2516242, -5847713, 9695691, -7221186, 16512645, 960770, 12121869, 16648078 }
		  },
		  {
			{ -15218652, 14667096, -13336229, 2013717, 30598287, -464137, -31504922, -7882064, 20237806, 2838411 },
			{ -19288047, 4453152, 15298546, -16178388, 22115043, -15972604, 12544294, -13470457, 1068881, -12499905 },
			{ -9558883, -16518835, 33238498, 13506958, 30505848, -1114596, -8486907, -2630053, 12521378, 4845654 }
		  },
		  {
			{ -28198521, 10744108, -2958380, 10199664, 7759311, -13088600, 3409348, -873400, -6482306, -12885870 },
			{ -23561822, 6230156, -20382013, 10655314, -24040585, -11621172, 10477734, -1240216, -3113227, 13974498 },
			{ 12966261, 15550616, -32038948, -1615346, 21025980, -629444, 5642325, 7188737, 18895762, 12629579 }
		  }
		},
		{ // 21/31
		  {
			{ 14741879, -14946887, 22177208, -11721237, 1279741, 8058600, 11758140, 789443, 32195181, 3895677 },
			{ 10758205, 15755439, -4509950, 9243698, -4879422, 6879879, -2204575, -3566119, -8982069, 4429647 },
			{ -2453894, 15725973, -20436342, -10410672, -5803908, -11040220, -7135870, -11642895, 18047436, -15281743 }
		  },
		  {
			{ -25173001, -11307165, 29759956, 11776784, -22262383, -15820455, 10993114, -12850837, -17620701, -9408468 },
			{ 21987233, 700364, -24505048, 14972008, -7774265, -5718395, 32155026, 2581431, -29958985, 8773375 },
			{ -25568350, 454463, -13211935, 16126715, 25240068, 8594567, 20656846, 12017935, -7874389, -13920155 }
		  },
		  {
			{ 6028182, 6263078, -31011806, -11301710, -818919, 2461772, -31841174, -5468042, -1721788, -2776725 },
			{ -12278994, 16624277, 987579, -5922598, 32908203, 1248608, 7719845, -4166698, 28408820, 6816612 },
			{ -10358094, -8237829, 19549651, -12169222, 22082623, 16147817, 20613181, 13982702, -10339570, 5067943 }
		  },
		  {
			{ -30505967, -3821767, 12074681, 13582412, -19877972, 2443951, -19719286, 12746132, 5331210, -10105944 },
			{ 30528811, 3601899, -1957090, 4619785, -27361822, -15436388, 24180793, -12570394, 27679908, -1648928 },
			{ 9402404, -13957065, 32834043, 10838634, -26580150, -13237195, 26653274, -8685565, 22611444, -12715406 }
		  },
		  {
			{ 22190590, 1118029, 22736441, 15130463, -30460692, -5991321, 19189625, -4648942, 4854859, 6622139 },
			{ -8310738, -2953450, -8262579, -3388049, -10401731, -271929, 13424426, -3567227, 26404409, 13001963 },
			{ -31241838, -15415700, -2994250, 8939346, 11562230, -12840670, -26064365, -11621720, -15405155, 11020693 }
		  },
		  {
			{ 1866042, -7949489, -7898649, -10301010, 12483315, 13477547, 3175636, -12424163, 28761762, 1406734 },
			{ -448555, -1777666, 13018551, 3194501, -9580420, -11161737, 24760585, -4347088, 25577411, -13378680 },
			{ -24290378, 4759345, -690653, -1852816, 2066747, 10693769, -29595790, 9884936, -9368926, 4745410 }
		  },
		  {
			{ -9141284, 6049714, -19531061, -4341411, -31260798, 9944276, -15462008, -11311852, 10931924, -11931931 },
			{ -16561513, 14112680, -8012645, 4817318, -8040464, -11414606, -22853429, 10856641, -20470770, 13434654 },
			{ 22759489, -10073434, -16766264, -1871422, 13637442, -10168091, 1765144, -12654326, 28445307, -5364710 }
		  },
		  {
			{ 29875063, 12493613, 2795536, -3786330, 1710620, 15181182, -10195717, -8788675, 9074234, 1167180 },
			{ -26205683, 11014233, -9842651, -2635485, -26908120, 7532294, -18716888, -9535498, 3843903, 9367684 },
			{ -10969595, -6403711, 9591134, 9582310, 11349256, 108879, 16235123, 8601684, -139197, 4242895 }
		  }
		},
		{ // 22/31
		  {
			{ 22092954, -13191123, -2042793, -11968512, 32186753, -11517388, -6574341, 2470660, -27417366, 16625501 },
			{ -11057722, 3042016, 13770083, -9257922, 584236, -544855, -7770857, 2602725, -27351616, 14247413 },
			{ 6314175, -10264892, -32772502, 15957557, -10157730, 168750, -8618807, 14290061, 27108877, -1180880 }
		  },
		  {
			{ -8586597, -7170966, 13241782, 10960156, -32991015, -13794596, 33547976, -11058889, -27148451, 981874 },
			{ 22833440, 9293594, -32649448, -13618667, -9136966, 14756819, -22928859, -13970780, -10479804, -16197962 },
			{ -7768587, 3326786, -28111797, 10783824, 19178761, 14905060, 22680049, 13906969, -15933690, 3797899 }
		  },
		  {
			{ 21721356, -4212746, -12206123, 9310182, -3882239, -13653110, 23740224, -2709232, 20491983, -8042152 },
			{ 9209270, -15135055, -13256557, -6167798, -731016, 15289673, 25947805, 15286587, 30997318, -6703063 },
			{ 7392032, 16618386, 23946583, -8039892, -13265164, -1533858, -14197445, -2321576, 17649998, -250080 }
		  },
		  {
			{ -9301088, -14193827, 30609526, -3049543, -25175069, -1283752, -15241566, -9525724, -2233253, 7662146 },
			{ -17558673, 1763594, -33114336, 15908610, -30040870, -12174295, 7335080, -8472199, -3174674, 3440183 },
			{ -19889700, -5977008, -24111293, -9688870, 10799743, -16571957, 40450, -4431835, 4862400, 1133 }
		  },
		  {
			{ -32856209, -7873957, -5422389, 14860950, -16319031, 7956142, 7258061, 311861, -30594991, -7379421 },
			{ -3773428, -1565936, 28985340, 7499440, 24445838, 9325937, 29727763, 16527196, 18278453, 15405622 },
			{ -4381906, 8508652, -19898366, -3674424, -5984453, 15149970, -13313598, 843523, -21875062, 13626197 }
		  },
		  {
			{ 2281448, -13487055, -10915418, -2609910, 1879358, 16164207, -10783882, 3953792, 13340839, 15928663 },
			{ 31727126, -7179855, -18437503, -8283652, 2875793, -16390330, -25269894, -7014826, -23452306, 5964753 },
			{ 4100420, -5959452, -17179337, 6017714, -18705837, 12227141, -26684835, 11344144, 2538215, -7570755 }
		  },
		  {
			{ -9433605, 6123113, 11159803, -2156608, 30016280, 14966241, -20474983, 1485421, -629256, -15958862 },
			{ -26804558, 4260919, 11851389, 9658551, -32017107, 16367492, -20205425, -13191288, 11659922, -11115118 },
			{ 26180396, 10015009, -30844224, -8581293, 5418197, 9480663, 2231568, -10170080, 33100372, -1306171 }
		  },
		  {
			{ 15121113, -5201871, -10389905, 15427821, -27509937, -15992507, 21670947, 4486675, -5931810, -14466380 },
			{ 16166486, -9483733, -11104130, 6023908, -31926798, -1364923, 2340060, -16254968, -10735770, -10039824 },
			{ 28042865, -3557089, -12126526, 12259706, -3717498, -6945899, 6766453, -8689599, 18036436, 5803270 }
		  }
		},
		{ // 23/31
		  {
			{ -817581, 6763912, 11803561, 1585585, 10958447, -2671165, 23855391, 4598332, -6159431, -14117438 },
			{ -31031306, -14256194, 17332029, -2383520, 31312682, -5967183, 696309, 50292, -20095739, 11763584 },
			{ -594563, -2514283, -32234153, 12643980, 12650761, 14811489, 665117, -12613632, -19773211, -10713562 }
		  },
		  {
			{ 30464590, -11262872, -4127476, -12734478, 19835327, -7105613, -24396175, 2075773, -17020157, 992471 },
			{ 18357185, -6994433, 7766382, 16342475, -29324918, 411174, 14578841, 8080033, -11574335, -10601610 },
			{ 19598397, 10334610, 12555054, 2555664, 18821899, -10339780, 21873263, 16014234, 26224780, 16452269 }
		  },
		  {
			{ -30223925, 5145196, 5944548, 16385966, 3976735, 2009897, -11377804, -7618186, -20533829, 3698650 },
			{ 14187449, 3448569, -10636236, -10810935, -22663880, -3433596, 7268410, -10890444, 27394301, 12015369 },
			{ 19695761, 16087646, 28032085, 12999827, 6817792, 11427614, 20244189, -1312777, -13259127, -3402461 }
		  },
		  {
			{ 30860103, 12735208, -1888245, -4699734, -16974906, 2256940, -8166013, 12298312, -8550524, -10393462 },
			{ -5719826, -11245325, -1910649, 15569035, 26642876, -7587760, -5789354, -15118654, -4976164, 12651793 },
			{ -2848395, 9953421, 11531313, -5282879, 26895123, -12697089, -13118820, -16517902, 9768698, -2533218 }
		  },
		  {
			{ -24719459, 1894651, -287698, -4704085, 15348719, -8156530, 32767513, 12765450, 4940095, 10678226 },
			{ 18860224, 15980149, -18987240, -1562570, -26233012, -11071856, -7843882, 13944024, -24372348, 16582019 },
			{ -15504260, 4970268, -29893044, 4175593, -20993212, -2199756, -11704054, 15444560, -11003761, 7989037 }
		  },
		  {
			{ 31490452, 5568061, -2412803, 2182383, -32336847, 4531686, -32078269, 6200206, -19686113, -14800171 },
			{ -17308668, -15879940, -31522777, -2831, -32887382, 16375549, 8680158, -16371713, 28550068, -6857132 },
			{ -28126887, -5688091, 16837845, -1820458, -6850681, 12700016, -30039981, 4364038, 1155602, 5988841 }
		  },
		  {
			{ 21890435, -13272907, -12624011, 12154349, -7831873, 15300496, 23148983, -4470481, 24618407, 8283181 },
			{ -33136107, -10512751, 9975416, 6841041, -31559793, 16356536, 3070187, -7025928, 1466169, 10740210 },
			{ -1509399, -15488185, -13503385, -10655916, 32799044, 909394, -13938903, -5779719, -32164649, -15327040 }
		  },
		  {
			{ 3960823, -14267803, -28026090, -15918051, -19404858, 13146868, 15567327, 951507, -3260321, -573935 },
			{ 24740841, 5052253, -30094131, 8961361, 25877428, 6165135, -24368180, 14397372, -7380369, -6144105 },
			{ -28888365, 3510803, -28103278, -1158478, -11238128, -10631454, -15441463, -14453128, -1625486, -6494814 }
		  }
		},
		{ // 24/31
		  {
			{ 793299, -9230478, 8836302, -6235707, -27360908, -2369593, 33152843, -4885251, -9906200, -621852 },
			{ 5666233, 525582, 20782575, -8038419, -24538499, 14657740, 16099374, 1468826, -6171428, -15186581 },
			{ -4859255, -3779343, -2917758, -6748019, 7778750, 11688288, -30404353, -9871238, -1558923, -9863646 }
		  },
		  {
			{ 10896332, -7719704, 824275, 472601, -19460308, 3009587, 25248958, 14783338, -30581476, -15757844 },
			{ 10566929, 12612572, -31944212, 11118703, -12633376, 12362879, 21752402, 8822496, 24003793, 14264025 },
			{ 27713862, -7355973, -11008240, 9227530, 27050101, 2504721, 23886875, -13117525, 13958495, -5732453 }
		  },
		  {
			{ -23481610, 4867226, -27247128, 3900521, 29838369, -8212291, -31889399, -10041781, 7340521, -15410068 },
			{ 4646514, -8011124, -22766023, -11532654, 23184553, 8566613, 31366726, -1381061, -15066784, -10375192 },
			{ -17270517, 12723032, -16993061, 14878794, 21619651, -6197576, 27584817, 3093888, -8843694, 3849921 }
		  },
		  {
			{ -9064912, 2103172, 25561640, -15125738, -5239824, 9582958, 32477045, -9017955, 5002294, -15550259 },
			{ -12057553, -11177906, 21115585, -13365155, 8808712, -12030708, 16489530, 13378448, -25845716, 12741426 },
			{ -5946367, 10645103, -30911586, 15390284, -3286982, -7118677, 24306472, 15852464, 28834118, -7646072 }
		  },
		  {
			{ -17335748, -9107057, -24531279, 9434953, -8472084, -583362, -13090771, 455841, 20461858, 5491305 },
			{ 13669248, -16095482, -12481974, -10203039, -14569770, -11893198, -24995986, 11293807, -28588204, -9421832 },
			{ 28497928, 6272777, -33022994, 14470570, 8906179, -1225630, 18504674, -14165166, 29867745, -8795943 }
		  },
		  {
			{ -16207023, 13517196, -27799630, -13697798, 24009064, -6373891, -6367600, -13175392, 22853429, -4012011 },
			{ 24191378, 16712145, -13931797, 15217831, 14542237, 1646131, 18603514, -11037887, 12876623, -2112447 },
			{ 17902668, 4518229, -411702, -2829247, 26878217, 5258055, -12860753, 608397, 16031844, 3723494 }
		  },
		  {
			{ -28632773, 12763728, -20446446, 7577504, 33001348, -13017745, 17558842, -7872890, 23896954, -4314245 },
			{ -20005381, -12011952, 31520464, 605201, 2543521, 5991821, -2945064, 7229064, -9919646, -8826859 },
			{ 28816045, 298879, -28165016, -15920938, 19000928, -1665890, -12680833, -2949325, -18051778, -2082915 }
		  },
		  {
			{ 16000882, -344896, 3493092, -11447198, -29504595, -13159789, 12577740, 16041268, -19715240, 7847707 },
			{ 10151868, 10572098, 27312476, 7922682, 14825339, 4723128, -32855931, -6519018, -10020567, 3852848 },
			{ -11430470, 15697596, -21121557, -4420647, 5386314, 15063598, 16514493, -15932110, 29330899, -15076224 }
		  }
		},
		{ // 25/31
		  {
			{ -25499735, -4378794, -15222908, -6901211, 16615731, 2051784, 3303702, 15490, -27548796, 12314391 },
			{ 15683520, -6003043, 18109120, -9980648, 15337968, -5997823, -16717435, 15921866, 16103996, -3731215 },
			{ -23169824, -10781249, 13588192, -1628807, -3798557, -1074929, -19273607, 5402699, -29815713, -9841101 }
		  },
		  {
			{ 23190676, 2384583, -32714340, 3462154, -29903655, -1529132, -11266856, 8911517, -25205859, 2739713 },
			{ 21374101, -3554250, -33524649, 9874411, 15377179, 11831242, -33529904, 6134907, 4931255, 11987849 },
			{ -7732, -2978858, -16223486, 7277597, 105524, -322051, -31480539, 13861388, -30076310, 10117930 }
		  },
		  {
			{ -29501170, -10744872, -26163768, 13051539, -25625564, 5089643, -6325503, 6704079, 12890019, 15728940 },
			{ -21972360, -11771379, -951059, -4418840, 14704840, 2695116, 903376, -10428139, 12885167, 8311031 },
			{ -17516482, 5352194, 10384213, -13811658, 7506451, 13453191, 26423267, 4384730, 1888765, -5435404 }
		  },
		  {
			{ -25817338, -3107312, -13494599, -3182506, 30896459, -13921729, -32251644, -12707869, -19464434, -3340243 },
			{ -23607977, -2665774, -526091, 4651136, 5765089, 4618330, 6092245, 14845197, 17151279, -9854116 },
			{ -24830458, -12733720, -15165978, 10367250, -29530908, -265356, 22825805, -7087279, -16866484, 16176525 }
		  },
		  {
			{ -23583256, 6564961, 20063689, 3798228, -4740178, 7359225, 2006182, -10363426, -28746253, -10197509 },
			{ -10626600, -4486402, -13320562, -5125317, 3432136, -6393229, 23632037, -1940610, 32808310, 1099883 },
			{ 15030977, 5768825, -27451236, -2887299, -6427378, -15361371, -15277896, -6809350, 2051441, -15225865 }
		  },
		  {
			{ -3362323, -7239372, 7517890, 9824992, 23555850, 295369, 5148398, -14154188, -22686354, 16633660 },
			{ 4577086, -16752288, 13249841, -15304328, 19958763, -14537274, 18559670, -10759549, 8402478, -9864273 },
			{ -28406330, -1051581, -26790155, -907698, -17212414, -11030789, 9453451, -14980072, 17983010, 9967138 }
		  },
		  {
			{ -25762494, 6524722, 26585488, 9969270, 24709298, 1220360, -1677990, 7806337, 17507396, 3651560 },
			{ -10420457, -4118111, 14584639, 15971087, -15768321, 8861010, 26556809, -5574557, -18553322, -11357135 },
			{ 2839101, 14284142, 4029895, 3472686, 14402957, 12689363, -26642121, 8459447, -5605463, -7621941 }
		  },
		  {
			{ -4839289, -3535444, 9744961, 2871048, 25113978, 3187018, -25110813, -849066, 17258084, -7977739 },
			{ 18164541, -10595176, -17154882, -1542417, 19237078, -9745295, 23357533, -15217008, 26908270, 12150756 },
			{ -30264870, -7647865, 5112249, -7036672, -1499807, -6974257, 43168, -5537701, -32302074, 16215819 }
		  }
		},
		{ // 26/31
		  {
			{ -6898905, 9824394, -12304779, -4401089, -31397141, -6276835, 32574489, 12532905, -7503072, -8675347 },
			{ -27343522, -16515468, -27151524, -10722951, 946346, 16291093, 254968, 7168080, 21676107, -1943028 },
			{ 21260961, -8424752, -16831886, -11920822, -23677961, 3968121, -3651949, -6215466, -3556191, -7913075 }
		  },
		  {
			{ 16544754, 13250366, -16804428, 15546242, -4583003, 12757258, -2462308, -8680336, -18907032, -9662799 },
			{ -2415239, -15577728, 18312303, 4964443, -15272530, -12653564, 26820651, 16690659, 25459437, -4564609 },
			{ -25144690, 11425020, 28423002, -11020557, -6144921, -15826224, 9142795, -2391602, -6432418, -1644817 }
		  },
		  {
			{ -23104652, 6253476, 16964147, -3768872, -25113972, -12296437, -27457225, -16344658, 6335692, 7249989 },
			{ -30333227, 13979675, 7503222, -12368314, -11956721, -4621693, -30272269, 2682242, 25993170, -12478523 },
			{ 4364628, 5930691, 32304656, -10044554, -8054781, 15091131, 22857016, -10598955, 31820368, 15075278 }
		  },
		  {
			{ 31879134, -8918693, 17258761, 90626, -8041836, -4917709, 24162788, -9650886, -17970238, 12833045 },
			{ 19073683, 14851414, -24403169, -11860168, 7625278, 11091125, -19619190, 2074449, -9413939, 14905377 },
			{ 24483667, -11935567, -2518866, -11547418, -1553130, 15355506, -25282080, 9253129, 27628530, -7555480 }
		  },
		  {
			{ 17597607, 8340603, 19355617, 552187, 26198470, -3176583, 4593324, -9157582, -14110875, 15297016 },
			{ 510886, 14337390, -31785257, 16638632, 6328095, 2713355, -20217417, -11864220, 8683221, 2921426 },
			{ 18606791, 11874196, 27155355, -5281482, -24031742, 6265446, -25178240, -1278924, 4674690, 13890525 }
		  },
		  {
			{ 13609624, 13069022, -27372361, -13055908, 24360586, 9592974, 14977157, 9835105, 4389687, 288396 },
			{ 9922506, -519394, 13613107, 5883594, -18758345, -434263, -12304062, 8317628, 23388070, 16052080 },
			{ 12720016, 11937594, -31970060, -5028689, 26900120, 8561328, -20155687, -11632979, -14754271, -10812892 }
		  },
		  {
			{ 15961858, 14150409, 26716931, -665832, -22794328, 13603569, 11829573, 7467844, -28822128, 929275 },
			{ 11038231, -11582396, -27310482, -7316562, -10498527, -16307831, -23479533, -9371869, -21393143, 2465074 },
			{ 20017163, -4323226, 27915242, 1529148, 12396362, 15675764, 13817261, -9658066, 2463391, -4622140 }
		  },
		  {
			{ -16358878, -12663911, -12065183, 4996454, -1256422, 1073572, 9583558, 12851107, 4003896, 12673717 },
			{ -1731589, -15155870, -3262930, 16143082, 19294135, 13385325, 14741514, -9103726, 7903886, 2348101 },
			{ 24536016, -16515207, 12715592, -3862155, 1511293, 10047386, -3842346, -7129159, -28377538, 10048127 }
		  }
		},
		{ // 27/31
		  {
			{ -12622226, -6204820, 30718825, 2591312, -10617028, 12192840, 18873298, -7297090, -32297756, 15221632 },
			{ -26478122, -11103864, 11546244, -1852483, 9180880, 7656409, -21343950, 2095755, 29769758, 6593415 },
			{ -31994208, -2907461, 4176912, 3264766, 12538965, -868111, 26312345, -6118678, 30958054, 8292160 }
		  },
		  {
			{ 31429822, -13959116, 29173532, 15632448, 12174511, -2760094, 32808831, 3977186, 26143136, -3148876 },
			{ 22648901, 1402143, -22799984, 13746059, 7936347, 365344, -8668633, -1674433, -3758243, -2304625 },
			{ -15491917, 8012313, -2514730, -12702462, -23965846, -10254029, -1612713, -1535569, -16664475, 8194478 }
		  },
		  {
			{ 27338066, -7507420, -7414224, 10140405, -19026427, -6589889, 27277191, 8855376, 28572286, 3005164 },
			{ 26287124, 4821776, 25476601, -4145903, -3764513, -15788984, -18008582, 1182479, -26094821, -13079595 },
			{ -7171154, 3178080, 23970071, 6201893, -17195577, -4489192, -21876275, -13982627, 32208683, -1198248 }
		  },
		  {
			{ -16657702, 2817643, -10286362, 14811298, 6024667, 13349505, -27315504, -10497842, -27672585, -11539858 },
			{ 15941029, -9405932, -21367050, 8062055, 31876073, -238629, -15278393, -1444429, 15397331, -4130193 },
			{ 8934485, -13485467, -23286397, -13423241, -32446090, 14047986, 31170398, -1441021, -27505566, 15087184 }
		  },
		  {
			{ -18357243, -2156491, 24524913, -16677868, 15520427, -6360776, -15502406, 11461896, 16788528, -5868942 },
			{ -1947386, 16013773, 21750665, 3714552, -17401782, -16055433, -3770287, -10323320, 31322514, -11615635 },
			{ 21426655, -5650218, -13648287, -5347537, -28812189, -4920970, -18275391, -14621414, 13040862, -12112948 }
		  },
		  {
			{ 11293895, 12478086, -27136401, 15083750, -29307421, 14748872, 14555558, -13417103, 1613711, 4896935 },
			{ -25894883, 15323294, -8489791, -8057900, 25967126, -13425460, 2825960, -4897045, -23971776, -11267415 },
			{ -15924766, -5229880, -17443532, 6410664, 3622847, 10243618, 20615400, 12405433, -23753030, -8436416 }
		  },
		  {
			{ -7091295, 12556208, -20191352, 9025187, -17072479, 4333801, 4378436, 2432030, 23097949, -566018 },
			{ 4565804, -16025654, 20084412, -7842817, 1724999, 189254, 24767264, 10103221, -18512313, 2424778 },
			{ 366633, -11976806, 8173090, -6890119, 30788634, 5745705, -7168678, 1344109, -3642553, 12412659 }
		  },
		  {
			{ -24001791, 7690286, 14929416, -168257, -32210835, -13412986, 24162697, -15326504, -3141501, 11179385 },
			{ 18289522, -14724954, 8056945, 16430056, -21729724, 7842514, -6001441, -1486897, -18684645, -11443503 },
			{ 476239, 6601091, -6152790, -9723375, 17503545, -4863900, 27672959, 13403813, 11052904, 5219329 }
		  }
		},
		{ // 28/31
		  {
			{ 20678546, -8375738, -32671898, 8849123, -5009758, 14574752, 31186971, -3973730, 9014762, -8579056 },
			{ -13644050, -10350239, -15962508, 5075808, -1514661, -11534600, -33102500, 9160280, 8473550, -3256838 },
			{ 24900749, 14435722, 17209120, -15292541, -22592275, 9878983, -7689309, -16335821, -24568481, 11788948 }
		  },
		  {
			{ -3118155, -11395194, -13802089, 14797441, 9652448, -6845904, -20037437, 10410733, -24568470, -1458691 },
			{ -15659161, 16736706, -22467150, 10215878, -9097177, 7563911, 11871841, -12505194, -18513325, 8464118 },
			{ -23400612, 8348507, -14585951, -861714, -3950205, -6373419, 14325289, 8628612, 33313881, -8370517 }
		  },
		  {
			{ -20186973, -4967935, 22367356, 5271547, -1097117, -4788838, -24805667, -10236854, -8940735, -5818269 },
			{ -6948785, -1795212, -32625683, -16021179, 32635414, -7374245, 15989197, -12838188, 28358192, -4253904 },
			{ -23561781, -2799059, -32351682, -1661963, -9147719, 10429267, -16637684, 4072016, -5351664, 5596589 }
		  },
		  {
			{ -28236598, -3390048, 12312896, 6213178, 3117142, 16078565, 29266239, 2557221, 1768301, 15373193 },
			{ -7243358, -3246960, -4593467, -7553353, -127927, -912245, -1090902, -4504991, -24660491, 3442910 },
			{ -30210571, 5124043, 14181784, 8197961, 18964734, -11939093, 22597931, 7176455, -18585478, 13365930 }
		  },
		  {
			{ -7877390, -1499958, 8324673, 4690079, 6261860, 890446, 24538107, -8570186, -9689599, -3031667 },
			{ 25008904, -10771599, -4305031, -9638010, 16265036, 15721635, 683793, -11823784, 15723479, -15163481 },
			{ -9660625, 12374379, -27006999, -7026148, -7724114, -12314514, 11879682, 5400171, 519526, -1235876 }
		  },
		  {
			{ 22258397, -16332233, -7869817, 14613016, -22520255, -2950923, -20353881, 7315967, 16648397, 7605640 },
			{ -8081308, -8464597, -8223311, 9719710, 19259459, -15348212, 23994942, -5281555, -9468848, 4763278 },
			{ -21699244, 9220969, -15730624, 1084137, -25476107, -2852390, 31088447, -7764523, -11356529, 728112 }
		  },
		  {
			{ 26047220, -11751471, -6900323, -16521798, 24092068, 9158119, -4273545, -12555558, -29365436, -5498272 },
			{ 17510331, -322857, 5854289, 8403524, 17133918, -3112612, -28111007, 12327945, 10750447, 10014012 },
			{ -10312768, 3936952, 9156313, -8897683, 16498692, -994647, -27481051, -666732, 3424691, 7540221 }
		  },
		  {
			{ 30322361, -6964110, 11361005, -4143317, 7433304, 4989748, -7071422, -16317219, -9244265, 15258046 },
			{ 13054562, -2779497, 19155474, 469045, -12482797, 4566042, 5631406, 2711395, 1062915, -5136345 },
			{ -19240248, -11254599, -29509029, -7499965, -5835763, 13005411, -6066489, 12194497, 32960380, 1459310 }
		  }
		},
		{ // 29/31
		  {
			{ 19852034, 7027924, 23669353, 10020366, 8586503, -6657907, 394197, -6101885, 18638003, -11174937 },
			{ 31395534, 15098109, 26581030, 8030562, -16527914, -5007134, 9012486, -7584354, -6643087, -5442636 },
			{ -9192165, -2347377, -1997099, 4529534, 25766844, 607986, -13222, 9677543, -32294889, -6456008 }
		  },
		  {
			{ -2444496, -149937, 29348902, 8186665, 1873760, 12489863, -30934579, -7839692, -7852844, -8138429 },
			{ -15236356, -15433509, 7766470, 746860, 26346930, -10221762, -27333451, 10754588, -9431476, 5203576 },
			{ 31834314, 14135496, -770007, 5159118, 20917671, -16768096, -7467973, -7337524, 31809243, 7347066 }
		  },
		  {
			{ -9606723, -11874240, 20414459, 13033986, 13716524, -11691881, 19797970, -12211255, 15192876, -2087490 },
			{ -12663563, -2181719, 1168162, -3804809, 26747877, -14138091, 10609330, 12694420, 33473243, -13382104 },
			{ 33184999, 11180355, 15832085, -11385430, -1633671, 225884, 15089336, -11023903, -6135662, 14480053 }
		  },
		  {
			{ 31308717, -5619998, 31030840, -1897099, 15674547, -6582883, 5496208, 13685227, 27595050, 8737275 },
			{ -20318852, -15150239, 10933843, -16178022, 8335352, -7546022, -31008351, -12610604, 26498114, 66511 },
			{ 22644454, -8761729, -16671776, 4884562, -3105614, -13559366, 30540766, -4286747, -13327787, -7515095 }
		  },
		  {
			{ -28017847, 9834845, 18617207, -2681312, -3401956, -13307506, 8205540, 13585437, -17127465, 15115439 },
			{ 23711543, -672915, 31206561, -8362711, 6164647, -9709987, -33535882, -1426096, 8236921, 16492939 },
			{ -23910559, -13515526, -26299483, -4503841, 25005590, -7687270, 19574902, 10071562, 6708380, -6222424 }
		  },
		  {
			{ 2101391, -4930054, 19702731, 2367575, -15427167, 1047675, 5301017, 9328700, 29955601, -11678310 },
			{ 3096359, 9271816, -21620864, -15521844, -14847996, -7592937, -25892142, -12635595, -9917575, 6216608 },
			{ -32615849, 338663, -25195611, 2510422, -29213566, -13820213, 24822830, -6146567, -26767480, 7525079 }
		  },
		  {
			{ -23066649, -13985623, 16133487, -7896178, -3389565, 778788, -910336, -2782495, -19386633, 11994101 },
			{ 21691500, -13624626, -641331, -14367021, 3285881, -3483596, -25064666, 9718258, -7477437, 13381418 },
			{ 18445390, -4202236, 14979846, 11622458, -1727110, -3582980, 23111648, -6375247, 28535282, 15779576 }
		  },
		  {
			{ 30098053, 3089662, -9234387, 16662135, -21306940, 11308411, -14068454, 12021730, 9955285, -16303356 },
			{ 9734894, -14576830, -7473633, -9138735, 2060392, 11313496, -18426029, 9924399, 20194861, 13380996 },
			{ -26378102, -7965207, -22167821, 15789297, -18055342, -6168792, -1984914, 15707771, 26342023, 10146099 }
		  }
		},
		{ // 30/31
		  {
			{ -26016874, -219943, 21339191, -41388, 19745256, -2878700, -29637280, 2227040, 21612326, -545728 },
			{ -13077387, 1184228, 23562814, -5970442, -20351244, -6348714, 25764461, 12243797, -20856566, 11649658 },
			{ -10031494, 11262626, 27384172, 2271902, 26947504, -15997771, 39944, 6114064, 33514190, 2333242 }
		  },
		  {
			{ -21433588, -12421821, 8119782, 7219913, -21830522, -9016134, -6679750, -12670638, 24350578, -13450001 },
			{ -4116307, -11271533, -23886186, 4843615, -30088339, 690623, -31536088, -10406836, 8317860, 12352766 },
			{ 18200138, -14475911, -33087759, -2696619, -23702521, -9102511, -23552096, -2287550, 20712163, 6719373 }
		  },
		  {
			{ 26656208, 6075253, -7858556, 1886072, -28344043, 4262326, 11117530, -3763210, 26224235, -3297458 },
			{ -17168938, -14854097, -3395676, -16369877, -19954045, 14050420, 21728352, 9493610, 18620611, -16428628 },
			{ -13323321, 13325349, 11432106, 5964811, 18609221, 6062965, -5269471, -9725556, -30701573, -16479657 }
		  },
		  {
			{ -23860538, -11233159, 26961357, 1640861, -32413112, -16737940, 12248509, -5240639, 13735342, 1934062 },
			{ 25089769, 6742589, 17081145, -13406266, 21909293, -16067981, -15136294, -3765346, -21277997, 5473616 },
			{ 31883677, -7961101, 1083432, -11572403, 22828471, 13290673, -7125085, 12469656, 29111212, -5451014 }
		  },
		  {
			{ 24244947, -15050407, -26262976, 2791540, -14997599, 16666678, 24367466, 6388839, -10295587, 452383 },
			{ -25640782, -3417841, 5217916, 16224624, 19987036, -4082269, -24236251, -5915248, 15766062, 8407814 },
			{ -20406999, 13990231, 15495425, 16395525, 5377168, 15166495, -8917023, -4388953, -8067909, 2276718 }
		  },
		  {
			{ 30157918, 12924066, -17712050, 9245753, 19895028, 3368142, -23827587, 5096219, 22740376, -7303417 },
			{ 2041139, -14256350, 7783687, 13876377, -25946985, -13352459, 24051124, 13742383, -15637599, 13295222 },
			{ 33338237, -8505733, 12532113, 7977527, 9106186, -1715251, -17720195, -4612972, -4451357, -14669444 }
		  },
		  {
			{ -20045281, 5454097, -14346548, 6447146, 28862071, 1883651, -2469266, -4141880, 7770569, 9620597 },
			{ 23208068, 7979712, 33071466, 8149229, 1758231, -10834995, 30945528, -1694323, -33502340, -14767970 },
			{ 1439958, -16270480, -1079989, -793782, 4625402, 10647766, -5043801, 1220118, 30494170, -11440799 }
		  },
		  {
			{ -5037580, -13028295, -2970559, -3061767, 15640974, -6701666, -26739026, 926050, -1684339, -13333647 },
			{ 13908495, -3549272, 30919928, -6273825, -21521863, 7989039, 9021034, 9078865, 3353509, 4033511 },
			{ -29663431, -15113610, 32259991, -344482, 24295849, -12912123, 23161163, 8839127, 27485041, 7356032 }
		  }
		},
		{ // 31/31
		  {
			{ 9661027, 705443, 11980065, -5370154, -1628543, 14661173, -6346142, 2625015, 28431036, -16771834 },
			{ -23839233, -8311415, -25945511, 7480958, -17681669, -8354183, -22545972, 14150565, 15970762, 4099461 },
			{ 29262576, 16756590, 26350592, -8793563, 8529671, -11208050, 13617293, -9937143, 11465739, 8317062 }
		  },
		  {
			{ -25493081, -6962928, 32500200, -9419051, -23038724, -2302222, 14898637, 3848455, 20969334, -5157516 },
			{ -20384450, -14347713, -18336405, 13884722, -33039454, 2842114, -21610826, -3649888, 11177095, 14989547 },
			{ -24496721, -11716016, 16959896, 2278463, 12066309, 10137771, 13515641, 2581286, -28487508, 9930240 }
		  },
		  {
			{ -17751622, -2097826, 16544300, -13009300, -15914807, -14949081, 18345767, -13403753, 16291481, -5314038 },
			{ -33229194, 2553288, 32678213, 9875984, 8534129, 6889387, -9676774, 6957617, 4368891, 9788741 },
			{ 16660756, 7281060, -10830758, 12911820, 20108584, -8101676, -21722536, -8613148, 16250552, -11111103 }
		  },
		  {
			{ -19765507, 2390526, -16551031, 14161980, 1905286, 6414907, 4689584, 10604807, -30190403, 4782747 },
			{ -1354539, 14736941, -7367442, -13292886, 7710542, -14155590, -9981571, 4383045, 22546403, 437323 },
			{ 31665577, -12180464, -16186830, 1491339, -18368625, 3294682, 27343084, 2786261, -30633590, -14097016 }
		  },
		  {
			{ -14467279, -683715, -33374107, 7448552, 19294360, 14334329, -19690631, 2355319, -19284671, -6114373 },
			{ 15121312, -15796162, 6377020, -6031361, -10798111, -12957845, 18952177, 15496498, -29380133, 11754228 },
			{ -2637277, -13483075, 8488727, -14303896, 12728761, -1622493, 7141596, 11724556, 22761615, -10134141 }
		  },
		  {
			{ 16918416, 11729663, -18083579, 3022987, -31015732, -13339659, -28741185, -12227393, 32851222, 11717399 },
			{ 11166634, 7338049, -6722523, 4531520, -29468672, -7302055, 31474879, 3483633, -1193175, -4030831 },
			{ -185635, 9921305, 31456609, -13536438, -12013818, 13348923, 33142652, 6546660, -19985279, -3948376 }
		  },
		  {
			{ -32460596, 11266712, -11197107, -7899103, 31703694, 3855903, -8537131, -12833048, -30772034, -15486313 },
			{ -18006477, 12709068, 3991746, -6479188, -21491523, -10550425, -31135347, -16049879, 10928917, 3011958 },
			{ -6957757, -15594337, 31696059, 334240, 29576716, 14796075, -30831056, -12805180, 18008031, 10258577 }
		  },
		  {
			{ -22448644, 15655569, 7018479, -4410003, -30314266, -1201591, -1853465, 1367120, 25127874, 6671743 },
			{ 29701166, -14373934, -10878120, 9279288, -17568, 13127210, 21382910, 11042292, 25838796, 4642684 },
			{ -20430234, 14955537, -24126347, 8124619, -5369288, -5990470, 30468147, -13900640, 18423289, 4177476 }
		  }
		}
#endif
	};

	Ge25519cMov8(T, base[Position], B);
}

void EC25519::Ge25519P2Dbl(ge25519p1p1 &R, const ge25519p2 &P)
{
	fe25519 t0 = { 0 };

	Fe25519Sq(R.x, P.x);
	Fe25519Sq(R.z, P.y);
	Fe25519Sq2(R.t, P.z);
	Fe25519Add(R.y, P.x, P.y);
	Fe25519Sq(t0, R.y);
	Fe25519Add(R.y, R.z, R.x);
	Fe25519Sub(R.z, R.z, R.x);
	Fe25519Sub(R.x, t0, R.y);
	Fe25519Sub(R.t, R.t, R.z);
}

void EC25519::Ge25519P3ToP2(ge25519p2 &R, const ge25519p3 &P)
{
	Fe25519Copy(R.x, P.x);
	Fe25519Copy(R.y, P.y);
	Fe25519Copy(R.z, P.z);
}

void EC25519::Ge25519P3Dbl(ge25519p1p1 &R, const ge25519p3 &P)
{
	ge25519p2 q = { 0 };

	Ge25519P3ToP2(q, P);
	Ge25519P2Dbl(R, q);
}

void EC25519::Ge25519P2Zero(ge25519p2 &H)
{
	Fe25519Zero(H.x);
	Fe25519One(H.y);
	Fe25519One(H.z);
}

void EC25519::Ge25519P1P1ToP3(ge25519p3 &R, const ge25519p1p1 &P)
{
	Fe25519Mul(R.x, P.x, P.t);
	Fe25519Mul(R.y, P.y, P.z);
	Fe25519Mul(R.z, P.z, P.t);
	Fe25519Mul(R.t, P.x, P.y);
}

void EC25519::Ge25519P1P1ToP2(ge25519p2 &R, const ge25519p1p1 &P)
{
	Fe25519Mul(R.x, P.x, P.t);
	Fe25519Mul(R.y, P.y, P.z);
	Fe25519Mul(R.z, P.z, P.t);
}

void EC25519::Ge25519ScalarBase(ge25519p3 &H, const std::vector<uint8_t> &A)
{
	std::array<int8_t, 64> e = { 0 };
	ge25519p1p1 r = { 0 };
	ge25519p2 s = { 0 };
	ge25519precomp t = { 0 };
	size_t i;
	int8_t carry;

	for (i = 0; i < 32; ++i)
	{
		e[2 * i] = A[i] & 15;
		e[2 * i + 1] = (A[i] >> 4) & 15;
	}

	carry = 0;

	// each e[i] is between 0 and 15
	// e[63] is between 0 and 7
	for (i = 0; i < 63; ++i)
	{
		e[i] += carry;
		carry = e[i] + 8;
		carry >>= 4;
		e[i] -= carry * ((uint8_t)1 << 4);
	}

	e[63] += carry;

	// each e[i] is between -8 and 8
	Ge25519P3Zero(H);

	for (i = 1; i < 64; i += 2)
	{
		Ge25519cMov8Base(t, (int32_t)i / 2, e[i]);
		Fe25519AddPrecomp(r, H, t);
		Ge25519P1P1ToP3(H, r);
	}

	Ge25519P3Dbl(r, H);
	Ge25519P1P1ToP2(s, r);
	Ge25519P2Dbl(r, s);
	Ge25519P1P1ToP2(s, r);
	Ge25519P2Dbl(r, s);
	Ge25519P1P1ToP2(s, r);
	Ge25519P2Dbl(r, s);
	Ge25519P1P1ToP3(H, r);

	for (i = 0; i < 64; i += 2)
	{
		Ge25519cMov8Base(t, (int32_t)i / 2, e[i]);
		Fe25519AddPrecomp(r, H, t);
		Ge25519P1P1ToP3(H, r);
	}
}

void EC25519::Ge25519P3ToBytes(std::vector<uint8_t> &S, const ge25519p3 &H)
{
	fe25519 recip = { 0 };
	fe25519 x = { 0 };
	fe25519 y = { 0 };

	Fe25519Invert(recip, H.z);
	Fe25519Mul(x, H.x, recip);
	Fe25519Mul(y, H.y, recip);
	Fe25519ToBytes(S, y);
	S[31] ^= Fe25519IsNegative(x) << 7;
}

int32_t EC25519::Ge25519IsCanonical(const std::vector<uint8_t> &S)
{
	size_t i;
	uint8_t c;
	uint8_t d;

	c = (S[31] & 0x7F) ^ 0x7F;

	for (i = 30; i > 0; i--)
	{
		c |= S[i] ^ 0xFF;
	}

	c = (static_cast<uint32_t>(c) - 1U) >> 8;
	d = (0xED - 1U - static_cast<uint32_t>(S[0])) >> 8;

	return 1L - (c & d & 1);
}

int32_t EC25519::Ge25519HasSmallOrder(const std::vector<uint8_t> &S)
{
	static const std::vector<std::vector<uint8_t>> blocklist =
	{
		// 0 (order 4) 
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
		},
		// 1 (order 1) 
		{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
		// 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
		{
			0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
			0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
			0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05
		},
		// 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
		{
			0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
			0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
			0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a
		},
		// p-1 (order 2)
		{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
		},
		// p (=0, order 4)
		{
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
		},
		// p+1 (=1, order 1)
		{
			0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
		}
	};

	std::array<uint8_t, 7> c = { 0 };
	size_t i;
	size_t j;
	uint32_t k;

	for (j = 0; j < 31; ++j)
	{
		for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
		{
			c[i] |= S[j] ^ blocklist[i][j];
		}
	}

	for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
	{
		c[i] |= (S[j] & 0x7f) ^ blocklist[i][j];
	}

	k = 0;

	for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
	{
		k |= (c[i] - 1);
	}

	return static_cast<int32_t>((k >> 8) & 1);
}

int32_t EC25519::Ge25519FromBytesNegateVarTime(ge25519p3 &H, const std::vector<uint8_t> &S)
{
	fe25519 u = { 0 };
	fe25519 v = { 0 };
	fe25519 v3 = { 0 };
	fe25519 vxx = { 0 };
	fe25519 mrcheck = { 0 };
	fe25519 prcheck = { 0 };
	int32_t res;

	res = 0;
	Fe25519FromBytes(H.y, S);
	Fe25519One(H.z);
	Fe25519Sq(u, H.y);
	Fe25519Mul(v, u, Ed25519D);
	// u = y^2-1 
	Fe25519Sub(u, u, H.z);
	// v = dy^2+1 
	Fe25519Add(v, v, H.z);

	Fe25519Sq(v3, v);
	// v3 = v^3 
	Fe25519Mul(v3, v3, v);
	Fe25519Sq(H.x, v3);
	// x = uv^7 
	Fe25519Mul(H.x, H.x, v);
	Fe25519Mul(H.x, H.x, u);
	// x = (uv^7)^((q-5)/8) 
	Fe25519Pow22523(H.x, H.x);
	Fe25519Mul(H.x, H.x, v3);
	Fe25519Mul(H.x, H.x, u);
	// x = uv^3(uv^7)^((q-5)/8) 
	Fe25519Sq(vxx, H.x);
	Fe25519Mul(vxx, vxx, v);
	// vx^2-u 
	Fe25519Sub(mrcheck, vxx, u);

	if (Fe25519IsZero(mrcheck) == 0)
	{
		// vx^2+u 
		Fe25519Add(prcheck, vxx, u);

		if (Fe25519IsZero(prcheck) == 0)
		{
			res = -1;
		}
		else
		{
			Fe25519Mul(H.x, H.x, Fe25519SqrtM1);
		}
	}

	if (res != -1)
	{
		if (Fe25519IsNegative(H.x) == (S[31] >> 7))
		{
			Fe25519Neg(H.x, H.x);
		}

		Fe25519Mul(H.t, H.x, H.y);
	}

	return res;
}

void EC25519::Ge25519P3ToCached(ge25519cached &R, const ge25519p3 &P)
{
	Fe25519Add(R.yplusx, P.y, P.x);
	Fe25519Sub(R.yminusx, P.y, P.x);
	Fe25519Copy(R.z, P.z);
	Fe25519Mul(R.t2d, P.t, Ed25519D2);
}

void EC25519::Ge25519AddCached(ge25519p1p1 &R, const ge25519p3 &P, const ge25519cached &Q)
{
	fe25519 t0 = { 0 };

	Fe25519Add(R.x, P.y, P.x);
	Fe25519Sub(R.y, P.y, P.x);
	Fe25519Mul(R.z, R.x, Q.yplusx);
	Fe25519Mul(R.y, R.y, Q.yminusx);
	Fe25519Mul(R.t, Q.t2d, P.t);
	Fe25519Mul(R.x, P.z, Q.z);
	Fe25519Add(t0, R.x, R.x);
	Fe25519Sub(R.x, R.z, R.y);
	Fe25519Add(R.y, R.z, R.y);
	Fe25519Add(R.z, t0, R.t);
	Fe25519Sub(R.t, t0, R.t);
}

void EC25519::Ge25519SubPrecomp(ge25519p1p1 &R, const ge25519p3 &P, const ge25519precomp &Q)
{
	fe25519 t0 = { 0 };

	Fe25519Add(R.x, P.y, P.x);
	Fe25519Sub(R.y, P.y, P.x);
	Fe25519Mul(R.z, R.x, Q.yminusx);
	Fe25519Mul(R.y, R.y, Q.yplusx);
	Fe25519Mul(R.t, Q.xy2d, P.t);
	Fe25519Add(t0, P.z, P.z);
	Fe25519Sub(R.x, R.z, R.y);
	Fe25519Add(R.y, R.z, R.y);
	Fe25519Sub(R.z, t0, R.t);
	Fe25519Add(R.t, t0, R.t);
}

void EC25519::Ge25519DoubleScalarMultVarTime(ge25519p2 &R, const std::vector<uint8_t> &A, const ge25519p3 &AL, const std::vector<uint8_t> &B, size_t BOffset)
{
	static const std::vector<ge25519precomp> Bi =
	{
#if defined(CEX_SYSTEM_NATIVE_UINT128)
		{
		  { 1288382639258501, 245678601348599, 269427782077623, 1462984067271730, 137412439391563 },
		  { 62697248952638, 204681361388450, 631292143396476, 338455783676468, 1213667448819585 },
		  { 301289933810280, 1259582250014073, 1422107436869536, 796239922652654, 1953934009299142 }
		},
		{
		  { 1601611775252272, 1720807796594148, 1132070835939856, 1260455018889551, 2147779492816911 },
		  { 316559037616741, 2177824224946892, 1459442586438991, 1461528397712656, 751590696113597 },
		  { 1850748884277385, 1200145853858453, 1068094770532492, 672251375690438, 1586055907191707 }
		},
		{
		  { 769950342298419, 132954430919746, 844085933195555, 974092374476333, 726076285546016 },
		  { 425251763115706, 608463272472562, 442562545713235, 837766094556764, 374555092627893 },
		  { 1086255230780037, 274979815921559, 1960002765731872, 929474102396301, 1190409889297339 }
		},
		{
		  { 665000864555967, 2065379846933859, 370231110385876, 350988370788628, 1233371373142985 },
		  { 2019367628972465, 676711900706637, 110710997811333, 1108646842542025, 517791959672113 },
		  { 965130719900578, 247011430587952, 526356006571389, 91986625355052, 2157223321444601 }
		},
		{
		  { 1802695059465007, 1664899123557221, 593559490740857, 2160434469266659, 927570450755031 },
		  { 1725674970513508, 1933645953859181, 1542344539275782, 1767788773573747, 1297447965928905 },
		  { 1381809363726107, 1430341051343062, 2061843536018959, 1551778050872521, 2036394857967624 }
		},
		{
		  { 1970894096313054, 528066325833207, 1619374932191227, 2207306624415883, 1169170329061080 },
		  { 2070390218572616, 1458919061857835, 624171843017421, 1055332792707765, 433987520732508 },
		  { 893653801273833, 1168026499324677, 1242553501121234, 1306366254304474, 1086752658510815 }
		},
		{
		  { 213454002618221, 939771523987438, 1159882208056014, 317388369627517, 621213314200687 },
		  { 1971678598905747, 338026507889165, 762398079972271, 655096486107477, 42299032696322 },
		  { 177130678690680, 1754759263300204, 1864311296286618, 1180675631479880, 1292726903152791 }
		},
		{
		  { 1913163449625248, 460779200291993, 2193883288642314, 1008900146920800, 1721983679009502 },
		  { 1070401523076875, 1272492007800961, 1910153608563310, 2075579521696771, 1191169788841221 },
		  { 692896803108118, 500174642072499, 2068223309439677, 1162190621851337, 1426986007309901 }
		}
#else
		{
		  { 25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605 },
		  { -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378 },
		  { -8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546 }
		},
		{
		  { 15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024 },
		  { 16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574 },
		  { 30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357 }
		},
		{
		  { 10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380 },
		  { 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306 },
		  { 19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942 }
		},
		{
		  { 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766 },
		  { -30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701 },
		  { 28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300 }
		},
		{
		  { -22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211, -1361450, -13062696, 13821877 },
		  { -6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028, -7212327, 18853322, -14220951 },
		  { 4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358, -10431137, 2207753, -3209784 }
		},
		{
		  { -25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364, -663000, -31111463, -16132436 },
		  { 25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789, 15725684, 171356, 6466918 },
		  { 23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339, -14088058, -30714912, 16193877 }
		},
		{
		  { -33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398, 4729455, -18074513, 9256800 },
		  { -25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405, 9761698, -19827198, 630305 },
		  { -13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551, -15960994, -2449256, -14291300 }
		},
		{
		  { -3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575, 15033784, 25105118, -7894876 },
		  { -24326370, 15950226, -31801215, -14592823, -11662737, -5090925, 1573892, -2625887, 2198790, -15804619 },
		  { -3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022, -16236442, -32461234, -12290683 }
		}
#endif
	};

	std::vector<int8_t> aslide(256);
	std::vector<int8_t> bslide(256);
	ge25519cached Ai[8] = { 0 };
	ge25519p1p1 t = { 0 };
	ge25519p3 u = { 0 };
	ge25519p3 A2 = { 0 };
	int32_t i;

	EcdsaBaseSlideVarTime(aslide, A, 0);
	EcdsaBaseSlideVarTime(bslide, B, BOffset);

	Ge25519P3ToCached(Ai[0], AL);

	Ge25519P3Dbl(t, AL);
	Ge25519P1P1ToP3(A2, t);

	Ge25519AddCached(t, A2, Ai[0]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[1], u);

	Ge25519AddCached(t, A2, Ai[1]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[2], u);

	Ge25519AddCached(t, A2, Ai[2]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[3], u);

	Ge25519AddCached(t, A2, Ai[3]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[4], u);

	Ge25519AddCached(t, A2, Ai[4]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[5], u);

	Ge25519AddCached(t, A2, Ai[5]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[6], u);

	Ge25519AddCached(t, A2, Ai[6]);
	Ge25519P1P1ToP3(u, t);
	Ge25519P3ToCached(Ai[7], u);

	Ge25519P2Zero(R);

	for (i = 255; i >= 0; --i)
	{
		if (aslide[i] || bslide[i])
		{
			break;
		}
	}

	for (; i >= 0; --i)
	{
		Ge25519P2Dbl(t, R);

		if (aslide[i] > 0)
		{
			Ge25519P1P1ToP3(u, t);
			Ge25519AddCached(t, u, Ai[aslide[i] / 2]);
		}
		else if (aslide[i] < 0)
		{
			Ge25519P1P1ToP3(u, t);
			Ge25519SubCached(t, u, Ai[(-aslide[i]) / 2]);
		}

		if (bslide[i] > 0)
		{
			Ge25519P1P1ToP3(u, t);
			Fe25519AddPrecomp(t, u, Bi[bslide[i] / 2]);
		}
		else if (bslide[i] < 0)
		{
			Ge25519P1P1ToP3(u, t);
			Ge25519SubPrecomp(t, u, Bi[(-bslide[i]) / 2]);
		}

		Ge25519P1P1ToP2(R, t);
	}
}

void EC25519::Ge25519SubCached(ge25519p1p1 &R, const ge25519p3 &P, const ge25519cached &Q)
{
	fe25519 t0 = { 0 };

	Fe25519Add(R.x, P.y, P.x);
	Fe25519Sub(R.y, P.y, P.x);
	Fe25519Mul(R.z, R.x, Q.yminusx);
	Fe25519Mul(R.y, R.y, Q.yplusx);
	Fe25519Mul(R.t, Q.t2d, P.t);
	Fe25519Mul(R.x, P.z, Q.z);
	Fe25519Add(t0, R.x, R.x);
	Fe25519Sub(R.x, R.z, R.y);
	Fe25519Add(R.y, R.z, R.y);
	Fe25519Sub(R.z, t0, R.t);
	Fe25519Add(R.t, t0, R.t);
}

void EC25519::Ge25519ToBytes(std::vector<uint8_t> &S, const ge25519p2 &H)
{
	fe25519 recip = { 0 };
	fe25519 x = { 0 };
	fe25519 y = { 0 };

	Fe25519Invert(recip, H.z);
	Fe25519Mul(x, H.x, recip);
	Fe25519Mul(y, H.y, recip);
	Fe25519ToBytes(S, y);
	S[31] ^= Fe25519IsNegative(x) << 7;
}

void EC25519::EdwardsToMontgomery(fe25519 &MontgomeryX, const fe25519 &EdwardsY, const fe25519 &EdwardsZ)
{
	fe25519 tempX = { 0 };
	fe25519 tempZ = { 0 };

	Fe25519Add(tempX, EdwardsZ, EdwardsY);
	Fe25519Sub(tempZ, EdwardsZ, EdwardsY);
	Fe25519Invert(tempZ, tempZ);
	Fe25519Mul(MontgomeryX, tempX, tempZ);
}

int32_t EC25519::ScalarmultCurve25519Ref10Base(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N)
{
	ge25519p3 A = { 0 };
	fe25519 pk = { 0 };
	size_t i;

	for (i = 0; i < 32; ++i)
	{
		Q[i] = N[i];
	}

	Sc25519Clamp(Q);
	Ge25519ScalarBase(A, Q);
	EdwardsToMontgomery(pk, A.y, A.z);
	Fe25519ToBytes(Q, pk);

	return 0;
}

int32_t EC25519::ScalarMultCurve25519Ref10(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N, const std::vector<uint8_t> &P)
{
	fe25519 a = { 0 };
	fe25519 b = { 0 };
	fe25519 aa = { 0 };
	fe25519 bb = { 0 };
	fe25519 cb = { 0 };
	fe25519 da = { 0 };
	fe25519 e = { 0 };
	fe25519 x1 = { 0 };
	fe25519 x2 = { 0 };
	fe25519 x3 = { 0 };
	fe25519 z2 = { 0 };
	fe25519 z3 = { 0 };
	size_t i;
	uint32_t swap;
	uint32_t bit;
	int32_t pos;

	if (Ed25519SmallOrder(P))
	{
		return -1;
	}

	for (i = 0; i < 32; i++)
	{
		Q[i] = N[i];
	}

	Sc25519Clamp(Q);
	Fe25519FromBytes(x1, P);
	Fe25519One(x2);
	Fe25519Zero(z2);
	Fe25519Copy(x3, x1);
	Fe25519One(z3);

	swap = 0;

	for (pos = 254; pos >= 0; --pos)
	{
		bit = Q[pos / 8] >> (pos & 7);
		bit &= 1;
		swap ^= bit;
		Fe25519cSwap(x2, x3, swap);
		Fe25519cSwap(z2, z3, swap);
		swap = bit;
		Fe25519Add(a, x2, z2);
		Fe25519Sub(b, x2, z2);
		Fe25519Sq(aa, a);
		Fe25519Sq(bb, b);
		Fe25519Mul(x2, aa, bb);
		Fe25519Sub(e, aa, bb);
		Fe25519Sub(da, x3, z3);
		Fe25519Mul(da, da, a);
		Fe25519Add(cb, x3, z3);
		Fe25519Mul(cb, cb, b);
		Fe25519Add(x3, da, cb);
		Fe25519Sq(x3, x3);
		Fe25519Sub(z3, da, cb);
		Fe25519Sq(z3, z3);
		Fe25519Mul(z3, z3, x1);
		Fe25519Mul32(z2, e, 121666);
		Fe25519Add(z2, z2, bb);
		Fe25519Mul(z2, z2, e);
	}

	Fe25519cSwap(x2, x3, swap);
	Fe25519cSwap(z2, z3, swap);
	Fe25519Invert(z2, z2);
	Fe25519Mul(x2, x2, z2);
	Fe25519ToBytes(Q, x2);

	return 0;
}

int32_t EC25519::ScalarMultCurve25519(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N, const std::vector<uint8_t> &P)
{
	size_t i;
	uint8_t d;

	d = 0;

	if (ScalarMultCurve25519Ref10(Q, N, P) != 0)
	{
		return -1;
	}

	for (i = 0; i < EC25519_CURVE_SIZE; ++i)
	{
		d |= Q[i];
	}

	return -(1 & ((d - 1) >> 8));
}

int32_t EC25519::Ed25519SmallOrder(const std::vector<uint8_t> &S)
{
	// Reject small order points early to mitigate the implications of
	// unexpected optimizations that would affect the ref10 code.
	// See https://eprint.iacr.org/2017/806.pdf for reference.
	static const std::vector<std::vector<uint8_t>> blocklist =
	{
		// 0 (order 4) 
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
		// 1 (order 1) 
		{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		},
		// 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8) 
		{
			0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
			0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
			0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 
		},
		// 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8) 
		{
			0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
			0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
			0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57
		},
		// p-1 (order 2) 
		{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f 
		},
		// p (=0, order 4) 
		{
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f 
		},
		// p+1 (=1, order 1) 
		{
			0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
		}
	};

	std::array<uint8_t, 7> c = { 0 };
	size_t i;
	size_t j;
	uint32_t k;

	for (j = 0; j < 31; ++j)
	{
		for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
		{
			c[i] |= S[j] ^ blocklist[i][j];
		}
	}

	for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
	{
		c[i] |= (S[j] & 0x7f) ^ blocklist[i][j];
	}

	k = 0;

	for (i = 0; i < sizeof(blocklist) / sizeof(blocklist[0]); ++i)
	{
		k |= (c[i] - 1);
	}

	return static_cast<int32_t>((k >> 8) & 1);
}

void EC25519::Sc25519Clamp(std::vector<uint8_t> &K)
{
	K[0] &= 248;
	K[31] &= 127;
	K[31] |= 64;
}

int32_t EC25519::Sc25519IsCanonical(const std::vector<uint8_t> &S, size_t Offset)
{
	static const std::array<uint8_t, 32> L =
	{
		0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7,
		0xA2, 0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	};

	size_t i;
	uint8_t c;
	uint8_t n;

	c = 0;
	n = 1;
	i = 32;

	do
	{
		i--;
		c |= ((S[Offset + i] - L[i]) >> 8) & n;
		n &= ((S[Offset + i] ^ L[i]) - 1) >> 8;
	} 
	while (i != 0);

	return (c != 0);
}

void EC25519::Sc25519MulAdd(std::vector<uint8_t> &S, size_t SOffset, const std::vector<uint8_t> &A, const std::vector<uint8_t> &B, const std::vector<uint8_t> &C)
{
	int64_t a0;
	int64_t a1;
	int64_t a2;
	int64_t a3;
	int64_t a4;
	int64_t a5;
	int64_t a6;
	int64_t a7;
	int64_t a8;
	int64_t a9;
	int64_t a10;
	int64_t a11;
	int64_t b0;
	int64_t b1;
	int64_t b2;
	int64_t b3;
	int64_t b4;
	int64_t b5;
	int64_t b6;
	int64_t b7;
	int64_t b8;
	int64_t b9;
	int64_t b10;
	int64_t b11;
	int64_t carry;
	int64_t c0;
	int64_t c1;
	int64_t c2;
	int64_t c3;
	int64_t c4;
	int64_t c5;
	int64_t c6;
	int64_t c7;
	int64_t c8;
	int64_t c9;
	int64_t c10;
	int64_t c11;
	int64_t s0;
	int64_t s1;
	int64_t s2;
	int64_t s3;
	int64_t s4;
	int64_t s5;
	int64_t s6;
	int64_t s7;
	int64_t s8;
	int64_t s9;
	int64_t s10;
	int64_t s11;
	int64_t s12;
	int64_t s13;
	int64_t s14;
	int64_t s15;
	int64_t s16;
	int64_t s17;
	int64_t s18;
	int64_t s19;
	int64_t s20;
	int64_t s21;
	int64_t s22;
	int64_t s23;

	a0 = 2097151 & EcdsaBaseLoad3(A, 0);
	a1 = 2097151 & (EcdsaBaseLoad4(A, 2) >> 5);
	a2 = 2097151 & (EcdsaBaseLoad3(A, 5) >> 2);
	a3 = 2097151 & (EcdsaBaseLoad4(A, 7) >> 7);
	a4 = 2097151 & (EcdsaBaseLoad4(A, 10) >> 4);
	a5 = 2097151 & (EcdsaBaseLoad3(A, 13) >> 1);
	a6 = 2097151 & (EcdsaBaseLoad4(A, 15) >> 6);
	a7 = 2097151 & (EcdsaBaseLoad3(A, 18) >> 3);
	a8 = 2097151 & EcdsaBaseLoad3(A, 21);
	a9 = 2097151 & (EcdsaBaseLoad4(A, 23) >> 5);
	a10 = 2097151 & (EcdsaBaseLoad3(A, 26) >> 2);
	a11 = (EcdsaBaseLoad4(A, 28) >> 7);

	b0 = 2097151 & EcdsaBaseLoad3(B, 0);
	b1 = 2097151 & (EcdsaBaseLoad4(B, 2) >> 5);
	b2 = 2097151 & (EcdsaBaseLoad3(B, 5) >> 2);
	b3 = 2097151 & (EcdsaBaseLoad4(B, 7) >> 7);
	b4 = 2097151 & (EcdsaBaseLoad4(B, 10) >> 4);
	b5 = 2097151 & (EcdsaBaseLoad3(B, 13) >> 1);
	b6 = 2097151 & (EcdsaBaseLoad4(B, 15) >> 6);
	b7 = 2097151 & (EcdsaBaseLoad3(B, 18) >> 3);
	b8 = 2097151 & EcdsaBaseLoad3(B, 21);
	b9 = 2097151 & (EcdsaBaseLoad4(B, 23) >> 5);
	b10 = 2097151 & (EcdsaBaseLoad3(B, 26) >> 2);
	b11 = (EcdsaBaseLoad4(B, 28) >> 7);

	c0 = 2097151 & EcdsaBaseLoad3(C, 0);
	c1 = 2097151 & (EcdsaBaseLoad4(C, 2) >> 5);
	c2 = 2097151 & (EcdsaBaseLoad3(C, 5) >> 2);
	c3 = 2097151 & (EcdsaBaseLoad4(C, 7) >> 7);
	c4 = 2097151 & (EcdsaBaseLoad4(C, 10) >> 4);
	c5 = 2097151 & (EcdsaBaseLoad3(C, 13) >> 1);
	c6 = 2097151 & (EcdsaBaseLoad4(C, 15) >> 6);
	c7 = 2097151 & (EcdsaBaseLoad3(C, 18) >> 3);
	c8 = 2097151 & EcdsaBaseLoad3(C, 21);
	c9 = 2097151 & (EcdsaBaseLoad4(C, 23) >> 5);
	c10 = 2097151 & (EcdsaBaseLoad3(C, 26) >> 2);
	c11 = (EcdsaBaseLoad4(C, 28) >> 7);

	s0 = c0 + a0 * b0;
	s1 = c1 + a0 * b1 + a1 * b0;
	s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
	s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
	s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
	s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
	s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
	s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
	s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
	s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
	s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
	s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
	s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
	s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
	s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
	s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
	s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
	s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
	s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
	s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
	s20 = a9 * b11 + a10 * b10 + a11 * b9;
	s21 = a10 * b11 + a11 * b10;
	s22 = a11 * b11;
	s23 = 0;

	carry = (s0 + (1LL << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = (s2 + (1LL << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = (s4 + (1LL << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = (s6 + (1LL << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = (s8 + (1LL << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = (s10 + (1LL << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);
	carry = (s12 + (1LL << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1ULL << 21);
	carry = (s14 + (int64_t)(1L << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1ULL << 21);
	carry = (s16 + (1LL << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1ULL << 21);
	carry = (s18 + (1LL << 20)) >> 21;
	s19 += carry;
	s18 -= carry * (1ULL << 21);
	carry = (s20 + (1LL << 20)) >> 21;
	s21 += carry;
	s20 -= carry * (1ULL << 21);
	carry = (s22 + (1LL << 20)) >> 21;
	s23 += carry;
	s22 -= carry * (1ULL << 21);

	carry = (s1 + (1LL << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = (s3 + (1LL << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = (s5 + (1LL << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = (s7 + (1LL << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = (s9 + (1LL << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = (s11 + (1LL << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);
	carry = (s13 + (1LL << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1ULL << 21);
	carry = (s15 + (1LL << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1ULL << 21);
	carry = (s17 + (1LL << 20)) >> 21;
	s18 += carry;
	s17 -= carry * (1ULL << 21);
	carry = (s19 + (1LL << 20)) >> 21;
	s20 += carry;
	s19 -= carry * (1ULL << 21);
	carry = (s21 + (1LL << 20)) >> 21;
	s22 += carry;
	s21 -= carry * (1ULL << 21);

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;

	carry = (s6 + (1LL << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = (s8 + (1LL << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = (s10 + (1LL << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);
	carry = (s12 + (1LL << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1ULL << 21);
	carry = (s14 + (1LL << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1ULL << 21);
	carry = (s16 + (1LL << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1ULL << 21);

	carry = (s7 + (1LL << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = (s9 + (1LL << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = (s11 + (1LL << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);
	carry = (s13 + (1LL << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1ULL << 21);
	carry = (s15 + (1LL << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1ULL << 21);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = (s0 + (1LL << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = (s2 + (1LL << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = (s4 + (1LL << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = (s6 + (1LL << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = (s8 + (1LL << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = (s10 + (1LL << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);

	carry = (s1 + (1LL << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = (s3 + (1LL << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = (s5 + (1LL << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = (s7 + (1LL << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = (s9 + (1LL << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = (s11 + (1LL << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);
	carry = s11 >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);

	S[SOffset] = static_cast<uint8_t>(s0);
	S[SOffset + 1] = static_cast<uint8_t>(s0 >> 8);
	S[SOffset + 2] = static_cast<uint8_t>((s0 >> 16) | (s1 * (1ULL << 5)));
	S[SOffset + 3] = static_cast<uint8_t>(s1 >> 3);
	S[SOffset + 4] = static_cast<uint8_t>(s1 >> 11);
	S[SOffset + 5] = static_cast<uint8_t>((s1 >> 19) | (s2 * (1ULL << 2)));
	S[SOffset + 6] = static_cast<uint8_t>(s2 >> 6);
	S[SOffset + 7] = static_cast<uint8_t>((s2 >> 14) | (s3 * (1ULL << 7)));
	S[SOffset + 8] = static_cast<uint8_t>(s3 >> 1);
	S[SOffset + 9] = static_cast<uint8_t>(s3 >> 9);
	S[SOffset + 10] = static_cast<uint8_t>((s3 >> 17) | (s4 * (1ULL << 4)));
	S[SOffset + 11] = static_cast<uint8_t>(s4 >> 4);
	S[SOffset + 12] = static_cast<uint8_t>(s4 >> 12);
	S[SOffset + 13] = static_cast<uint8_t>((s4 >> 20) | (s5 * (1ULL << 1)));
	S[SOffset + 14] = static_cast<uint8_t>(s5 >> 7);
	S[SOffset + 15] = static_cast<uint8_t>((s5 >> 15) | (s6 * (1ULL << 6)));
	S[SOffset + 16] = static_cast<uint8_t>(s6 >> 2);
	S[SOffset + 17] = static_cast<uint8_t>(s6 >> 10);
	S[SOffset + 18] = static_cast<uint8_t>((s6 >> 18) | (s7 * (1ULL << 3)));
	S[SOffset + 19] = static_cast<uint8_t>(s7 >> 5);
	S[SOffset + 20] = static_cast<uint8_t>(s7 >> 13);
	S[SOffset + 21] = static_cast<uint8_t>(s8);
	S[SOffset + 22] = static_cast<uint8_t>(s8 >> 8);
	S[SOffset + 23] = static_cast<uint8_t>((s8 >> 16) | (s9 * (1ULL << 5)));
	S[SOffset + 24] = static_cast<uint8_t>(s9 >> 3);
	S[SOffset + 25] = static_cast<uint8_t>(s9 >> 11);
	S[SOffset + 26] = static_cast<uint8_t>((s9 >> 19) | (s10 * (1ULL << 2)));
	S[SOffset + 27] = static_cast<uint8_t>(s10 >> 6);
	S[SOffset + 28] = static_cast<uint8_t>((s10 >> 14) | (s11 * (1ULL << 7)));
	S[SOffset + 29] = static_cast<uint8_t>(s11 >> 1);
	S[SOffset + 30] = static_cast<uint8_t>(s11 >> 9);
	S[SOffset + 31] = static_cast<uint8_t>(s11 >> 17);
}

void EC25519::Sc25519Reduce(std::vector<uint8_t> &S)
{
	int64_t carry;
	int64_t s0;
	int64_t s1;
	int64_t s2;
	int64_t s3;
	int64_t s4;
	int64_t s5;
	int64_t s6;
	int64_t s7;
	int64_t s8;
	int64_t s9;
	int64_t s10;
	int64_t s11;
	int64_t s12;
	int64_t s13;
	int64_t s14;
	int64_t s15;
	int64_t s16;
	int64_t s17;
	int64_t s18;
	int64_t s19;
	int64_t s20;
	int64_t s21;
	int64_t s22;
	int64_t s23;

	s0 = 2097151 & EcdsaBaseLoad3(S, 0);
	s1 = 2097151 & (EcdsaBaseLoad4(S, 2) >> 5);
	s2 = 2097151 & (EcdsaBaseLoad3(S, 5) >> 2);
	s3 = 2097151 & (EcdsaBaseLoad4(S, 7) >> 7);
	s4 = 2097151 & (EcdsaBaseLoad4(S, 10) >> 4);
	s5 = 2097151 & (EcdsaBaseLoad3(S, 13) >> 1);
	s6 = 2097151 & (EcdsaBaseLoad4(S, 15) >> 6);
	s7 = 2097151 & (EcdsaBaseLoad3(S, 18) >> 3);
	s8 = 2097151 & EcdsaBaseLoad3(S, 21);
	s9 = 2097151 & (EcdsaBaseLoad4(S, 23) >> 5);
	s10 = 2097151 & (EcdsaBaseLoad3(S, 26) >> 2);
	s11 = 2097151 & (EcdsaBaseLoad4(S, 28) >> 7);
	s12 = 2097151 & (EcdsaBaseLoad4(S, 31) >> 4);
	s13 = 2097151 & (EcdsaBaseLoad3(S, 34) >> 1);
	s14 = 2097151 & (EcdsaBaseLoad4(S, 36) >> 6);
	s15 = 2097151 & (EcdsaBaseLoad3(S, 39) >> 3);
	s16 = 2097151 & EcdsaBaseLoad3(S, 42);
	s17 = 2097151 & (EcdsaBaseLoad4(S, 44) >> 5);
	s18 = 2097151 & (EcdsaBaseLoad3(S, 47) >> 2);
	s19 = 2097151 & (EcdsaBaseLoad4(S, 49) >> 7);
	s20 = 2097151 & (EcdsaBaseLoad4(S, 52) >> 4);
	s21 = 2097151 & (EcdsaBaseLoad3(S, 55) >> 1);
	s22 = 2097151 & (EcdsaBaseLoad4(S, 57) >> 6);
	s23 = (EcdsaBaseLoad4(S, 60) >> 3);

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;

	carry = (s6 + (1LL << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = (s8 + (1LL << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = (s10 + (1ULL << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);
	carry = (s12 + (1LL << 20)) >> 21;
	s13 += carry;
	s12 -= carry * (1ULL << 21);
	carry = (s14 + (1LL << 20)) >> 21;
	s15 += carry;
	s14 -= carry * (1ULL << 21);
	carry = (s16 + (1LL << 20)) >> 21;
	s17 += carry;
	s16 -= carry * (1ULL << 21);

	carry = (s7 + (1LL << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = (s9 + (1LL << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = (s11 + (1LL << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);
	carry = (s13 + (1LL << 20)) >> 21;
	s14 += carry;
	s13 -= carry * (1ULL << 21);
	carry = (s15 + (1LL << 20)) >> 21;
	s16 += carry;
	s15 -= carry * (1ULL << 21);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = (s0 + (1LL << 20)) >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = (s2 + (1LL << 20)) >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = (s4 + (1LL << 20)) >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = (s6 + (1LL << 20)) >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = (s8 + (1LL << 20)) >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = (s10 + (1LL << 20)) >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);

	carry = (s1 + (1LL << 20)) >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = (s3 + (1LL << 20)) >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = (s5 + (1LL << 20)) >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = (s7 + (1LL << 20)) >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = (s9 + (1LL << 20)) >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = (s11 + (1LL << 20)) >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);
	carry = s11 >> 21;
	s12 += carry;
	s11 -= carry * (1ULL << 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;

	carry = s0 >> 21;
	s1 += carry;
	s0 -= carry * (1ULL << 21);
	carry = s1 >> 21;
	s2 += carry;
	s1 -= carry * (1ULL << 21);
	carry = s2 >> 21;
	s3 += carry;
	s2 -= carry * (1ULL << 21);
	carry = s3 >> 21;
	s4 += carry;
	s3 -= carry * (1ULL << 21);
	carry = s4 >> 21;
	s5 += carry;
	s4 -= carry * (1ULL << 21);
	carry = s5 >> 21;
	s6 += carry;
	s5 -= carry * (1ULL << 21);
	carry = s6 >> 21;
	s7 += carry;
	s6 -= carry * (1ULL << 21);
	carry = s7 >> 21;
	s8 += carry;
	s7 -= carry * (1ULL << 21);
	carry = s8 >> 21;
	s9 += carry;
	s8 -= carry * (1ULL << 21);
	carry = s9 >> 21;
	s10 += carry;
	s9 -= carry * (1ULL << 21);
	carry = s10 >> 21;
	s11 += carry;
	s10 -= carry * (1ULL << 21);

	S[0] = static_cast<uint8_t>(s0);
	S[1] = static_cast<uint8_t>(s0 >> 8);
	S[2] = static_cast<uint8_t>((s0 >> 16) | (s1 * (1ULL << 5)));
	S[3] = static_cast<uint8_t>(s1 >> 3);
	S[4] = static_cast<uint8_t>(s1 >> 11);
	S[5] = static_cast<uint8_t>((s1 >> 19) | (s2 * (1ULL << 2)));
	S[6] = static_cast<uint8_t>(s2 >> 6);
	S[7] = static_cast<uint8_t>((s2 >> 14) | (s3 * (1ULL << 7)));
	S[8] = static_cast<uint8_t>(s3 >> 1);
	S[9] = static_cast<uint8_t>(s3 >> 9);
	S[10] = static_cast<uint8_t>((s3 >> 17) | (s4 * (1ULL << 4)));
	S[11] = static_cast<uint8_t>(s4 >> 4);
	S[12] = static_cast<uint8_t>(s4 >> 12);
	S[13] = static_cast<uint8_t>((s4 >> 20) | (s5 * (1ULL << 1)));
	S[14] = static_cast<uint8_t>(s5 >> 7);
	S[15] = static_cast<uint8_t>((s5 >> 15) | (s6 * (1ULL << 6)));
	S[16] = static_cast<uint8_t>(s6 >> 2);
	S[17] = static_cast<uint8_t>(s6 >> 10);
	S[18] = static_cast<uint8_t>((s6 >> 18) | (s7 * (1ULL << 3)));
	S[19] = static_cast<uint8_t>(s7 >> 5);
	S[20] = static_cast<uint8_t>(s7 >> 13);
	S[21] = static_cast<uint8_t>(s8);
	S[22] = static_cast<uint8_t>(s8 >> 8);
	S[23] = static_cast<uint8_t>((s8 >> 16) | (s9 * (1ULL << 5)));
	S[24] = static_cast<uint8_t>(s9 >> 3);
	S[25] = static_cast<uint8_t>(s9 >> 11);
	S[26] = static_cast<uint8_t>((s9 >> 19) | (s10 * (1ULL << 2)));
	S[27] = static_cast<uint8_t>(s10 >> 6);
	S[28] = static_cast<uint8_t>((s10 >> 14) | (s11 * (1ULL << 7)));
	S[29] = static_cast<uint8_t>(s11 >> 1);
	S[30] = static_cast<uint8_t>(s11 >> 9);
	S[31] = static_cast<uint8_t>(s11 >> 17);
}

int32_t EC25519::Sc25519Verify(const std::vector<uint8_t> &X, const std::vector<uint8_t> &Y, const size_t N)
{
	size_t i;
	uint16_t d;

	d = 0;

	for (i = 0; i < N; i++)
	{
		d |= X[i] ^ Y[i];
	}

	return static_cast<int32_t>((1L & ((d - 1) >> 8)) - 1);
}

NAMESPACE_ECDHEND
