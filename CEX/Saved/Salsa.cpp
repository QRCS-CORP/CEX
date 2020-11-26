#include "Salsa.h"
#include "IntegerTools.h"
#if defined(__AVX__)
#	include "Intrinsics.h"
#endif

NAMESPACE_STREAM

using Tools::IntegerTools;

#if defined(__AVX__)

void Salsa::PermuteP512V(std::vector<uint> &State)
{
	__m128i X0, X1, X2, X3;
	__m128i tmp;

	X0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[0]));
	X1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[4]));
	X2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[8]));
	X3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[12]));
	std::vector<__m128i> B{ X0, X1, X2, X3 };

	for (size_t i = 0; i < 8; i += 2)
	{
		tmp = _mm_add_epi32(X0, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(tmp, 7));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(tmp, 25));
		tmp = _mm_add_epi32(X1, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(tmp, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(tmp, 23));
		tmp = _mm_add_epi32(X2, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(tmp, 13));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(tmp, 19));
		tmp = _mm_add_epi32(X3, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(tmp, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(tmp, 14));

		X1 = _mm_shuffle_epi32(X1, 0x93);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x39);

		tmp = _mm_add_epi32(X0, X1);
		X3 = _mm_xor_si128(X3, _mm_slli_epi32(tmp, 7));
		X3 = _mm_xor_si128(X3, _mm_srli_epi32(tmp, 25));
		tmp = _mm_add_epi32(X3, X0);
		X2 = _mm_xor_si128(X2, _mm_slli_epi32(tmp, 9));
		X2 = _mm_xor_si128(X2, _mm_srli_epi32(tmp, 23));
		tmp = _mm_add_epi32(X2, X3);
		X1 = _mm_xor_si128(X1, _mm_slli_epi32(tmp, 13));
		X1 = _mm_xor_si128(X1, _mm_srli_epi32(tmp, 19));
		tmp = _mm_add_epi32(X1, X2);
		X0 = _mm_xor_si128(X0, _mm_slli_epi32(tmp, 18));
		X0 = _mm_xor_si128(X0, _mm_srli_epi32(tmp, 14));

		X1 = _mm_shuffle_epi32(X1, 0x39);
		X2 = _mm_shuffle_epi32(X2, 0x4E);
		X3 = _mm_shuffle_epi32(X3, 0x93);
	}

	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[0]), _mm_add_epi32(B[0], X0));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[4]), _mm_add_epi32(B[1], X1));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[8]), _mm_add_epi32(B[2], X2));
	_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[12]), _mm_add_epi32(B[3], X3));
}

#else

void Salsa::PermuteP512C(std::vector<uint> &State)
{
	uint X0;
	uint X1;
	uint X2;
	uint X3;
	uint X4;
	uint X5;
	uint X6;
	uint X7;
	uint X8;
	uint X9;
	uint X10;
	uint X11;
	uint X12;
	uint X13;
	uint X14;
	uint X15;
	size_t ctr;

	X0 = State[0];
	X1 = State[1];
	X2 = State[2];
	X3 = State[3];
	X4 = State[4];
	X5 = State[5];
	X6 = State[6];
	X7 = State[7];
	X8 = State[8];
	X9 = State[9];
	X10 = State[10];
	X11 = State[11];
	X12 = State[12];
	X13 = State[13];
	X14 = State[14];
	X15 = State[15];
	ctr = 8;

	while (ctr != 0)
	{
		X4 ^= IntegerTools::RotFL32(X0 + X12, 7);
		X8 ^= IntegerTools::RotFL32(X4 + X0, 9);
		X12 ^= IntegerTools::RotFL32(X8 + X4, 13);
		X0 ^= IntegerTools::RotFL32(X12 + X8, 18);
		X9 ^= IntegerTools::RotFL32(X5 + X1, 7);
		X13 ^= IntegerTools::RotFL32(X9 + X5, 9);
		X1 ^= IntegerTools::RotFL32(X13 + X9, 13);
		X5 ^= IntegerTools::RotFL32(X1 + X13, 18);
		X14 ^= IntegerTools::RotFL32(X10 + X6, 7);
		X2 ^= IntegerTools::RotFL32(X14 + X10, 9);
		X6 ^= IntegerTools::RotFL32(X2 + X14, 13);
		X10 ^= IntegerTools::RotFL32(X6 + X2, 18);
		X3 ^= IntegerTools::RotFL32(X15 + X11, 7);
		X7 ^= IntegerTools::RotFL32(X3 + X15, 9);
		X11 ^= IntegerTools::RotFL32(X7 + X3, 13);
		X15 ^= IntegerTools::RotFL32(X11 + X7, 18);
		X1 ^= IntegerTools::RotFL32(X0 + X3, 7);
		X2 ^= IntegerTools::RotFL32(X1 + X0, 9);
		X3 ^= IntegerTools::RotFL32(X2 + X1, 13);
		X0 ^= IntegerTools::RotFL32(X3 + X2, 18);
		X6 ^= IntegerTools::RotFL32(X5 + X4, 7);
		X7 ^= IntegerTools::RotFL32(X6 + X5, 9);
		X4 ^= IntegerTools::RotFL32(X7 + X6, 13);
		X5 ^= IntegerTools::RotFL32(X4 + X7, 18);
		X11 ^= IntegerTools::RotFL32(X10 + X9, 7);
		X8 ^= IntegerTools::RotFL32(X11 + X10, 9);
		X9 ^= IntegerTools::RotFL32(X8 + X11, 13);
		X10 ^= IntegerTools::RotFL32(X9 + X8, 18);
		X12 ^= IntegerTools::RotFL32(X15 + X14, 7);
		X13 ^= IntegerTools::RotFL32(X12 + X15, 9);
		X14 ^= IntegerTools::RotFL32(X13 + X12, 13);
		X15 ^= IntegerTools::RotFL32(X14 + X13, 18);
		ctr -= 2;
	}

	State[0] += X0;
	State[1] += X1;
	State[2] += X2;
	State[3] += X3;
	State[4] += X4;
	State[5] += X5;
	State[6] += X6;
	State[7] += X7;
	State[8] += X8;
	State[9] += X9;
	State[10] += X10;
	State[11] += X11;
	State[12] += X12;
	State[13] += X13;
	State[14] += X14;
	State[15] += X15;
}

#endif


NAMESPACE_STREAMEND