#include "ChaCha.h"
#include "IntUtils.h"
#include "MemUtils.h"

#if defined(__AVX__)
#	include "UInt128.h"
#endif
#if defined(__AVX__)
#	include "UInt256.h"
#endif
#if defined(__AVX512__)
#	include "UInt512.h"
#endif

NAMESPACE_STREAM

using Utility::IntUtils;
using Utility::MemUtils;

#if defined(__AVX__)
using Numeric::UInt128;
#endif
#if defined(__AVX2__)
using Numeric::UInt256;
#endif
#if defined(__AVX512__)
using Numeric::UInt512;
#endif

struct ChaCha::ChaChaState
{
	// counter
	std::array<uint, 2> C;
	// state
	std::array<uint, 14> S;

	ChaChaState()
	{
		Reset();
	}

	void Increase(size_t Length)
	{
		C[0] += Length;

		if (C[0] < Length)
		{
			C[1] += 1;
		}
	}

	void Reset()
	{
		// 128 bits of counter
		C[0] = 0;
		C[1] = 0;
		MemUtils::Clear(C, 0, C.size() * sizeof(uint));
		MemUtils::Clear(S, 0, S.size() * sizeof(uint));
	}
};

void ChaCha::PermuteP512C(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 2> &Counter, std::array<uint, 14> &State, size_t Rounds)
{
	std::array<uint, 16> S;

	MemUtils::Copy(State, 0, S, 0, 12 * sizeof(uint));
	MemUtils::Copy(Counter, 0, S, 12, 2 * sizeof(uint));
	MemUtils::Copy(State, 12, S, 14, 2 * sizeof(uint));

	while (Rounds != 0)
	{
		S[0] += S[4];
		S[12] = IntUtils::RotFL32(S[12] ^ S[0], 16);
		S[8] += S[12];
		S[4] = IntUtils::RotFL32(S[4] ^ S[8], 12);
		S[0] += S[4];
		S[12] = IntUtils::RotFL32(S[12] ^ S[0], 8);
		S[8] += S[12];
		S[4] = IntUtils::RotFL32(S[4] ^ S[8], 7);
		S[1] += S[5];
		S[13] = IntUtils::RotFL32(S[13] ^ S[1], 16);
		S[9] += S[13];
		S[5] = IntUtils::RotFL32(S[5] ^ S[9], 12);
		S[1] += S[5];
		S[13] = IntUtils::RotFL32(S[13] ^ S[1], 8);
		S[9] += S[13];
		S[5] = IntUtils::RotFL32(S[5] ^ S[9], 7);
		S[2] += S[6];
		S[14] = IntUtils::RotFL32(S[14] ^ S[2], 16);
		S[10] += S[14];
		S[6] = IntUtils::RotFL32(S[6] ^ S[10], 12);
		S[2] += S[6];
		S[14] = IntUtils::RotFL32(S[14] ^ S[2], 8);
		S[10] += S[14];
		S[6] = IntUtils::RotFL32(S[6] ^ S[10], 7);
		S[3] += S[7];
		S[15] = IntUtils::RotFL32(S[15] ^ S[3], 16);
		S[11] += S[15];
		S[7] = IntUtils::RotFL32(S[7] ^ S[11], 12);
		S[3] += S[7];
		S[15] = IntUtils::RotFL32(S[15] ^ S[3], 8);
		S[11] += S[15];
		S[7] = IntUtils::RotFL32(S[7] ^ S[11], 7);
		S[0] += S[5];
		S[15] = IntUtils::RotFL32(S[15] ^ S[0], 16);
		S[10] += S[15];
		S[5] = IntUtils::RotFL32(S[5] ^ S[10], 12);
		S[0] += S[5];
		S[15] = IntUtils::RotFL32(S[15] ^ S[0], 8);
		S[10] += S[15];
		S[5] = IntUtils::RotFL32(S[5] ^ S[10], 7);
		S[1] += S[6];
		S[12] = IntUtils::RotFL32(S[12] ^ S[1], 16);
		S[11] += S[12];
		S[6] = IntUtils::RotFL32(S[6] ^ S[11], 12);
		S[1] += S[6];
		S[12] = IntUtils::RotFL32(S[12] ^ S[1], 8);
		S[11] += S[12];
		S[6] = IntUtils::RotFL32(S[6] ^ S[11], 7);
		S[2] += S[7];
		S[13] = IntUtils::RotFL32(S[13] ^ S[2], 16);
		S[8] += S[13];
		S[7] = IntUtils::RotFL32(S[7] ^ S[8], 12);
		S[2] += S[7];
		S[13] = IntUtils::RotFL32(S[13] ^ S[2], 8);
		S[8] += S[13];
		S[7] = IntUtils::RotFL32(S[7] ^ S[8], 7);
		S[3] += S[4];
		S[14] = IntUtils::RotFL32(S[14] ^ S[3], 16);
		S[9] += S[14];
		S[4] = IntUtils::RotFL32(S[4] ^ S[9], 12);
		S[3] += S[4];
		S[14] = IntUtils::RotFL32(S[14] ^ S[3], 8);
		S[9] += S[14];
		S[4] = IntUtils::RotFL32(S[4] ^ S[9], 7);
		Rounds -= 2;
	}

	IntUtils::Le32ToBytes(S[0] + State[0], Output, OutOffset);
	IntUtils::Le32ToBytes(S[1] + State[1], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(S[2] + State[2], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(S[3] + State[3], Output, OutOffset + 12);
	IntUtils::Le32ToBytes(S[4] + State[4], Output, OutOffset + 16);
	IntUtils::Le32ToBytes(S[5] + State[5], Output, OutOffset + 20);
	IntUtils::Le32ToBytes(S[6] + State[6], Output, OutOffset + 24);
	IntUtils::Le32ToBytes(S[7] + State[7], Output, OutOffset + 28);
	IntUtils::Le32ToBytes(S[8] + State[8], Output, OutOffset + 32);
	IntUtils::Le32ToBytes(S[9] + State[9], Output, OutOffset + 36);
	IntUtils::Le32ToBytes(S[10] + State[10], Output, OutOffset + 40);
	IntUtils::Le32ToBytes(S[11] + State[11], Output, OutOffset + 44);
	IntUtils::Le32ToBytes(S[12] + Counter[0], Output, OutOffset + 48);
	IntUtils::Le32ToBytes(S[13] + Counter[1], Output, OutOffset + 52);
	IntUtils::Le32ToBytes(S[14] + State[12], Output, OutOffset + 56);
	IntUtils::Le32ToBytes(S[15] + State[13], Output, OutOffset + 60);
}

void ChaCha::PermuteR20P512U(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 2> &Counter, std::array<uint, 14> &State)
{
	uint X0 = State[0];
	uint X1 = State[1];
	uint X2 = State[2];
	uint X3 = State[3];
	uint X4 = State[4];
	uint X5 = State[5];
	uint X6 = State[6];
	uint X7 = State[7];
	uint X8 = State[8];
	uint X9 = State[9];
	uint X10 = State[10];
	uint X11 = State[11];
	uint X12 = Counter[0];
	uint X13 = Counter[1];
	uint X14 = State[12];
	uint X15 = State[13];

	// rounds 0-1
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 2-3
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 4-5
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 6-7
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 8-9
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 10-11
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 12-13
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 14-15
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 16-17
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);
	// rounds 18-19
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 16);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 12);
	X0 += X4;
	X12 = IntUtils::RotFL32(X12 ^ X0, 8);
	X8 += X12;
	X4 = IntUtils::RotFL32(X4 ^ X8, 7);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 16);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 12);
	X1 += X5;
	X13 = IntUtils::RotFL32(X13 ^ X1, 8);
	X9 += X13;
	X5 = IntUtils::RotFL32(X5 ^ X9, 7);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 16);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 12);
	X2 += X6;
	X14 = IntUtils::RotFL32(X14 ^ X2, 8);
	X10 += X14;
	X6 = IntUtils::RotFL32(X6 ^ X10, 7);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 16);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 12);
	X3 += X7;
	X15 = IntUtils::RotFL32(X15 ^ X3, 8);
	X11 += X15;
	X7 = IntUtils::RotFL32(X7 ^ X11, 7);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 16);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 12);
	X0 += X5;
	X15 = IntUtils::RotFL32(X15 ^ X0, 8);
	X10 += X15;
	X5 = IntUtils::RotFL32(X5 ^ X10, 7);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 16);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 12);
	X1 += X6;
	X12 = IntUtils::RotFL32(X12 ^ X1, 8);
	X11 += X12;
	X6 = IntUtils::RotFL32(X6 ^ X11, 7);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 16);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 12);
	X2 += X7;
	X13 = IntUtils::RotFL32(X13 ^ X2, 8);
	X8 += X13;
	X7 = IntUtils::RotFL32(X7 ^ X8, 7);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 16);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 12);
	X3 += X4;
	X14 = IntUtils::RotFL32(X14 ^ X3, 8);
	X9 += X14;
	X4 = IntUtils::RotFL32(X4 ^ X9, 7);

	IntUtils::Le32ToBytes(X0 + State[0], Output, OutOffset);
	IntUtils::Le32ToBytes(X1 + State[1], Output, OutOffset + 4);
	IntUtils::Le32ToBytes(X2 + State[2], Output, OutOffset + 8);
	IntUtils::Le32ToBytes(X3 + State[3], Output, OutOffset + 12);
	IntUtils::Le32ToBytes(X4 + State[4], Output, OutOffset + 16);
	IntUtils::Le32ToBytes(X5 + State[5], Output, OutOffset + 20);
	IntUtils::Le32ToBytes(X6 + State[6], Output, OutOffset + 24);
	IntUtils::Le32ToBytes(X7 + State[7], Output, OutOffset + 28);
	IntUtils::Le32ToBytes(X8 + State[8], Output, OutOffset + 32);
	IntUtils::Le32ToBytes(X9 + State[9], Output, OutOffset + 36);
	IntUtils::Le32ToBytes(X10 + State[10], Output, OutOffset + 40);
	IntUtils::Le32ToBytes(X11 + State[11], Output, OutOffset + 44);
	IntUtils::Le32ToBytes(X12 + Counter[0], Output, OutOffset + 48);
	IntUtils::Le32ToBytes(X13 + Counter[1], Output, OutOffset + 52);
	IntUtils::Le32ToBytes(X14 + State[12], Output, OutOffset + 56);
	IntUtils::Le32ToBytes(X15 + State[13], Output, OutOffset + 60);
}

#if defined(__AVX__)

void ChaCha::PermuteP4x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 8> &Counter, std::array<uint, 14> &State, size_t Rounds)
{
	std::array<UInt128, 16> X{ UInt128(State[0]), UInt128(State[1]), UInt128(State[2]), UInt128(State[3]),
		UInt128(State[4]), UInt128(State[5]), UInt128(State[6]), UInt128(State[7]), 
		UInt128(State[8]), UInt128(State[9]), UInt128(State[10]), UInt128(State[11]), 
		UInt128(Counter, 0), UInt128(Counter, 4), UInt128(State[12]), UInt128(State[13]) };

	while (Rounds != 0)
	{
		X[0] += X[4];
		X[12] = UInt128::RotL32(X[12] ^ X[0], 16);
		X[8] += X[12];
		X[4] = UInt128::RotL32(X[4] ^ X[8], 12);
		X[0] += X[4];
		X[12] = UInt128::RotL32(X[12] ^ X[0], 8);
		X[8] += X[12];
		X[4] = UInt128::RotL32(X[4] ^ X[8], 7);
		X[1] += X[5];
		X[13] = UInt128::RotL32(X[13] ^ X[1], 16);
		X[9] += X[13];
		X[5] = UInt128::RotL32(X[5] ^ X[9], 12);
		X[1] += X[5];
		X[13] = UInt128::RotL32(X[13] ^ X[1], 8);
		X[9] += X[13];
		X[5] = UInt128::RotL32(X[5] ^ X[9], 7);
		X[2] += X[6];
		X[14] = UInt128::RotL32(X[14] ^ X[2], 16);
		X[10] += X[14];
		X[6] = UInt128::RotL32(X[6] ^ X[10], 12);
		X[2] += X[6];
		X[14] = UInt128::RotL32(X[14] ^ X[2], 8);
		X[10] += X[14];
		X[6] = UInt128::RotL32(X[6] ^ X[10], 7);
		X[3] += X[7];
		X[15] = UInt128::RotL32(X[15] ^ X[3], 16);
		X[11] += X[15];
		X[7] = UInt128::RotL32(X[7] ^ X[11], 12);
		X[3] += X[7];
		X[15] = UInt128::RotL32(X[15] ^ X[3], 8);
		X[11] += X[15];
		X[7] = UInt128::RotL32(X[7] ^ X[11], 7);
		X[0] += X[5];
		X[15] = UInt128::RotL32(X[15] ^ X[0], 16);
		X[10] += X[15];
		X[5] = UInt128::RotL32(X[5] ^ X[10], 12);
		X[0] += X[5];
		X[15] = UInt128::RotL32(X[15] ^ X[0], 8);
		X[10] += X[15];
		X[5] = UInt128::RotL32(X[5] ^ X[10], 7);
		X[1] += X[6];
		X[12] = UInt128::RotL32(X[12] ^ X[1], 16);
		X[11] += X[12];
		X[6] = UInt128::RotL32(X[6] ^ X[11], 12);
		X[1] += X[6];
		X[12] = UInt128::RotL32(X[12] ^ X[1], 8);
		X[11] += X[12];
		X[6] = UInt128::RotL32(X[6] ^ X[11], 7);
		X[2] += X[7];
		X[13] = UInt128::RotL32(X[13] ^ X[2], 16);
		X[8] += X[13];
		X[7] = UInt128::RotL32(X[7] ^ X[8], 12);
		X[2] += X[7];
		X[13] = UInt128::RotL32(X[13] ^ X[2], 8);
		X[8] += X[13];
		X[7] = UInt128::RotL32(X[7] ^ X[8], 7);
		X[3] += X[4];
		X[14] = UInt128::RotL32(X[14] ^ X[3], 16);
		X[9] += X[14];
		X[4] = UInt128::RotL32(X[4] ^ X[9], 12);
		X[3] += X[4];
		X[14] = UInt128::RotL32(X[14] ^ X[3], 8);
		X[9] += X[14];
		X[4] = UInt128::RotL32(X[4] ^ X[9], 7);
		Rounds -= 2;
	}

	X[0] += UInt128(State[0]);
	X[1] += UInt128(State[1]);
	X[2] += UInt128(State[2]);
	X[3] += UInt128(State[3]);
	X[4] += UInt128(State[4]);
	X[5] += UInt128(State[5]);
	X[6] += UInt128(State[6]);
	X[7] += UInt128(State[7]);
	X[8] += UInt128(State[8]);
	X[9] += UInt128(State[9]);
	X[10] += UInt128(State[10]);
	X[11] += UInt128(State[11]);
	X[12] += UInt128(Counter, 0);
	X[13] += UInt128(Counter, 4);
	X[14] += UInt128(State[12]);
	X[15] += UInt128(State[13]);

	Store4xUL512(X, Output, OutOffset);
}

#endif

#if defined(__AVX2__)

void ChaCha::PermuteP8x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 16> &Counter, std::array<uint, 14> &State, size_t Rounds)
{
	std::array<UInt256, 16> X{ UInt256(State[0]), UInt256(State[1]), UInt256(State[2]), UInt256(State[3]),
		UInt256(State[4]), UInt256(State[5]), UInt256(State[6]), UInt256(State[7]),
		UInt256(State[8]), UInt256(State[9]), UInt256(State[10]), UInt256(State[11]),
		UInt256(Counter, 0), UInt256(Counter, 8), UInt256(State[12]), UInt256(State[13]) };

	while (Rounds != 0)
	{
		X[0] += X[4];
		X[12] = UInt256::RotL32(X[12] ^ X[0], 16);
		X[8] += X[12];
		X[4] = UInt256::RotL32(X[4] ^ X[8], 12);
		X[0] += X[4];
		X[12] = UInt256::RotL32(X[12] ^ X[0], 8);
		X[8] += X[12];
		X[4] = UInt256::RotL32(X[4] ^ X[8], 7);
		X[1] += X[5];
		X[13] = UInt256::RotL32(X[13] ^ X[1], 16);
		X[9] += X[13];
		X[5] = UInt256::RotL32(X[5] ^ X[9], 12);
		X[1] += X[5];
		X[13] = UInt256::RotL32(X[13] ^ X[1], 8);
		X[9] += X[13];
		X[5] = UInt256::RotL32(X[5] ^ X[9], 7);
		X[2] += X[6];
		X[14] = UInt256::RotL32(X[14] ^ X[2], 16);
		X[10] += X[14];
		X[6] = UInt256::RotL32(X[6] ^ X[10], 12);
		X[2] += X[6];
		X[14] = UInt256::RotL32(X[14] ^ X[2], 8);
		X[10] += X[14];
		X[6] = UInt256::RotL32(X[6] ^ X[10], 7);
		X[3] += X[7];
		X[15] = UInt256::RotL32(X[15] ^ X[3], 16);
		X[11] += X[15];
		X[7] = UInt256::RotL32(X[7] ^ X[11], 12);
		X[3] += X[7];
		X[15] = UInt256::RotL32(X[15] ^ X[3], 8);
		X[11] += X[15];
		X[7] = UInt256::RotL32(X[7] ^ X[11], 7);
		X[0] += X[5];
		X[15] = UInt256::RotL32(X[15] ^ X[0], 16);
		X[10] += X[15];
		X[5] = UInt256::RotL32(X[5] ^ X[10], 12);
		X[0] += X[5];
		X[15] = UInt256::RotL32(X[15] ^ X[0], 8);
		X[10] += X[15];
		X[5] = UInt256::RotL32(X[5] ^ X[10], 7);
		X[1] += X[6];
		X[12] = UInt256::RotL32(X[12] ^ X[1], 16);
		X[11] += X[12];
		X[6] = UInt256::RotL32(X[6] ^ X[11], 12);
		X[1] += X[6];
		X[12] = UInt256::RotL32(X[12] ^ X[1], 8);
		X[11] += X[12];
		X[6] = UInt256::RotL32(X[6] ^ X[11], 7);
		X[2] += X[7];
		X[13] = UInt256::RotL32(X[13] ^ X[2], 16);
		X[8] += X[13];
		X[7] = UInt256::RotL32(X[7] ^ X[8], 12);
		X[2] += X[7];
		X[13] = UInt256::RotL32(X[13] ^ X[2], 8);
		X[8] += X[13];
		X[7] = UInt256::RotL32(X[7] ^ X[8], 7);
		X[3] += X[4];
		X[14] = UInt256::RotL32(X[14] ^ X[3], 16);
		X[9] += X[14];
		X[4] = UInt256::RotL32(X[4] ^ X[9], 12);
		X[3] += X[4];
		X[14] = UInt256::RotL32(X[14] ^ X[3], 8);
		X[9] += X[14];
		X[4] = UInt256::RotL32(X[4] ^ X[9], 7);
		Rounds -= 2;
	}

	X[0] += UInt256(State[0]);
	X[1] += UInt256(State[1]);
	X[2] += UInt256(State[2]);
	X[3] += UInt256(State[3]);
	X[4] += UInt256(State[4]);
	X[5] += UInt256(State[5]);
	X[6] += UInt256(State[6]);
	X[7] += UInt256(State[7]);
	X[8] += UInt256(State[8]);
	X[9] += UInt256(State[9]);
	X[10] += UInt256(State[10]);
	X[11] += UInt256(State[11]);
	X[12] += UInt256(Counter, 0);
	X[13] += UInt256(Counter, 8);
	X[14] += UInt256(State[12]);
	X[15] += UInt256(State[13]);

	Store8xUL512(X, Output, OutOffset);
}

#endif

#if defined(__AVX512__)

void ChaCha::PermuteP16x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 32> &Counter, std::array<uint, 14> &State, size_t Rounds)
{
	std::array<UInt512, 16> X{ UInt512(State[0]), UInt512(State[1]), UInt512(State[2]), UInt512(State[3]),
		UInt512(State[4]), UInt512(State[5]), UInt512(State[6]), UInt512(State[7]),
		UInt512(State[8]), UInt512(State[9]), UInt512(State[10]), UInt512(State[11]),
		UInt512(Counter, 0), UInt512(Counter, 16), UInt512(State[12]), UInt512(State[13]) };

	while (Rounds != 0)
	{
		X[0] += X[4];
		X[12] = UInt512::RotL32(X[12] ^ X[0], 16);
		X[8] += X[12];
		X[4] = UInt512::RotL32(X[4] ^ X[8], 12);
		X[0] += X[4];
		X[12] = UInt512::RotL32(X[12] ^ X[0], 8);
		X[8] += X[12];
		X[4] = UInt512::RotL32(X[4] ^ X[8], 7);
		X[1] += X[5];
		X[13] = UInt512::RotL32(X[13] ^ X[1], 16);
		X[9] += X[13];
		X[5] = UInt512::RotL32(X[5] ^ X[9], 12);
		X[1] += X[5];
		X[13] = UInt512::RotL32(X[13] ^ X[1], 8);
		X[9] += X[13];
		X[5] = UInt512::RotL32(X[5] ^ X[9], 7);
		X[2] += X[6];
		X[14] = UInt512::RotL32(X[14] ^ X[2], 16);
		X[10] += X[14];
		X[6] = UInt512::RotL32(X[6] ^ X[10], 12);
		X[2] += X[6];
		X[14] = UInt512::RotL32(X[14] ^ X[2], 8);
		X[10] += X[14];
		X[6] = UInt512::RotL32(X[6] ^ X[10], 7);
		X[3] += X[7];
		X[15] = UInt512::RotL32(X[15] ^ X[3], 16);
		X[11] += X[15];
		X[7] = UInt512::RotL32(X[7] ^ X[11], 12);
		X[3] += X[7];
		X[15] = UInt512::RotL32(X[15] ^ X[3], 8);
		X[11] += X[15];
		X[7] = UInt512::RotL32(X[7] ^ X[11], 7);
		X[0] += X[5];
		X[15] = UInt512::RotL32(X[15] ^ X[0], 16);
		X[10] += X[15];
		X[5] = UInt512::RotL32(X[5] ^ X[10], 12);
		X[0] += X[5];
		X[15] = UInt512::RotL32(X[15] ^ X[0], 8);
		X[10] += X[15];
		X[5] = UInt512::RotL32(X[5] ^ X[10], 7);
		X[1] += X[6];
		X[12] = UInt512::RotL32(X[12] ^ X[1], 16);
		X[11] += X[12];
		X[6] = UInt512::RotL32(X[6] ^ X[11], 12);
		X[1] += X[6];
		X[12] = UInt512::RotL32(X[12] ^ X[1], 8);
		X[11] += X[12];
		X[6] = UInt512::RotL32(X[6] ^ X[11], 7);
		X[2] += X[7];
		X[13] = UInt512::RotL32(X[13] ^ X[2], 16);
		X[8] += X[13];
		X[7] = UInt512::RotL32(X[7] ^ X[8], 12);
		X[2] += X[7];
		X[13] = UInt512::RotL32(X[13] ^ X[2], 8);
		X[8] += X[13];
		X[7] = UInt512::RotL32(X[7] ^ X[8], 7);
		X[3] += X[4];
		X[14] = UInt512::RotL32(X[14] ^ X[3], 16);
		X[9] += X[14];
		X[4] = UInt512::RotL32(X[4] ^ X[9], 12);
		X[3] += X[4];
		X[14] = UInt512::RotL32(X[14] ^ X[3], 8);
		X[9] += X[14];
		X[4] = UInt512::RotL32(X[4] ^ X[9], 7);
		Rounds -= 2;
	}

	// last round
	X[0] += UInt512(State[0]);
	X[1] += UInt512(State[1]);
	X[2] += UInt512(State[2]);
	X[3] += UInt512(State[3]);
	X[4] += UInt512(State[4]);
	X[5] += UInt512(State[5]);
	X[6] += UInt512(State[6]);
	X[7] += UInt512(State[7]);
	X[8] += UInt512(State[8]);
	X[9] += UInt512(State[9]);
	X[10] += UInt512(State[10]);
	X[11] += UInt512(State[11]);
	X[12] += UInt512(Counter, 0);
	X[13] += UInt512(Counter, 16);
	X[14] += UInt512(State[12]);
	X[15] += UInt512(State[13]);

	Store16xUL512(X, Output, OutOffset);
}

#endif

NAMESPACE_STREAMEND