// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_CHACHA_H
#define _CEX_CHACHA_H

#include "CexDomain.h"
#include "IntUtils.h"
#include "UInt128.h"
#include "UInt256.h"

NAMESPACE_STREAM

using Utility::IntUtils;
using Numeric::UInt128;
using Numeric::UInt256;

/**
* \internal
*/
class ChaCha
{
public:

	static void Transform64(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
		size_t ctr = 0;
		uint X0 = State[ctr];
		uint X1 = State[++ctr];
		uint X2 = State[++ctr];
		uint X3 = State[++ctr];
		uint X4 = State[++ctr];
		uint X5 = State[++ctr];
		uint X6 = State[++ctr];
		uint X7 = State[++ctr];
		uint X8 = State[++ctr];
		uint X9 = State[++ctr];
		uint X10 = State[++ctr];
		uint X11 = State[++ctr];
		uint X12 = Counter[0];
		uint X13 = Counter[1];
		uint X14 = State[++ctr];
		uint X15 = State[++ctr];

		ctr = Rounds;
		while (ctr != 0)
		{
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
			ctr -= 2;
		}

		IntUtils::Le32ToBytes(X0 + State[ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X1 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X2 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X3 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X4 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X5 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X6 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X7 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X8 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X9 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X10 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X11 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X12 + Counter[0], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X13 + Counter[1], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X14 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X15 + State[++ctr], Output, OutOffset);
	}

	static void Transform256(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
		size_t ctr = 0;
		std::vector<UInt128> X{
			UInt128(State[ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(Counter, 0),
			UInt128(Counter, 4),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
		};

		ctr = Rounds;
		while (ctr != 0)
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
			ctr -= 2;
		}

		// last round
		X[0] += UInt128(State[ctr]);
		X[1] += UInt128(State[++ctr]);
		X[2] += UInt128(State[++ctr]);
		X[3] += UInt128(State[++ctr]);
		X[4] += UInt128(State[++ctr]);
		X[5] += UInt128(State[++ctr]);
		X[6] += UInt128(State[++ctr]);
		X[7] += UInt128(State[++ctr]);
		X[8] += UInt128(State[++ctr]);
		X[9] += UInt128(State[++ctr]);
		X[10] += UInt128(State[++ctr]);
		X[11] += UInt128(State[++ctr]);
		X[12] += UInt128(Counter, 0);
		X[13] += UInt128(Counter, 4);
		X[14] += UInt128(State[++ctr]);
		X[15] += UInt128(State[++ctr]);

		UInt128::StoreLE256(X, 0, Output, OutOffset);
	}

	static void Transform512(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
		size_t ctr = 0;
		std::vector<UInt256> X{
			UInt256(State[ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(Counter, 0),
			UInt256(Counter, 8),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
		};

		ctr = Rounds;
		while (ctr != 0)
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
			ctr -= 2;
		}

		// last round
		X[0] += UInt256(State[ctr]);
		X[1] += UInt256(State[++ctr]);
		X[2] += UInt256(State[++ctr]);
		X[3] += UInt256(State[++ctr]);
		X[4] += UInt256(State[++ctr]);
		X[5] += UInt256(State[++ctr]);
		X[6] += UInt256(State[++ctr]);
		X[7] += UInt256(State[++ctr]);
		X[8] += UInt256(State[++ctr]);
		X[9] += UInt256(State[++ctr]);
		X[10] += UInt256(State[++ctr]);
		X[11] += UInt256(State[++ctr]);
		X[12] += UInt256(Counter, 0);
		X[13] += UInt256(Counter, 8);
		X[14] += UInt256(State[++ctr]);
		X[15] += UInt256(State[++ctr]);

		UInt256::StoreLE512(X, 0, Output, OutOffset);
	}
};

NAMESPACE_STREAMEND
#endif
