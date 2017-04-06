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

#ifndef _CEX_SALSA_H
#define _CEX_SALSA_H

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
class Salsa
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
		uint X8 = Counter[0];
		uint X9 = Counter[1];
		uint X10 = State[++ctr];
		uint X11 = State[++ctr];
		uint X12 = State[++ctr];
		uint X13 = State[++ctr];
		uint X14 = State[++ctr];
		uint X15 = State[++ctr];

		ctr = Rounds;
		while (ctr != 0)
		{
			X4 ^= IntUtils::RotFL32(X0 + X12, 7);
			X8 ^= IntUtils::RotFL32(X4 + X0, 9);
			X12 ^= IntUtils::RotFL32(X8 + X4, 13);
			X0 ^= IntUtils::RotFL32(X12 + X8, 18);
			X9 ^= IntUtils::RotFL32(X5 + X1, 7);
			X13 ^= IntUtils::RotFL32(X9 + X5, 9);
			X1 ^= IntUtils::RotFL32(X13 + X9, 13);
			X5 ^= IntUtils::RotFL32(X1 + X13, 18);
			X14 ^= IntUtils::RotFL32(X10 + X6, 7);
			X2 ^= IntUtils::RotFL32(X14 + X10, 9);
			X6 ^= IntUtils::RotFL32(X2 + X14, 13);
			X10 ^= IntUtils::RotFL32(X6 + X2, 18);
			X3 ^= IntUtils::RotFL32(X15 + X11, 7);
			X7 ^= IntUtils::RotFL32(X3 + X15, 9);
			X11 ^= IntUtils::RotFL32(X7 + X3, 13);
			X15 ^= IntUtils::RotFL32(X11 + X7, 18);
			X1 ^= IntUtils::RotFL32(X0 + X3, 7);
			X2 ^= IntUtils::RotFL32(X1 + X0, 9);
			X3 ^= IntUtils::RotFL32(X2 + X1, 13);
			X0 ^= IntUtils::RotFL32(X3 + X2, 18);
			X6 ^= IntUtils::RotFL32(X5 + X4, 7);
			X7 ^= IntUtils::RotFL32(X6 + X5, 9);
			X4 ^= IntUtils::RotFL32(X7 + X6, 13);
			X5 ^= IntUtils::RotFL32(X4 + X7, 18);
			X11 ^= IntUtils::RotFL32(X10 + X9, 7);
			X8 ^= IntUtils::RotFL32(X11 + X10, 9);
			X9 ^= IntUtils::RotFL32(X8 + X11, 13);
			X10 ^= IntUtils::RotFL32(X9 + X8, 18);
			X12 ^= IntUtils::RotFL32(X15 + X14, 7);
			X13 ^= IntUtils::RotFL32(X12 + X15, 9);
			X14 ^= IntUtils::RotFL32(X13 + X12, 13);
			X15 ^= IntUtils::RotFL32(X14 + X13, 18);
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
		IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X10 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X11 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X12 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X13 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X14 + State[++ctr], Output, OutOffset); OutOffset += 4;
		IntUtils::Le32ToBytes(X15 + State[++ctr], Output, OutOffset);
	}

	static void Transform256(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
#if defined(__AVX__)

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
			UInt128(Counter, 0),
			UInt128(Counter, 4),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
			UInt128(State[++ctr]),
		};

		ctr = Rounds;
		while (ctr != 0)
		{
			X[4] ^= UInt128::RotL32(X[0] + X[12], 7);
			X[8] ^= UInt128::RotL32(X[4] + X[0], 9);
			X[12] ^= UInt128::RotL32(X[8] + X[4], 13);
			X[0] ^= UInt128::RotL32(X[12] + X[8], 18);
			X[9] ^= UInt128::RotL32(X[5] + X[1], 7);
			X[13] ^= UInt128::RotL32(X[9] + X[5], 9);
			X[1] ^= UInt128::RotL32(X[13] + X[9], 13);
			X[5] ^= UInt128::RotL32(X[1] + X[13], 18);
			X[14] ^= UInt128::RotL32(X[10] + X[6], 7);
			X[2] ^= UInt128::RotL32(X[14] + X[10], 9);
			X[6] ^= UInt128::RotL32(X[2] + X[14], 13);
			X[10] ^= UInt128::RotL32(X[6] + X[2], 18);
			X[3] ^= UInt128::RotL32(X[15] + X[11], 7);
			X[7] ^= UInt128::RotL32(X[3] + X[15], 9);
			X[11] ^= UInt128::RotL32(X[7] + X[3], 13);
			X[15] ^= UInt128::RotL32(X[11] + X[7], 18);
			X[1] ^= UInt128::RotL32(X[0] + X[3], 7);
			X[2] ^= UInt128::RotL32(X[1] + X[0], 9);
			X[3] ^= UInt128::RotL32(X[2] + X[1], 13);
			X[0] ^= UInt128::RotL32(X[3] + X[2], 18);
			X[6] ^= UInt128::RotL32(X[5] + X[4], 7);
			X[7] ^= UInt128::RotL32(X[6] + X[5], 9);
			X[4] ^= UInt128::RotL32(X[7] + X[6], 13);
			X[5] ^= UInt128::RotL32(X[4] + X[7], 18);
			X[11] ^= UInt128::RotL32(X[10] + X[9], 7);
			X[8] ^= UInt128::RotL32(X[11] + X[10], 9);
			X[9] ^= UInt128::RotL32(X[8] + X[11], 13);
			X[10] ^= UInt128::RotL32(X[9] + X[8], 18);
			X[12] ^= UInt128::RotL32(X[15] + X[14], 7);
			X[13] ^= UInt128::RotL32(X[12] + X[15], 9);
			X[14] ^= UInt128::RotL32(X[13] + X[12], 13);
			X[15] ^= UInt128::RotL32(X[14] + X[13], 18);
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
		X[8] += UInt128(Counter, 0);
		X[9] += UInt128(Counter, 4);
		X[10] += UInt128(State[++ctr]);
		X[11] += UInt128(State[++ctr]);
		X[12] += UInt128(State[++ctr]);
		X[13] += UInt128(State[++ctr]);
		X[14] += UInt128(State[++ctr]);
		X[15] += UInt128(State[++ctr]);

		UInt128::StoreLE256(X, 0, Output, OutOffset);

#endif
	}

	static void Transform512(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
#if defined(__AVX2__)

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
			UInt256(Counter, 0),
			UInt256(Counter, 8),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
			UInt256(State[++ctr]),
		};

		ctr = Rounds;
		while (ctr != 0)
		{
			X[4] ^= UInt256::RotL32(X[0] + X[12], 7);
			X[8] ^= UInt256::RotL32(X[4] + X[0], 9);
			X[12] ^= UInt256::RotL32(X[8] + X[4], 13);
			X[0] ^= UInt256::RotL32(X[12] + X[8], 18);
			X[9] ^= UInt256::RotL32(X[5] + X[1], 7);
			X[13] ^= UInt256::RotL32(X[9] + X[5], 9);
			X[1] ^= UInt256::RotL32(X[13] + X[9], 13);
			X[5] ^= UInt256::RotL32(X[1] + X[13], 18);
			X[14] ^= UInt256::RotL32(X[10] + X[6], 7);
			X[2] ^= UInt256::RotL32(X[14] + X[10], 9);
			X[6] ^= UInt256::RotL32(X[2] + X[14], 13);
			X[10] ^= UInt256::RotL32(X[6] + X[2], 18);
			X[3] ^= UInt256::RotL32(X[15] + X[11], 7);
			X[7] ^= UInt256::RotL32(X[3] + X[15], 9);
			X[11] ^= UInt256::RotL32(X[7] + X[3], 13);
			X[15] ^= UInt256::RotL32(X[11] + X[7], 18);
			X[1] ^= UInt256::RotL32(X[0] + X[3], 7);
			X[2] ^= UInt256::RotL32(X[1] + X[0], 9);
			X[3] ^= UInt256::RotL32(X[2] + X[1], 13);
			X[0] ^= UInt256::RotL32(X[3] + X[2], 18);
			X[6] ^= UInt256::RotL32(X[5] + X[4], 7);
			X[7] ^= UInt256::RotL32(X[6] + X[5], 9);
			X[4] ^= UInt256::RotL32(X[7] + X[6], 13);
			X[5] ^= UInt256::RotL32(X[4] + X[7], 18);
			X[11] ^= UInt256::RotL32(X[10] + X[9], 7);
			X[8] ^= UInt256::RotL32(X[11] + X[10], 9);
			X[9] ^= UInt256::RotL32(X[8] + X[11], 13);
			X[10] ^= UInt256::RotL32(X[9] + X[8], 18);
			X[12] ^= UInt256::RotL32(X[15] + X[14], 7);
			X[13] ^= UInt256::RotL32(X[12] + X[15], 9);
			X[14] ^= UInt256::RotL32(X[13] + X[12], 13);
			X[15] ^= UInt256::RotL32(X[14] + X[13], 18);
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
		X[8] += UInt256(Counter, 0);
		X[9] += UInt256(Counter, 8);
		X[10] += UInt256(State[++ctr]);
		X[11] += UInt256(State[++ctr]);
		X[12] += UInt256(State[++ctr]);
		X[13] += UInt256(State[++ctr]);
		X[14] += UInt256(State[++ctr]);
		X[15] += UInt256(State[++ctr]);

		UInt256::StoreLE512(X, 0, Output, OutOffset);

#endif
	}
};

NAMESPACE_STREAMEND
#endif
