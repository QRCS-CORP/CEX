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
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_CHACHA_H
#define CEX_CHACHA_H

#include "CexDomain.h"
#include "IntUtils.h"

NAMESPACE_STREAM

/**
* \internal
*/
class ChaCha
{
public:

	static void ChaChaTransform512(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
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
			X12 = Utility::IntUtils::RotFL32(X12 ^ X0, 16);
			X8 += X12;
			X4 = Utility::IntUtils::RotFL32(X4 ^ X8, 12);
			X0 += X4;
			X12 = Utility::IntUtils::RotFL32(X12 ^ X0, 8);
			X8 += X12;
			X4 = Utility::IntUtils::RotFL32(X4 ^ X8, 7);
			X1 += X5;
			X13 = Utility::IntUtils::RotFL32(X13 ^ X1, 16);
			X9 += X13;
			X5 = Utility::IntUtils::RotFL32(X5 ^ X9, 12);
			X1 += X5;
			X13 = Utility::IntUtils::RotFL32(X13 ^ X1, 8);
			X9 += X13;
			X5 = Utility::IntUtils::RotFL32(X5 ^ X9, 7);
			X2 += X6;
			X14 = Utility::IntUtils::RotFL32(X14 ^ X2, 16);
			X10 += X14;
			X6 = Utility::IntUtils::RotFL32(X6 ^ X10, 12);
			X2 += X6;
			X14 = Utility::IntUtils::RotFL32(X14 ^ X2, 8);
			X10 += X14;
			X6 = Utility::IntUtils::RotFL32(X6 ^ X10, 7);
			X3 += X7;
			X15 = Utility::IntUtils::RotFL32(X15 ^ X3, 16);
			X11 += X15;
			X7 = Utility::IntUtils::RotFL32(X7 ^ X11, 12);
			X3 += X7;
			X15 = Utility::IntUtils::RotFL32(X15 ^ X3, 8);
			X11 += X15;
			X7 = Utility::IntUtils::RotFL32(X7 ^ X11, 7);
			X0 += X5;
			X15 = Utility::IntUtils::RotFL32(X15 ^ X0, 16);
			X10 += X15;
			X5 = Utility::IntUtils::RotFL32(X5 ^ X10, 12);
			X0 += X5;
			X15 = Utility::IntUtils::RotFL32(X15 ^ X0, 8);
			X10 += X15;
			X5 = Utility::IntUtils::RotFL32(X5 ^ X10, 7);
			X1 += X6;
			X12 = Utility::IntUtils::RotFL32(X12 ^ X1, 16);
			X11 += X12;
			X6 = Utility::IntUtils::RotFL32(X6 ^ X11, 12);
			X1 += X6;
			X12 = Utility::IntUtils::RotFL32(X12 ^ X1, 8);
			X11 += X12;
			X6 = Utility::IntUtils::RotFL32(X6 ^ X11, 7);
			X2 += X7;
			X13 = Utility::IntUtils::RotFL32(X13 ^ X2, 16);
			X8 += X13;
			X7 = Utility::IntUtils::RotFL32(X7 ^ X8, 12);
			X2 += X7;
			X13 = Utility::IntUtils::RotFL32(X13 ^ X2, 8);
			X8 += X13;
			X7 = Utility::IntUtils::RotFL32(X7 ^ X8, 7);
			X3 += X4;
			X14 = Utility::IntUtils::RotFL32(X14 ^ X3, 16);
			X9 += X14;
			X4 = Utility::IntUtils::RotFL32(X4 ^ X9, 12);
			X3 += X4;
			X14 = Utility::IntUtils::RotFL32(X14 ^ X3, 8);
			X9 += X14;
			X4 = Utility::IntUtils::RotFL32(X4 ^ X9, 7);
			ctr -= 2;
		}

		Utility::IntUtils::Le32ToBytes(X0 + State[ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X1 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X2 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X3 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X4 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X5 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X6 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X7 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X8 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X9 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X10 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X11 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X12 + Counter[0], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X13 + Counter[1], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X14 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X15 + State[++ctr], Output, OutOffset);
	}

	template<class T>
	static void ChaChaTransformW(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
#if defined(__AVX__)

		size_t ctr = 0;
		T X0(State[ctr]);
		T X1(State[++ctr]);
		T X2(State[++ctr]);
		T X3(State[++ctr]);
		T X4(State[++ctr]);
		T X5(State[++ctr]);
		T X6(State[++ctr]);
		T X7(State[++ctr]);
		T X8(State[++ctr]);
		T X9(State[++ctr]);
		T X10(State[++ctr]);
		T X11(State[++ctr]);
		T X12(Counter, 0);
#if defined(__AVX512__)
		T X13(Counter, 16);
#elif defined(__AVX2__)
		T X13(Counter, 8);
#else
		T X13(Counter, 4);
#endif
		T X14(State[++ctr]);
		T X15(State[++ctr]);

		ctr = Rounds;
		while (ctr != 0)
		{
			X0 += X4;
			X12 = T::RotL32(X12 ^ X0, 16);
			X8 += X12;
			X4 = T::RotL32(X4 ^ X8, 12);
			X0 += X4;
			X12 = T::RotL32(X12 ^ X0, 8);
			X8 += X12;
			X4 = T::RotL32(X4 ^ X8, 7);
			X1 += X5;
			X13 = T::RotL32(X13 ^ X1, 16);
			X9 += X13;
			X5 = T::RotL32(X5 ^ X9, 12);
			X1 += X5;
			X13 = T::RotL32(X13 ^ X1, 8);
			X9 += X13;
			X5 = T::RotL32(X5 ^ X9, 7);
			X2 += X6;
			X14 = T::RotL32(X14 ^ X2, 16);
			X10 += X14;
			X6 = T::RotL32(X6 ^ X10, 12);
			X2 += X6;
			X14 = T::RotL32(X14 ^ X2, 8);
			X10 += X14;
			X6 = T::RotL32(X6 ^ X10, 7);
			X3 += X7;
			X15 = T::RotL32(X15 ^ X3, 16);
			X11 += X15;
			X7 = T::RotL32(X7 ^ X11, 12);
			X3 += X7;
			X15 = T::RotL32(X15 ^ X3, 8);
			X11 += X15;
			X7 = T::RotL32(X7 ^ X11, 7);
			X0 += X5;
			X15 = T::RotL32(X15 ^ X0, 16);
			X10 += X15;
			X5 = T::RotL32(X5 ^ X10, 12);
			X0 += X5;
			X15 = T::RotL32(X15 ^ X0, 8);
			X10 += X15;
			X5 = T::RotL32(X5 ^ X10, 7);
			X1 += X6;
			X12 = T::RotL32(X12 ^ X1, 16);
			X11 += X12;
			X6 = T::RotL32(X6 ^ X11, 12);
			X1 += X6;
			X12 = T::RotL32(X12 ^ X1, 8);
			X11 += X12;
			X6 = T::RotL32(X6 ^ X11, 7);
			X2 += X7;
			X13 = T::RotL32(X13 ^ X2, 16);
			X8 += X13;
			X7 = T::RotL32(X7 ^ X8, 12);
			X2 += X7;
			X13 = T::RotL32(X13 ^ X2, 8);
			X8 += X13;
			X7 = T::RotL32(X7 ^ X8, 7);
			X3 += X4;
			X14 = T::RotL32(X14 ^ X3, 16);
			X9 += X14;
			X4 = T::RotL32(X4 ^ X9, 12);
			X3 += X4;
			X14 = T::RotL32(X14 ^ X3, 8);
			X9 += X14;
			X4 = T::RotL32(X4 ^ X9, 7);
			ctr -= 2;
		}

		// last round
		X0 += T(State[ctr]);
		X1 += T(State[++ctr]);
		X2 += T(State[++ctr]);
		X3 += T(State[++ctr]);
		X4 += T(State[++ctr]);
		X5 += T(State[++ctr]);
		X6 += T(State[++ctr]);
		X7 += T(State[++ctr]);
		X8 += T(State[++ctr]);
		X9 += T(State[++ctr]);
		X10 += T(State[++ctr]);
		X11 += T(State[++ctr]);
		X12 += T(Counter, 0);
#if defined(__AVX512__)
		X13 += T(Counter, 16);
#elif defined(__AVX2__)
		X13 += T(Counter, 8);
#else
		X13 += T(Counter, 4);
#endif
		X14 += T(State[++ctr]);
		X15 += T(State[++ctr]);

		T::Store16(Output, OutOffset, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);
#endif
	}
};

NAMESPACE_STREAMEND
#endif
