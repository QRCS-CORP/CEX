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

#ifndef CEX_SALSA_H
#define CEX_SALSA_H

#include "CexDomain.h"
#include "IntUtils.h"

NAMESPACE_STREAM

/**
* \internal
*/
class Salsa
{
public:

	static void Transform(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
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
			X4 ^= Utility::IntUtils::RotFL32(X0 + X12, 7);
			X8 ^= Utility::IntUtils::RotFL32(X4 + X0, 9);
			X12 ^= Utility::IntUtils::RotFL32(X8 + X4, 13);
			X0 ^= Utility::IntUtils::RotFL32(X12 + X8, 18);
			X9 ^= Utility::IntUtils::RotFL32(X5 + X1, 7);
			X13 ^= Utility::IntUtils::RotFL32(X9 + X5, 9);
			X1 ^= Utility::IntUtils::RotFL32(X13 + X9, 13);
			X5 ^= Utility::IntUtils::RotFL32(X1 + X13, 18);
			X14 ^= Utility::IntUtils::RotFL32(X10 + X6, 7);
			X2 ^= Utility::IntUtils::RotFL32(X14 + X10, 9);
			X6 ^= Utility::IntUtils::RotFL32(X2 + X14, 13);
			X10 ^= Utility::IntUtils::RotFL32(X6 + X2, 18);
			X3 ^= Utility::IntUtils::RotFL32(X15 + X11, 7);
			X7 ^= Utility::IntUtils::RotFL32(X3 + X15, 9);
			X11 ^= Utility::IntUtils::RotFL32(X7 + X3, 13);
			X15 ^= Utility::IntUtils::RotFL32(X11 + X7, 18);
			X1 ^= Utility::IntUtils::RotFL32(X0 + X3, 7);
			X2 ^= Utility::IntUtils::RotFL32(X1 + X0, 9);
			X3 ^= Utility::IntUtils::RotFL32(X2 + X1, 13);
			X0 ^= Utility::IntUtils::RotFL32(X3 + X2, 18);
			X6 ^= Utility::IntUtils::RotFL32(X5 + X4, 7);
			X7 ^= Utility::IntUtils::RotFL32(X6 + X5, 9);
			X4 ^= Utility::IntUtils::RotFL32(X7 + X6, 13);
			X5 ^= Utility::IntUtils::RotFL32(X4 + X7, 18);
			X11 ^= Utility::IntUtils::RotFL32(X10 + X9, 7);
			X8 ^= Utility::IntUtils::RotFL32(X11 + X10, 9);
			X9 ^= Utility::IntUtils::RotFL32(X8 + X11, 13);
			X10 ^= Utility::IntUtils::RotFL32(X9 + X8, 18);
			X12 ^= Utility::IntUtils::RotFL32(X15 + X14, 7);
			X13 ^= Utility::IntUtils::RotFL32(X12 + X15, 9);
			X14 ^= Utility::IntUtils::RotFL32(X13 + X12, 13);
			X15 ^= Utility::IntUtils::RotFL32(X14 + X13, 18);
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
		Utility::IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X10 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X11 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X12 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X13 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X14 + State[++ctr], Output, OutOffset); OutOffset += 4;
		Utility::IntUtils::Le32ToBytes(X15 + State[++ctr], Output, OutOffset);
	}

#if defined(__AVX__)

	template<class T>
	static void TransformW(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{

		size_t ctr = 0;
		T X0(State[ctr]);
		T X1(State[++ctr]);
		T X2(State[++ctr]);
		T X3(State[++ctr]);
		T X4(State[++ctr]);
		T X5(State[++ctr]);
		T X6(State[++ctr]);
		T X7(State[++ctr]);
		T X8(Counter, 0);
#if defined(__AVX512__)
		T X9(Counter, 16);
#elif defined(__AVX2__)
		T X9(Counter, 8);
#else
		T X9(Counter, 4);
#endif
		T X10(State[++ctr]);
		T X11(State[++ctr]);
		T X12(State[++ctr]);
		T X13(State[++ctr]);
		T X14(State[++ctr]);
		T X15(State[++ctr]);

		ctr = Rounds;
		while (ctr != 0)
		{
			X4 ^= T::RotL32(X0 + X12, 7);
			X8 ^= T::RotL32(X4 + X0, 9);
			X12 ^= T::RotL32(X8 + X4, 13);
			X0 ^= T::RotL32(X12 + X8, 18);
			X9 ^= T::RotL32(X5 + X1, 7);
			X13 ^= T::RotL32(X9 + X5, 9);
			X1 ^= T::RotL32(X13 + X9, 13);
			X5 ^= T::RotL32(X1 + X13, 18);
			X14 ^= T::RotL32(X10 + X6, 7);
			X2 ^= T::RotL32(X14 + X10, 9);
			X6 ^= T::RotL32(X2 + X14, 13);
			X10 ^= T::RotL32(X6 + X2, 18);
			X3 ^= T::RotL32(X15 + X11, 7);
			X7 ^= T::RotL32(X3 + X15, 9);
			X11 ^= T::RotL32(X7 + X3, 13);
			X15 ^= T::RotL32(X11 + X7, 18);
			X1 ^= T::RotL32(X0 + X3, 7);
			X2 ^= T::RotL32(X1 + X0, 9);
			X3 ^= T::RotL32(X2 + X1, 13);
			X0 ^= T::RotL32(X3 + X2, 18);
			X6 ^= T::RotL32(X5 + X4, 7);
			X7 ^= T::RotL32(X6 + X5, 9);
			X4 ^= T::RotL32(X7 + X6, 13);
			X5 ^= T::RotL32(X4 + X7, 18);
			X11 ^= T::RotL32(X10 + X9, 7);
			X8 ^= T::RotL32(X11 + X10, 9);
			X9 ^= T::RotL32(X8 + X11, 13);
			X10 ^= T::RotL32(X9 + X8, 18);
			X12 ^= T::RotL32(X15 + X14, 7);
			X13 ^= T::RotL32(X12 + X15, 9);
			X14 ^= T::RotL32(X13 + X12, 13);
			X15 ^= T::RotL32(X14 + X13, 18);
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
		X8 += T(Counter, 0);
#if defined(__AVX512__)
		X9 += T(Counter, 16);
#elif defined(__AVX2__)
		X9 += T(Counter, 8);
#else
		X9 += T(Counter, 4);
#endif
		X10 += T(State[++ctr]);
		X11 += T(State[++ctr]);
		X12 += T(State[++ctr]);
		X13 += T(State[++ctr]);
		X14 += T(State[++ctr]);
		X15 += T(State[++ctr]);

		T::Store16(Output, OutOffset, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);

	}

#endif
};

NAMESPACE_STREAMEND
#endif
