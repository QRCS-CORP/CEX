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
		uint X0 = State[0];
		uint X1 = State[1];
		uint X2 = State[2];
		uint X3 = State[3];
		uint X4 = State[4];
		uint X5 = State[5];
		uint X6 = State[6];
		uint X7 = State[7];
		uint X8 = Counter[0];
		uint X9 = Counter[1];
		uint X10 = State[8];
		uint X11 = State[9];
		uint X12 = State[10];
		uint X13 = State[11];
		uint X14 = State[12];
		uint X15 = State[13];

		size_t stateCtr = Rounds;
		while (stateCtr != 0)
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
			stateCtr -= 2;
		}

		Utility::IntUtils::Le32ToBytes(X0 + State[0], Output, OutOffset);
		Utility::IntUtils::Le32ToBytes(X1 + State[1], Output, OutOffset + 4);
		Utility::IntUtils::Le32ToBytes(X2 + State[2], Output, OutOffset + 8);
		Utility::IntUtils::Le32ToBytes(X3 + State[3], Output, OutOffset + 12);
		Utility::IntUtils::Le32ToBytes(X4 + State[4], Output, OutOffset + 16);
		Utility::IntUtils::Le32ToBytes(X5 + State[5], Output, OutOffset + 20);
		Utility::IntUtils::Le32ToBytes(X6 + State[6], Output, OutOffset + 24);
		Utility::IntUtils::Le32ToBytes(X7 + State[7], Output, OutOffset + 28);
		Utility::IntUtils::Le32ToBytes(X8 + Counter[0], Output, OutOffset + 32);
		Utility::IntUtils::Le32ToBytes(X9 + Counter[1], Output, OutOffset + 36);
		Utility::IntUtils::Le32ToBytes(X10 + State[8], Output, OutOffset + 40);
		Utility::IntUtils::Le32ToBytes(X11 + State[9], Output, OutOffset + 44);
		Utility::IntUtils::Le32ToBytes(X12 + State[10], Output, OutOffset + 48);
		Utility::IntUtils::Le32ToBytes(X13 + State[11], Output, OutOffset + 52);
		Utility::IntUtils::Le32ToBytes(X14 + State[12], Output, OutOffset + 56);
		Utility::IntUtils::Le32ToBytes(X15 + State[13], Output, OutOffset + 60);
	}

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)

	template<class T>
	static void TransformW(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter, std::vector<uint> &State, size_t Rounds)
	{
		T X0(State[0]);
		T X1(State[1]);
		T X2(State[2]);
		T X3(State[3]);
		T X4(State[4]);
		T X5(State[5]);
		T X6(State[6]);
		T X7(State[7]);
		T X8(Counter, 0);
#if defined(__AVX512__)
		T X9(Counter, 16);
#elif defined(__AVX2__)
		T X9(Counter, 8);
#else
		T X9(Counter, 4);
#endif
		T X10(State[8]);
		T X11(State[9]);
		T X12(State[10]);
		T X13(State[11]);
		T X14(State[12]);
		T X15(State[13]);

		size_t stateCtr = Rounds;
		while (stateCtr != 0)
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
			stateCtr -= 2;
		}

		// last round
		X0 += T(State[0]);
		X1 += T(State[1]);
		X2 += T(State[2]);
		X3 += T(State[3]);
		X4 += T(State[4]);
		X5 += T(State[5]);
		X6 += T(State[6]);
		X7 += T(State[7]);
		X8 += T(Counter, 0);
#if defined(__AVX512__)
		X9 += T(Counter, 16);
#elif defined(__AVX2__)
		X9 += T(Counter, 8);
#else
		X9 += T(Counter, 4);
#endif
		X10 += T(State[8]);
		X11 += T(State[9]);
		X12 += T(State[10]);
		X13 += T(State[11]);
		X14 += T(State[12]);
		X15 += T(State[13]);

		T::Store16(Output, OutOffset, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);

	}

#endif
};

NAMESPACE_STREAMEND
#endif
