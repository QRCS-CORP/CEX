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
		T X8(State[8]);
		T X9(State[9]);
		T X10(State[10]);
		T X11(State[11]);
		T X12(Counter, 0);
#if defined(__AVX512__)
		T X13(Counter, 16);
#elif defined(__AVX2__)
		T X13(Counter, 8);
#else
		T X13(Counter, 4);
#endif
		T X14(State[12]);
		T X15(State[13]);

		size_t stateCtr = Rounds;
		while (stateCtr != 0)
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
		X8 += T(State[8]);
		X9 += T(State[9]);
		X10 += T(State[10]);
		X11 += T(State[11]);
		X12 += T(Counter, 0);
#if defined(__AVX512__)
		X13 += T(Counter, 16);
#elif defined(__AVX2__)
		X13 += T(Counter, 8);
#else
		X13 += T(Counter, 4);
#endif
		X14 += T(State[12]);
		X15 += T(State[13]);

		T::Store16(Output, OutOffset, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15);
	}

#endif

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
		uint X8 = State[8];
		uint X9 = State[9];
		uint X10 = State[10];
		uint X11 = State[11];
		uint X12 = Counter[0];
		uint X13 = Counter[1];
		uint X14 = State[12];
		uint X15 = State[13];

		size_t stateCtr = Rounds;
		while (stateCtr != 0)
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
		Utility::IntUtils::Le32ToBytes(X8 + State[8], Output, OutOffset + 32);
		Utility::IntUtils::Le32ToBytes(X9 + State[9], Output, OutOffset + 36);
		Utility::IntUtils::Le32ToBytes(X10 + State[10], Output, OutOffset + 40);
		Utility::IntUtils::Le32ToBytes(X11 + State[11], Output, OutOffset + 44);
		Utility::IntUtils::Le32ToBytes(X12 + Counter[0], Output, OutOffset + 48);
		Utility::IntUtils::Le32ToBytes(X13 + Counter[1], Output, OutOffset + 52);
		Utility::IntUtils::Le32ToBytes(X14 + State[12], Output, OutOffset + 56);
		Utility::IntUtils::Le32ToBytes(X15 + State[13], Output, OutOffset + 60);
	}
};

NAMESPACE_STREAMEND
#endif
