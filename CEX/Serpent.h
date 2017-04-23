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

#ifndef _CEX_SERPENT_H
#define _CEX_SERPENT_H

#include "CexDomain.h"

NAMESPACE_BLOCK

template<typename T>
void SHX::DecryptW(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Key)
{
#if defined(__AVX__)

	const size_t FNLRND = 4;
	const size_t INPOFF = T::size();
	size_t keyCtr = Key.size();

	// input round
	T R0(Input, InOffset);
	T R1(Input, InOffset + INPOFF);
	T R2(Input, InOffset + (INPOFF * 2));
	T R3(Input, InOffset + (INPOFF * 3));
	T::Transpose(R0, R1, R2, R3);

	R3 ^= T(Key[--keyCtr]);
	R2 ^= T(Key[--keyCtr]);
	R1 ^= T(Key[--keyCtr]);
	R0 ^= T(Key[--keyCtr]);

	// process 8 round blocks
	do
	{
		Ib7(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib6(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib5(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib4(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib3(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib2(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib1(R0, R1, R2, R3);
		R3 ^= T(Key[--keyCtr]);
		R2 ^= T(Key[--keyCtr]);
		R1 ^= T(Key[--keyCtr]);
		R0 ^= T(Key[--keyCtr]);
		InverseTransformW(R0, R1, R2, R3);

		Ib0(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != FNLRND)
		{
			R3 ^= T(Key[--keyCtr]);
			R2 ^= T(Key[--keyCtr]);
			R1 ^= T(Key[--keyCtr]);
			R0 ^= T(Key[--keyCtr]);
			InverseTransformW(R0, R1, R2, R3);
		}
	} while (keyCtr != FNLRND);

	// last round
	R3 ^= T(Key[--keyCtr]);
	R2 ^= T(Key[--keyCtr]);
	R1 ^= T(Key[--keyCtr]);
	R0 ^= T(Key[--keyCtr]);

	T::Transpose(R0, R1, R2, R3);
	R0.Store(Output, OutOffset);
	R1.Store(Output, OutOffset + INPOFF);
	R2.Store(Output, OutOffset + (INPOFF * 2));
	R3.Store(Output, OutOffset + (INPOFF * 3));

#endif
}

template<typename T>
void EncryptW(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Key)
{
#if defined(__AVX__)

	const size_t FNLRND = Key.size() - 5;
	const size_t INPOFF = T::size();
	int keyCtr = -1;

	// input round
	T R0(Input, InOffset);
	T R1(Input, InOffset + INPOFF);
	T R2(Input, InOffset + (INPOFF * 2));
	T R3(Input, InOffset + (INPOFF * 3));
	T::Transpose(R0, R1, R2, R3);

	// process 8 round blocks
	do
	{
		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb0(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb1(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb2(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb3(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb4(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb5(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb6(R0, R1, R2, R3);
		LinearTransformW(R0, R1, R2, R3);

		R0 ^= T(Key[++keyCtr]);
		R1 ^= T(Key[++keyCtr]);
		R2 ^= T(Key[++keyCtr]);
		R3 ^= T(Key[++keyCtr]);
		Sb7(R0, R1, R2, R3);

		// skip on last block
		if (keyCtr != FNLRND)
			LinearTransformW(R0, R1, R2, R3);
	} 
	while (keyCtr != FNLRND);

	// last round
	R0 ^= T(Key[++keyCtr]);
	R1 ^= T(Key[++keyCtr]);
	R2 ^= T(Key[++keyCtr]);
	R3 ^= T(Key[++keyCtr]);

	T::Transpose(R0, R1, R2, R3);
	R0.Store(Output, OutOffset);
	R1.Store(Output, OutOffset + INPOFF);
	R2.Store(Output, OutOffset + (INPOFF * 2));
	R3.Store(Output, OutOffset + (INPOFF * 3));

#endif
}

template<typename T>
void LinearTransform(T &R0, T &R1, T &R2, T &R3)
{
	R0 = Utility::IntUtils::RotL32(R0, 13);
	R2 = Utility::IntUtils::RotL32(R2, 3);
	R1 ^= R0 ^ R2;
	R3 ^= R2 ^ (R0 << 3);
	R1 = Utility::IntUtils::RotL32(R1, 1);
	R3 = Utility::IntUtils::RotL32(R3, 7);
	R0 ^= R1 ^ R3;
	R2 ^= R3 ^ (R1 << 7);
	R0 = Utility::IntUtils::RotL32(R0, 5);
	R2 = Utility::IntUtils::RotL32(R2, 22);
}

template<typename T>
void LinearTransformW(T &R0, T &R1, T &R2, T &R3)
{
	R0.RotL32(13);
	R2.RotL32(3);
	R1 ^= R0 ^ R2;
	R3 ^= R2 ^ (R0 << 3);
	R1.RotL32(1);
	R3.RotL32(7);
	R0 ^= R1 ^ R3;
	R2 ^= R3 ^ (R1 << 7);
	R0.RotL32(5);
	R2.RotL32(22);
}

template<typename T>
void InverseTransform(T &R0, T &R1, T &R2, T &R3)
{
	R2 = Utility::IntUtils::RotR32(R2, 22);
	R0 = Utility::IntUtils::RotR32(R0, 5);
	R2 ^= R3 ^ (R1 << 7);
	R0 ^= R1 ^ R3;
	R3 = Utility::IntUtils::RotR32(R3, 7);
	R1 = Utility::IntUtils::RotR32(R1, 1);
	R3 ^= R2 ^ (R0 << 3);
	R1 ^= R0 ^ R2;
	R2 = Utility::IntUtils::RotR32(R2, 3);
	R0 = Utility::IntUtils::RotR32(R0, 13);
}

template<typename T>
void InverseTransformW(T &R0, T &R1, T &R2, T &R3)
{
	R2.RotR32(22);
	R0.RotR32(5);
	R2 ^= R3 ^ (R1 << 7);
	R0 ^= R1 ^ R3;
	R3.RotR32(7);
	R1.RotR32(1);
	R3 ^= R2 ^ (R0 << 3);
	R1 ^= R0 ^ R2;
	R2.RotR32(3);
	R0.RotR32(13);
}

//~~~Serpent S-Boxes~~~//
template<typename T>
static void Sb0(T &R0, T &R1, T &R2, T &R3)
{
	R3 ^= R0;
	T B4 = R1;
	R1 &= R3;
	B4 ^= R2;
	R1 ^= R0;
	R0 |= R3;
	R0 ^= B4;
	B4 ^= R3;
	R3 ^= R2;
	R2 |= R1;
	R2 ^= B4;
	B4 = ~B4;
	B4 |= R1;
	R1 ^= R3;
	R1 ^= B4;
	R3 |= R0;
	R1 ^= R3;
	B4 ^= R3;
	R3 = R0; 
	R0 = R1; 
	R1 = B4; 
}

template<typename T>
static void Ib0(T &R0, T &R1, T &R2, T &R3)
{
	R2 = ~R2;
	T B4 = R1;
	R1 |= R0;
	B4 = ~B4;
	R1 ^= R2;
	R2 |= B4;
	R1 ^= R3;
	R0 ^= B4;
	R2 ^= R0;
	R0 &= R3;
	B4 ^= R0;
	R0 |= R1;
	R0 ^= R2;
	R3 ^= B4;
	R2 ^= R1;
	R3 ^= R0;
	R3 ^= R1;
	R2 &= R3;
	B4 ^= R2;
	R2 = R1;
	R1 = B4;
}

template<typename T>
static void Sb1(T &R0, T &R1, T &R2, T &R3)
{
	R0 = ~R0;
	R2 = ~R2;
	T B4 = R0;
	R0 &= R1;
	R2 ^= R0;
	R0 |= R3;
	R3 ^= R2;
	R1 ^= R0;
	R0 ^= B4;
	B4 |= R1;
	R1 ^= R3;
	R2 |= R0;
	R2 &= B4;
	R0 ^= R1;
	R1 &= R2;
	R1 ^= R0;
	R0 &= R2;
	B4 ^= R0;
	R0 = R2; 
	R2 = R3; 
	R3 = R1; 
	R1 = B4; 
}

template<typename T>
static void Ib1(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R1;
	R1 ^= R3;
	R3 &= R1;
	B4 ^= R2;
	R3 ^= R0;
	R0 |= R1;
	R2 ^= R3;
	R0 ^= B4;
	R0 |= R2;
	R1 ^= R3;
	R0 ^= R1;
	R1 |= R3;
	R1 ^= R0;
	B4 = ~B4;
	B4 ^= R1;
	R1 |= R0;
	R1 ^= R0;
	R1 |= B4;
	R3 ^= R1;
	R1 = R0;
	R0 = B4;
	B4 = R2;
	R2 = R3;
	R3 = B4;
}

template<typename T>
static void Sb2(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R0;
	R0 &= R2;
	R0 ^= R3;
	R2 ^= R1;
	R2 ^= R0;
	R3 |= B4;
	R3 ^= R1;
	B4 ^= R2;
	R1 = R3; 
	R3 |= B4;
	R3 ^= R0;
	R0 &= R1;
	B4 ^= R0;
	R1 ^= R3;
	R1 ^= B4;
	R0 = R2; 
	R2 = R1; 
	R1 = R3; 
	R3 = ~B4;
}

template<typename T>
static void Ib2(T &R0, T &R1, T &R2, T &R3)
{
	R2 ^= R3;
	R3 ^= R0;
	T B4 = R3;
	R3 &= R2;
	R3 ^= R1;
	R1 |= R2;
	R1 ^= B4;
	B4 &= R3;
	R2 ^= R3;
	B4 &= R0;
	B4 ^= R2;
	R2 &= R1;
	R2 |= R0;
	R3 = ~R3;
	R2 ^= R3;
	R0 ^= R3;
	R0 &= R1;
	R3 ^= B4;
	R3 ^= R0;
	R0 = R1;
	R1 = B4;
}

template<typename T>
static void Sb3(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R0;
	R0 |= R3;
	R3 ^= R1;
	R1 &= B4;
	B4 ^= R2;
	R2 ^= R3;
	R3 &= R0;
	B4 |= R1;
	R3 ^= B4;
	R0 ^= R1;
	B4 &= R0;
	R1 ^= R3;
	B4 ^= R2;
	R1 |= R0;
	R1 ^= R2;
	R0 ^= R3;
	R2 = R1; 
	R1 |= R3;
	R0 ^= R1;
	R1 = R2; 
	R2 = R3; 
	R3 = B4; 
}

template<typename T>
static void Ib3(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R2;
	R2 ^= R1;
	R0 ^= R2;
	B4 &= R2;
	B4 ^= R0;
	R0 &= R1;
	R1 ^= R3;
	R3 |= B4;
	R2 ^= R3;
	R0 ^= R3;
	R1 ^= B4;
	R3 &= R2;
	R3 ^= R1;
	R1 ^= R0;
	R1 |= R2;
	R0 ^= R3;
	R1 ^= B4;
	R0 ^= R1;
	B4 = R0; 
	R0 = R2; 
	R2 = R3; 
	R3 = B4; 
}

template<typename T>
static void Sb4(T &R0, T &R1, T &R2, T &R3)
{
	R1 ^= R3;
	R3 = ~R3;
	R2 ^= R3;
	R3 ^= R0;
	T B4 = R1;
	R1 &= R3;
	R1 ^= R2;
	B4 ^= R3;
	R0 ^= B4;
	R2 &= B4;
	R2 ^= R0;
	R0 &= R1;
	R3 ^= R0;
	B4 |= R1;
	B4 ^= R0;
	R0 |= R3;
	R0 ^= R2;
	R2 &= R3;
	R0 = ~R0;
	B4 ^= R2;
	R2 = R0;
	R0 = R1;
	R1 = B4;
}

template<typename T>
static void Ib4(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R2;
	R2 &= R3;
	R2 ^= R1;
	R1 |= R3;
	R1 &= R0;
	B4 ^= R2;
	B4 ^= R1;
	R1 &= R2;
	R0 = ~R0;
	R3 ^= B4;
	R1 ^= R3;
	R3 &= R0;
	R3 ^= R2;
	R0 ^= R1;
	R2 &= R0;
	R3 ^= R0;
	R2 ^= B4;
	R2 |= R3;
	R3 ^= R0;
	R2 ^= R1;
	R1 = R3;
	R3 = B4;
}

template<typename T>
static void Sb5(T &R0, T &R1, T &R2, T &R3)
{
	R0 ^= R1;
	R1 ^= R3;
	R3 = ~R3;
	T B4 = R1;
	R1 &= R0;
	R2 ^= R3;
	R1 ^= R2;
	R2 |= B4;
	B4 ^= R3;
	R3 &= R1;
	R3 ^= R0;
	B4 ^= R1;
	B4 ^= R2;
	R2 ^= R0;
	R0 &= R3;
	R2 = ~R2;
	R0 ^= B4;
	B4 |= R3;
	B4 ^= R2;
	R2 = R0;
	R0 = R1;
	R1 = R3;
	R3 = B4;
}

template<typename T>
static void Ib5(T &R0, T &R1, T &R2, T &R3)
{
	R1 = ~R1;
	T B4 = R3;
	R2 ^= R1;
	R3 |= R0;
	R3 ^= R2;
	R2 |= R1;
	R2 &= R0;
	B4 ^= R3;
	R2 ^= B4;
	B4 |= R0;
	B4 ^= R1;
	R1 &= R2;
	R1 ^= R3;
	B4 ^= R2;
	R3 &= B4;
	B4 ^= R1;
	R3 ^= B4;
	B4 = ~B4;
	R3 ^= R0;
	R0 = R1;
	R1 = B4;
	B4 = R3;
	R3 = R2;
	R2 = B4;
}

template<typename T>
static void Sb6(T &R0, T &R1, T &R2, T &R3)
{
	R2 = ~R2;
	T B4 = R3;
	R3 &= R0;
	R0 ^= B4;
	R3 ^= R2;
	R2 |= B4;
	R1 ^= R3;
	R2 ^= R0;
	R0 |= R1;
	R2 ^= R1;
	B4 ^= R0;
	R0 |= R3;
	R0 ^= R2;
	B4 ^= R3;
	B4 ^= R0;
	R3 = ~R3;
	R2 &= B4;
	R3 ^= R2;
	R2 = B4;
}

template<typename T>
static void Ib6(T &R0, T &R1, T &R2, T &R3)
{
	R0 ^= R2;
	T B4 = R2;
	R2 &= R0;
	B4 ^= R3;
	R2 = ~R2;
	R3 ^= R1;
	R2 ^= R3;
	B4 |= R0;
	R0 ^= R2;
	R3 ^= B4;
	B4 ^= R1;
	R1 &= R3;
	R1 ^= R0;
	R0 ^= R3;
	R0 |= R2;
	R3 ^= R1;
	B4 ^= R0;
	R0 = R1;
	R1 = R2;
	R2 = B4;
}

template<typename T>
static void Sb7(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R1;
	R1 |= R2;
	R1 ^= R3;
	B4 ^= R2;
	R2 ^= R1;
	R3 |= B4;
	R3 &= R0;
	B4 ^= R2;
	R3 ^= R1;
	R1 |= B4;
	R1 ^= R0;
	R0 |= B4;
	R0 ^= R2;
	R1 ^= B4;
	R2 ^= R1;
	R1 &= R0;
	R1 ^= B4;
	R2 = ~R2;
	R2 |= R0;
	B4 ^= R2;
	R2 = R1;
	R1 = R3;
	R3 = R0;
	R0 = B4;
}

template<typename T>
static void Ib7(T &R0, T &R1, T &R2, T &R3)
{
	T B4 = R2;
	R2 ^= R0;
	R0 &= R3;
	B4 |= R3;
	R2 = ~R2;
	R3 ^= R1;
	R1 |= R0;
	R0 ^= R2;
	R2 &= B4;
	R3 &= B4;
	R1 ^= R2;
	R2 ^= R0;
	R0 |= R2;
	B4 ^= R1;
	R0 ^= R3;
	R3 ^= B4;
	B4 |= R0;
	R3 ^= R2;
	B4 ^= R2;
	R2 = R1;
	R1 = R0;
	R0 = R3;
	R3 = B4;
}

NAMESPACE_BLOCKEND
#endif
