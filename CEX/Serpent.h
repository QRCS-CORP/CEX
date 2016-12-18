// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
void LinearTransform64(T &R0, T &R1, T &R2, T &R3)
{
	R0.Rotl32(13);
	R2.Rotl32(3);
	R1 ^= R0 ^ R2;
	R3 ^= R2 ^ (R0 << 3);
	R1.Rotl32(1);
	R3.Rotl32(7);
	R0 ^= R1 ^ R3;
	R2 ^= R3 ^ (R1 << 7);
	R0.Rotl32(5);
	R2.Rotl32(22);
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
void InverseTransform64(T &R0, T &R1, T &R2, T &R3)
{
	R2.Rotr32(22);
	R0.Rotr32(5);
	R2 ^= R3 ^ (R1 << 7);
	R0 ^= R1 ^ R3;
	R3.Rotr32(7);
	R1.Rotr32(1);
	R3 ^= R2 ^ (R0 << 3);
	R1 ^= R0 ^ R2;
	R2.Rotr32(3);
	R0.Rotr32(13);
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
