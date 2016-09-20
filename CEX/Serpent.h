// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef _CEXENGINE_SERPENT_H
#define _CEXENGINE_SERPENT_H

#include "Common.h"

template<typename T>
void LinearTransform(T &R0, T &R1, T &R2, T &R3)
{
	R0 = CEX::Utility::IntUtils::RotL32(R0, 13);
	R2 = CEX::Utility::IntUtils::RotL32(R2, 3);
	R1 ^= R0 ^ R2;
	R3 ^= R2 ^ (R0 << 3);
	R1 = CEX::Utility::IntUtils::RotL32(R1, 1);
	R3 = CEX::Utility::IntUtils::RotL32(R3, 7);
	R0 ^= R1 ^ R3;
	R2 ^= R3 ^ (R1 << 7);
	R0 = CEX::Utility::IntUtils::RotL32(R0, 5);
	R2 = CEX::Utility::IntUtils::RotL32(R2, 22);
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
	R2 = CEX::Utility::IntUtils::RotR32(R2, 22);
	R0 = CEX::Utility::IntUtils::RotR32(R0, 5);
	R2 ^= R3 ^ (R1 << 7);
	R0 ^= R1 ^ R3;
	R3 = CEX::Utility::IntUtils::RotR32(R3, 7);
	R1 = CEX::Utility::IntUtils::RotR32(R1, 1);
	R3 ^= R2 ^ (R0 << 3);
	R1 ^= R0 ^ R2;
	R2 = CEX::Utility::IntUtils::RotR32(R2, 3);
	R0 = CEX::Utility::IntUtils::RotR32(R0, 13);
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

#endif
