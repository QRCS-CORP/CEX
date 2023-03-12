// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_MCELIECEUTILS_H
#define CEX_MCELIECEUTILS_H

#include "CexDomain.h"

NAMESPACE_MCELIECE

/// 
/// internal
/// 

/// <summary>
// An internal McEliece utilities class
/// </summary>
class MPKCUtils
{
public:

	static void ApplyBenes(uint8_t* R, const uint8_t* Bits, bool Reverse);

	static uint16_t BitReverse(uint16_t A);

	static void Bm(uint16_t* Output, const uint16_t* S, uint32_t SysT);

	static void CbRecursion(uint8_t* Output, int64_t Position, int64_t Step, const int16_t* Pi, int64_t W, int64_t N, int32_t* Temp);

	static void ControlBitsFromPermutation(uint8_t* Output, const int16_t* Pi, int64_t W, int64_t N);

	static uint16_t Eval(const uint16_t* F, uint16_t A, uint32_t SysT);

	static uint16_t GfAdd(uint16_t Input0, uint16_t Input1);

	static uint16_t GfFrac(uint16_t Den, uint16_t Num);

	static uint16_t GfIsZero(uint16_t A);

	static uint16_t GfInv(uint16_t Den);

	static uint16_t GfMultiply(uint16_t Input0, uint16_t Input1);

	static uint16_t GfSq2(uint16_t Input);

	static uint16_t GfSq2Mul(uint16_t Input, uint16_t M);

	static uint16_t GfSqMul(uint16_t Input, uint16_t M);

	static void Layer(int16_t* P, const uint8_t* Cb, int32_t S, int32_t N);

	static void LayerEx(uint64_t* Data, const uint64_t* Bits, uint32_t Lgs);

	static void LayerIn(uint64_t Data[2][64], const uint64_t* Bits, uint32_t Lgs);

	static uint16_t LoadGf(const uint8_t* src);

	static void MinMax32(int32_t* A, int32_t* B);

	static void MinMax64(uint64_t* A, uint64_t* B);

	static void Root(uint16_t* Output, const uint16_t* F, const uint16_t* L, uint32_t N, uint32_t SysT);

	static uint8_t SameMask(uint16_t X, uint16_t Y);

	static void Sort32(int32_t* X, int64_t N);

	static void Sort64(uint64_t* X, int64_t N);

	static void Synd(uint16_t* Output, const uint16_t* F, const uint16_t* L, const uint8_t* R, uint32_t N, uint32_t SysT);

	static void Transpose64x64(uint64_t* Output, const uint64_t* Input);
};

NAMESPACE_MCELIECEEND
#endif
