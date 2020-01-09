// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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

#ifndef CEX_RNBWGFMATH_H
#define CEX_RNBWGFMATH_H

#include "CexDomain.h"

NAMESPACE_RAINBOW

/// 
/// internal
/// 

/// <summary>
/// The Rainbow GF math functions
/// </summary>
class RNBWGfMath
{
public:

	static byte Gf256vGetEle(const std::vector<byte> &A, size_t Offset, uint Index);

	static byte Gf256vSetEle(std::vector<byte> &A, size_t Offset, uint Index, byte V);

	static void Gf256vSetZero(std::vector<byte> &B, size_t BOffset, uint Count);

	static void Gf256MatProdRef(std::vector<byte> &C, const std::vector<byte> &MatA, uint Na, uint NaWidth, const std::vector<byte> &B, size_t BOffset);

	static uint Gf256MatGaussElimRef(std::vector<byte> &Mat, uint H, uint W);

	static void Gf256MatSubMat(std::vector<byte> &Mat2, uint W2, uint St, const std::vector<byte> &Mat, uint W, uint H);

	static void Gf256MatProd(std::vector<byte> &C, const std::vector<byte> &MatA, uint Na, uint NaWidth, const std::vector<byte> &B, size_t BOffset);

	static unsigned Gf256MatGaussElim(std::vector<byte> &Mat, uint H, uint W);

	static uint Gf256MatInv(std::vector<byte> &InvA, const std::vector<byte> &A, uint H, std::vector<byte> &Buffer);

#ifdef CEX_ARCH_64

	static void RNBWGfMath::Gf256vAddU32(std::vector<byte> &AccuB, size_t BOffset, const std::vector<byte> &A, size_t AOffset, size_t Length);

	static void RNBWGfMath::Gf256vMaddU32(std::vector<byte> &AccuC, size_t COffset, const std::vector<byte> &A, size_t AOffset, byte Gf256B, size_t Length);

	static void RNBWGfMath::Gf256vMulScalarU32(std::vector<byte> &A, size_t Offset, byte B, size_t Length);

	static void RNBWGfMath::Gf256vPredicatedAddU32(std::vector<byte> &AccuB, size_t BOffset, byte Predicate, const std::vector<byte> &A, size_t AOffset, size_t Length);

#endif

	static void RNBWGfMath::Gf256vAdd(std::vector<byte> &AccuB, size_t BOffset, const std::vector<byte> &A, size_t AOffset, size_t Length);

	static void RNBWGfMath::Gf256vMadd(std::vector<byte> &AccuC, size_t COffset, const std::vector<byte> &A, size_t AOffset, byte Gf256B, size_t Length);

	static void RNBWGfMath::Gf256vMulScalar(std::vector<byte> &A, size_t Offset, byte B, size_t Length);

	static void RNBWGfMath::Gf256vPredicatedAdd(std::vector<byte> &AccuB, size_t BOffset, byte Predicate, const std::vector<byte> &A, size_t AOffset, size_t Length);

private:

	static byte Gf4Mul2(byte A);

	static byte Gf4Mul3(byte A);

	static byte Gf4Mul(byte A, byte B);

	static byte Gf4Squ(byte A);

	static uint Gf4vMul2U32(uint A);

	static uint Gf4vMul3U32(uint A);

	static uint Gf4vMulU32(uint A, byte B);

	static uint Gf4vMulhU32U32(uint A0, uint A1, uint B0, uint B1);

	static uint Gf4vSquU32(uint A);

	static byte Gf16Mul(byte A, byte B);

	static byte Gf16Squ(byte A);

	static byte Gf16Mul8(byte A);

	static uint Gf16vMulU32(uint A, byte B);

	static uint Gf16vMulhU32U32(uint A0, uint A1, uint A2, uint A3, uint B0, uint B1, uint B2, uint B3);

	static byte Gf256vReduceU32(uint A);

	static uint Gf16vSquU32(uint A);

	static uint Gf16vMul8U32(uint A);

	static byte Gf256IsNonZero(byte A);

	static byte Gf256Mul(byte A, byte B);

	static byte Gf256MulGf16(byte A, byte Gf16B);

	static byte Gf256Squ(byte A);

	static byte Gf256Inv(byte A);

	static uint Gf256vMulU32(uint A, byte B);

	static uint Gf256vSquU32(uint A);

	static uint Gf256vMulGf16U32(uint A, byte Gf16B);

	static ulong Gf4vMul2U64(ulong A);

	static ulong Gf4vMul3U64(ulong A);

	static ulong Gf4vMulU64(ulong A, byte B);

	static ulong Gf4vMulhU64U64(ulong A0, ulong A1, ulong B0, ulong B1);

	static ulong Gf4vMulU64U64(ulong A, ulong B);

	static ulong Gf4vSquU64(ulong A);

	static ulong Gf16vMulU64(ulong A, byte B);

	static ulong Gf16vMulhU64U64(ulong A0, ulong A1, ulong A2, ulong A3, ulong B0, ulong B1, ulong B2, ulong B3);

	static ulong Gf16vMulU64U64(ulong A, ulong B);

	static byte Gf256vReduceU64(ulong A);

	static ulong Gf16vSquU64(ulong A);

	static ulong Gf16vMul8U64(ulong A);

	static ulong Gf256vMulU64(ulong A, byte B);

	static ulong Gf256vSquU64(ulong A);

	static ulong Gf256vMulGf16U64(ulong A, byte Gf16B);
};

NAMESPACE_RAINBOWEND
#endif