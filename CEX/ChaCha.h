// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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

#ifndef CEX_CHACHA_H
#define CEX_CHACHA_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

#if defined(CEX_HAS_AVX512)
#	include "UInt512.h"
#elif defined(CEX_HAS_AVX2)
#	include "UInt256.h"
#	include "ULong256.h"
#elif defined(CEX_HAS_AVX)
#	include "UInt128.h"
#	include "ULong512.h"
#endif

NAMESPACE_STREAM

using Tools::IntegerTools;
using Tools::MemoryTools;

#if defined(CEX_HAS_AVX512)
	using Numeric::UInt512;
	using Numeric::ULong512;
#elif defined(CEX_HAS_AVX2)
	using Numeric::UInt256;
	using Numeric::ULong256;
#elif defined(CEX_HAS_AVX)
	using Numeric::UInt128;
#endif

/// <summary>
/// Contains the ChaCha permutation functions.
/// <para>The function names are in the format; Permute-bits-suffix, ex. PermuteP512C, variable rounds, permutes 512 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
/// (enabled in the cipher functions by adding the CEX_CIPHER_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality (suffix U). \n
/// The H suffix denotes functions that take an SIMD wrapper class (UIntXXX) to process state in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PermuteP4x512H and PermuteP8x512H, which use the AVX and AVX2 instruction sets. \n
/// An experimental function using AVX512 instructions is also implemented; PermuteP16x512H. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (CEX_HAS_AVX, CEX_HAS_AVX2 or CEX_HAS_AVX512) is explicitly declared.</para>
/// </summary>
class ChaCha
{
private:

#if defined(CEX_HAS_AVX512)

	template<typename T>
	static void Store16xUL512(std::array<T, 16> &State, std::vector<byte> &Output, size_t OutOffset)
	{
		std::array<uint, 16> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			State[i].Store(tmp, 0);
			IntegerTools::Le32ToBytes(tmp[0], Output, OutOffset + (i * 4));
			IntegerTools::Le32ToBytes(tmp[1], Output, OutOffset + (i * 4) + 64);
			IntegerTools::Le32ToBytes(tmp[2], Output, OutOffset + (i * 4) + 128);
			IntegerTools::Le32ToBytes(tmp[3], Output, OutOffset + (i * 4) + 192);
			IntegerTools::Le32ToBytes(tmp[4], Output, OutOffset + (i * 4) + 256);
			IntegerTools::Le32ToBytes(tmp[5], Output, OutOffset + (i * 4) + 320);
			IntegerTools::Le32ToBytes(tmp[6], Output, OutOffset + (i * 4) + 384);
			IntegerTools::Le32ToBytes(tmp[7], Output, OutOffset + (i * 4) + 448);
			IntegerTools::Le32ToBytes(tmp[8], Output, OutOffset + (i * 4) + 512);
			IntegerTools::Le32ToBytes(tmp[9], Output, OutOffset + (i * 4) + 576);
			IntegerTools::Le32ToBytes(tmp[10], Output, OutOffset + (i * 4) + 640);
			IntegerTools::Le32ToBytes(tmp[11], Output, OutOffset + (i * 4) + 704);
			IntegerTools::Le32ToBytes(tmp[12], Output, OutOffset + (i * 4) + 768);
			IntegerTools::Le32ToBytes(tmp[13], Output, OutOffset + (i * 4) + 832);
			IntegerTools::Le32ToBytes(tmp[14], Output, OutOffset + (i * 4) + 896);
			IntegerTools::Le32ToBytes(tmp[15], Output, OutOffset + (i * 4) + 960);
		}
	}

	template<typename T>
	static void Store8xULL1024(std::array<T, 16> &State, std::vector<byte> &Output, size_t OutOffset)
	{
		std::array<ulong, 8> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			State[i].Store(tmp, 0);
			IntegerTools::Le64ToBytes(tmp[0], Output, OutOffset + (i * 8));
			IntegerTools::Le64ToBytes(tmp[1], Output, OutOffset + (i * 8) + 128);
			IntegerTools::Le64ToBytes(tmp[2], Output, OutOffset + (i * 8) + 256);
			IntegerTools::Le64ToBytes(tmp[3], Output, OutOffset + (i * 8) + 384);
			IntegerTools::Le64ToBytes(tmp[4], Output, OutOffset + (i * 8) + 512);
			IntegerTools::Le64ToBytes(tmp[5], Output, OutOffset + (i * 8) + 640);
			IntegerTools::Le64ToBytes(tmp[6], Output, OutOffset + (i * 8) + 768);
			IntegerTools::Le64ToBytes(tmp[7], Output, OutOffset + (i * 8) + 896);
		}
	}

#elif defined(CEX_HAS_AVX2)

	template<typename T>
	static void Store8xUL512(std::array<T, 16> &State, std::vector<byte> &Output, size_t OutOffset)
	{
		std::array<uint, 8> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			State[i].Store(tmp, 0);
			IntegerTools::Le32ToBytes(tmp[0], Output, OutOffset + (i * 4));
			IntegerTools::Le32ToBytes(tmp[1], Output, OutOffset + (i * 4) + 64);
			IntegerTools::Le32ToBytes(tmp[2], Output, OutOffset + (i * 4) + 128);
			IntegerTools::Le32ToBytes(tmp[3], Output, OutOffset + (i * 4) + 192);
			IntegerTools::Le32ToBytes(tmp[4], Output, OutOffset + (i * 4) + 256);
			IntegerTools::Le32ToBytes(tmp[5], Output, OutOffset + (i * 4) + 320);
			IntegerTools::Le32ToBytes(tmp[6], Output, OutOffset + (i * 4) + 384);
			IntegerTools::Le32ToBytes(tmp[7], Output, OutOffset + (i * 4) + 448);
		}
	}

	template<typename T>
	static void Store4xULL1024(std::array<T, 16> &State, std::vector<byte> &Output, size_t OutOffset)
	{
		std::array<ulong, 4> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			State[i].Store(tmp, 0);
			IntegerTools::Le64ToBytes(tmp[0], Output, OutOffset + (i * 8));
			IntegerTools::Le64ToBytes(tmp[1], Output, OutOffset + (i * 8) + 128);
			IntegerTools::Le64ToBytes(tmp[2], Output, OutOffset + (i * 8) + 256);
			IntegerTools::Le64ToBytes(tmp[3], Output, OutOffset + (i * 8) + 384);
		}
	}

#elif defined(CEX_HAS_AVX)

	template<typename T>
	static void Store4xUL512(std::array<T, 16> &State, std::vector<byte> &Output, size_t OutOffset)
	{
		std::array<uint, 4> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			State[i].Store(tmp, 0);
			IntegerTools::Le32ToBytes(tmp[0], Output, OutOffset + (i * 4));
			IntegerTools::Le32ToBytes(tmp[1], Output, OutOffset + (i * 4) + 64);
			IntegerTools::Le32ToBytes(tmp[2], Output, OutOffset + (i * 4) + 128);
			IntegerTools::Le32ToBytes(tmp[3], Output, OutOffset + (i * 4) + 192);
		}
	}

#endif

public:

	/// <summary>
	/// The compact form of the ChaCha permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The output array starting offset</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	template<typename ArrayU8, typename Array2xU32, typename Array14xU32>
	static void PermuteP512C(ArrayU8 &Output, size_t OutOffset, Array2xU32 &Counter, Array14xU32 &State, size_t Rounds)
	{
		std::array<ulong, 16> X{ State[0], State[1], State[2], State[3], 
			State[4], State[5], State[6], State[7], 
			State[8], State[9], State[10], State[11], 
			Counter[0], Counter[1], State[12], State[13] };

		while (Rounds != 0)
		{
			// round n
			X[0] += X[4];
			X[12] = IntegerTools::RotFL32(X[12] ^ X[0], 16);
			X[8] += X[12];
			X[4] = IntegerTools::RotFL32(X[4] ^ X[8], 12);
			X[0] += X[4];
			X[12] = IntegerTools::RotFL32(X[12] ^ X[0], 8);
			X[8] += X[12];
			X[4] = IntegerTools::RotFL32(X[4] ^ X[8], 7);
			X[1] += X[5];
			X[13] = IntegerTools::RotFL32(X[13] ^ X[1], 16);
			X[9] += X[13];
			X[5] = IntegerTools::RotFL32(X[5] ^ X[9], 12);
			X[1] += X[5];
			X[13] = IntegerTools::RotFL32(X[13] ^ X[1], 8);
			X[9] += X[13];
			X[5] = IntegerTools::RotFL32(X[5] ^ X[9], 7);
			X[2] += X[6];
			X[14] = IntegerTools::RotFL32(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = IntegerTools::RotFL32(X[6] ^ X[10], 12);
			X[2] += X[6];
			X[14] = IntegerTools::RotFL32(X[14] ^ X[2], 8);
			X[10] += X[14];
			X[6] = IntegerTools::RotFL32(X[6] ^ X[10], 7);
			X[3] += X[7];
			X[15] = IntegerTools::RotFL32(X[15] ^ X[3], 16);
			X[11] += X[15];
			X[7] = IntegerTools::RotFL32(X[7] ^ X[11], 12);
			X[3] += X[7];
			X[15] = IntegerTools::RotFL32(X[15] ^ X[3], 8);
			X[11] += X[15];
			X[7] = IntegerTools::RotFL32(X[7] ^ X[11], 7);
			// round n+1
			X[0] += X[5];
			X[15] = IntegerTools::RotFL32(X[15] ^ X[0], 16);
			X[10] += X[15];
			X[5] = IntegerTools::RotFL32(X[5] ^ X[10], 12);
			X[0] += X[5];
			X[15] = IntegerTools::RotFL32(X[15] ^ X[0], 8);
			X[10] += X[15];
			X[5] = IntegerTools::RotFL32(X[5] ^ X[10], 7);
			X[1] += X[6];
			X[12] = IntegerTools::RotFL32(X[12] ^ X[1], 16);
			X[11] += X[12];
			X[6] = IntegerTools::RotFL32(X[6] ^ X[11], 12);
			X[1] += X[6];
			X[12] = IntegerTools::RotFL32(X[12] ^ X[1], 8);
			X[11] += X[12];
			X[6] = IntegerTools::RotFL32(X[6] ^ X[11], 7);
			X[2] += X[7];
			X[13] = IntegerTools::RotFL32(X[13] ^ X[2], 16);
			X[8] += X[13];
			X[7] = IntegerTools::RotFL32(X[7] ^ X[8], 12);
			X[2] += X[7];
			X[13] = IntegerTools::RotFL32(X[13] ^ X[2], 8);
			X[8] += X[13];
			X[7] = IntegerTools::RotFL32(X[7] ^ X[8], 7);
			X[3] += X[4];
			X[14] = IntegerTools::RotFL32(X[14] ^ X[3], 16);
			X[9] += X[14];
			X[4] = IntegerTools::RotFL32(X[4] ^ X[9], 12);
			X[3] += X[4];
			X[14] = IntegerTools::RotFL32(X[14] ^ X[3], 8);
			X[9] += X[14];
			X[4] = IntegerTools::RotFL32(X[4] ^ X[9], 7);
			Rounds -= 2;
		}

		IntegerTools::Le32ToBytes(X[0] + State[0], Output, OutOffset);
		IntegerTools::Le32ToBytes(X[1] + State[1], Output, OutOffset + 4);
		IntegerTools::Le32ToBytes(X[2] + State[2], Output, OutOffset + 8);
		IntegerTools::Le32ToBytes(X[3] + State[3], Output, OutOffset + 12);
		IntegerTools::Le32ToBytes(X[4] + State[4], Output, OutOffset + 16);
		IntegerTools::Le32ToBytes(X[5] + State[5], Output, OutOffset + 20);
		IntegerTools::Le32ToBytes(X[6] + State[6], Output, OutOffset + 24);
		IntegerTools::Le32ToBytes(X[7] + State[7], Output, OutOffset + 28);
		IntegerTools::Le32ToBytes(X[8] + State[8], Output, OutOffset + 32);
		IntegerTools::Le32ToBytes(X[9] + State[9], Output, OutOffset + 36);
		IntegerTools::Le32ToBytes(X[10] + State[10], Output, OutOffset + 40);
		IntegerTools::Le32ToBytes(X[11] + State[11], Output, OutOffset + 44);
		IntegerTools::Le32ToBytes(X[12] + Counter[0], Output, OutOffset + 48);
		IntegerTools::Le32ToBytes(X[13] + Counter[1], Output, OutOffset + 52);
		IntegerTools::Le32ToBytes(X[14] + State[12], Output, OutOffset + 56);
		IntegerTools::Le32ToBytes(X[15] + State[13], Output, OutOffset + 60);
	}

	/// <summary>
	/// The unrolled form of the ChaChaPoly20 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	template<typename ArrayU8, typename Array2xU32, typename Array14xU32>
	static void PermuteR20P512U(ArrayU8 &Output, size_t OutOffset, Array2xU32 &Counter, Array14xU32 &State)
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

		// rounds 0-1
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 2-3
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 4-5
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 6-7
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 8-9
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 10-11
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 12-13
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 14-15
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 16-17
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);
		// rounds 18-19
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 16);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 12);
		X0 += X4;
		X12 = IntegerTools::RotFL32(X12 ^ X0, 8);
		X8 += X12;
		X4 = IntegerTools::RotFL32(X4 ^ X8, 7);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 16);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 12);
		X1 += X5;
		X13 = IntegerTools::RotFL32(X13 ^ X1, 8);
		X9 += X13;
		X5 = IntegerTools::RotFL32(X5 ^ X9, 7);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 16);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 12);
		X2 += X6;
		X14 = IntegerTools::RotFL32(X14 ^ X2, 8);
		X10 += X14;
		X6 = IntegerTools::RotFL32(X6 ^ X10, 7);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 16);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 12);
		X3 += X7;
		X15 = IntegerTools::RotFL32(X15 ^ X3, 8);
		X11 += X15;
		X7 = IntegerTools::RotFL32(X7 ^ X11, 7);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 16);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 12);
		X0 += X5;
		X15 = IntegerTools::RotFL32(X15 ^ X0, 8);
		X10 += X15;
		X5 = IntegerTools::RotFL32(X5 ^ X10, 7);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 16);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 12);
		X1 += X6;
		X12 = IntegerTools::RotFL32(X12 ^ X1, 8);
		X11 += X12;
		X6 = IntegerTools::RotFL32(X6 ^ X11, 7);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 16);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 12);
		X2 += X7;
		X13 = IntegerTools::RotFL32(X13 ^ X2, 8);
		X8 += X13;
		X7 = IntegerTools::RotFL32(X7 ^ X8, 7);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 16);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 12);
		X3 += X4;
		X14 = IntegerTools::RotFL32(X14 ^ X3, 8);
		X9 += X14;
		X4 = IntegerTools::RotFL32(X4 ^ X9, 7);

		IntegerTools::Le32ToBytes(X0 + State[0], Output, OutOffset);
		IntegerTools::Le32ToBytes(X1 + State[1], Output, OutOffset + 4);
		IntegerTools::Le32ToBytes(X2 + State[2], Output, OutOffset + 8);
		IntegerTools::Le32ToBytes(X3 + State[3], Output, OutOffset + 12);
		IntegerTools::Le32ToBytes(X4 + State[4], Output, OutOffset + 16);
		IntegerTools::Le32ToBytes(X5 + State[5], Output, OutOffset + 20);
		IntegerTools::Le32ToBytes(X6 + State[6], Output, OutOffset + 24);
		IntegerTools::Le32ToBytes(X7 + State[7], Output, OutOffset + 28);
		IntegerTools::Le32ToBytes(X8 + State[8], Output, OutOffset + 32);
		IntegerTools::Le32ToBytes(X9 + State[9], Output, OutOffset + 36);
		IntegerTools::Le32ToBytes(X10 + State[10], Output, OutOffset + 40);
		IntegerTools::Le32ToBytes(X11 + State[11], Output, OutOffset + 44);
		IntegerTools::Le32ToBytes(X12 + Counter[0], Output, OutOffset + 48);
		IntegerTools::Le32ToBytes(X13 + Counter[1], Output, OutOffset + 52);
		IntegerTools::Le32ToBytes(X14 + State[12], Output, OutOffset + 56);
		IntegerTools::Le32ToBytes(X15 + State[13], Output, OutOffset + 60);
	}

	/// <summary>
	/// An experimental form of the CSX-512 (based on ChaCha) permutation function using 64-bit integers.
	/// <para>This function has been optimized for small memory consumption.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The output array starting offset</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	template<typename ArrayU8, typename Array2xU64, typename Array14xU64>
	static void PermuteP1024C(ArrayU8 &Output, size_t OutOffset, Array2xU64 &Counter, Array14xU64 &State, size_t Rounds)
	{
		std::array<ulong, 16> X{ State[0], State[1], State[2], State[3], 
			State[4], State[5], State[6], State[7], 
			State[8], State[9], State[10], State[11], 
			Counter[0], Counter[1], State[12], State[13] };

		// new rotational constants = 
		// 38,19,10,55 
		// 33,4,51,13 
		// 16,34,56,51 
		// 4,53,42,41 
		// 34,41,59,17 
		// 23,31,37,20 
		// 31,44,47,46 
		// 12,47,44,30 

		while (Rounds != 0)
		{
			// round n
			X[0] += X[4];
			X[12] = IntegerTools::RotFL64(X[12] ^ X[0], 38);
			X[8] += X[12];
			X[4] = IntegerTools::RotFL64(X[4] ^ X[8], 19);
			X[0] += X[4];
			X[12] = IntegerTools::RotFL64(X[12] ^ X[0], 10);
			X[8] += X[12];
			X[4] = IntegerTools::RotFL64(X[4] ^ X[8], 55);
			X[1] += X[5];
			X[13] = IntegerTools::RotFL64(X[13] ^ X[1], 33);
			X[9] += X[13];
			X[5] = IntegerTools::RotFL64(X[5] ^ X[9], 4);
			X[1] += X[5];
			X[13] = IntegerTools::RotFL64(X[13] ^ X[1], 51);
			X[9] += X[13];
			X[5] = IntegerTools::RotFL64(X[5] ^ X[9], 13);
			X[2] += X[6];
			X[14] = IntegerTools::RotFL64(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = IntegerTools::RotFL64(X[6] ^ X[10], 34);
			X[2] += X[6];
			X[14] = IntegerTools::RotFL64(X[14] ^ X[2], 56);
			X[10] += X[14];
			X[6] = IntegerTools::RotFL64(X[6] ^ X[10], 51);
			X[3] += X[7];
			X[15] = IntegerTools::RotFL64(X[15] ^ X[3], 4);
			X[11] += X[15];
			X[7] = IntegerTools::RotFL64(X[7] ^ X[11], 53);
			X[3] += X[7];
			X[15] = IntegerTools::RotFL64(X[15] ^ X[3], 42);
			X[11] += X[15];
			X[7] = IntegerTools::RotFL64(X[7] ^ X[11], 41);
			// round n+1
			X[0] += X[5];
			X[15] = IntegerTools::RotFL64(X[15] ^ X[0], 34);
			X[10] += X[15];
			X[5] = IntegerTools::RotFL64(X[5] ^ X[10], 41);
			X[0] += X[5];
			X[15] = IntegerTools::RotFL64(X[15] ^ X[0], 59);
			X[10] += X[15];
			X[5] = IntegerTools::RotFL64(X[5] ^ X[10], 17);
			X[1] += X[6];
			X[12] = IntegerTools::RotFL64(X[12] ^ X[1], 23);
			X[11] += X[12];
			X[6] = IntegerTools::RotFL64(X[6] ^ X[11], 31);
			X[1] += X[6];
			X[12] = IntegerTools::RotFL64(X[12] ^ X[1], 37);
			X[11] += X[12];
			X[6] = IntegerTools::RotFL64(X[6] ^ X[11], 20);
			X[2] += X[7];
			X[13] = IntegerTools::RotFL64(X[13] ^ X[2], 31);
			X[8] += X[13];
			X[7] = IntegerTools::RotFL64(X[7] ^ X[8], 44);
			X[2] += X[7];
			X[13] = IntegerTools::RotFL64(X[13] ^ X[2], 47);
			X[8] += X[13];
			X[7] = IntegerTools::RotFL64(X[7] ^ X[8], 46);
			X[3] += X[4];
			X[14] = IntegerTools::RotFL64(X[14] ^ X[3], 12);
			X[9] += X[14];
			X[4] = IntegerTools::RotFL64(X[4] ^ X[9], 47);
			X[3] += X[4];
			X[14] = IntegerTools::RotFL64(X[14] ^ X[3], 44);
			X[9] += X[14];
			X[4] = IntegerTools::RotFL64(X[4] ^ X[9], 30);
			Rounds -= 2;
		}

		IntegerTools::Le64ToBytes(X[0] + State[0], Output, OutOffset);
		IntegerTools::Le64ToBytes(X[1] + State[1], Output, OutOffset + 8);
		IntegerTools::Le64ToBytes(X[2] + State[2], Output, OutOffset + 16);
		IntegerTools::Le64ToBytes(X[3] + State[3], Output, OutOffset + 24);
		IntegerTools::Le64ToBytes(X[4] + State[4], Output, OutOffset + 32);
		IntegerTools::Le64ToBytes(X[5] + State[5], Output, OutOffset + 40);
		IntegerTools::Le64ToBytes(X[6] + State[6], Output, OutOffset + 48);
		IntegerTools::Le64ToBytes(X[7] + State[7], Output, OutOffset + 56);
		IntegerTools::Le64ToBytes(X[8] + State[8], Output, OutOffset + 64);
		IntegerTools::Le64ToBytes(X[9] + State[9], Output, OutOffset + 72);
		IntegerTools::Le64ToBytes(X[10] + State[10], Output, OutOffset + 80);
		IntegerTools::Le64ToBytes(X[11] + State[11], Output, OutOffset + 88);
		IntegerTools::Le64ToBytes(X[12] + Counter[0], Output, OutOffset + 96);
		IntegerTools::Le64ToBytes(X[13] + Counter[1], Output, OutOffset + 104);
		IntegerTools::Le64ToBytes(X[14] + State[12], Output, OutOffset + 112);
		IntegerTools::Le64ToBytes(X[15] + State[13], Output, OutOffset + 120);
	}

#if defined(CEX_HAS_AVX512)

	/// <summary>
	/// The horizontally vectorized form of the ChaCha permutation function.
	/// <para>This function processes 16*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 20</param>
	template<typename ArrayU8, typename Array32xU32, typename Array14xU32>
	static void PermuteP16x512H(ArrayU8 &Output, size_t OutOffset, Array32xU32 &Counter, Array14xU32 &State, size_t Rounds)
	{
		std::array<UInt512, 16> X{ UInt512(State[0]), UInt512(State[1]), UInt512(State[2]), UInt512(State[3]),
			UInt512(State[4]), UInt512(State[5]), UInt512(State[6]), UInt512(State[7]),
			UInt512(State[8]), UInt512(State[9]), UInt512(State[10]), UInt512(State[11]),
			UInt512(Counter, 0), UInt512(Counter, 16), UInt512(State[12]), UInt512(State[13]) };

		while (Rounds != 0)
		{
			X[0] += X[4];
			X[12] = UInt512::RotL32(X[12] ^ X[0], 16);
			X[8] += X[12];
			X[4] = UInt512::RotL32(X[4] ^ X[8], 12);
			X[0] += X[4];
			X[12] = UInt512::RotL32(X[12] ^ X[0], 8);
			X[8] += X[12];
			X[4] = UInt512::RotL32(X[4] ^ X[8], 7);
			X[1] += X[5];
			X[13] = UInt512::RotL32(X[13] ^ X[1], 16);
			X[9] += X[13];
			X[5] = UInt512::RotL32(X[5] ^ X[9], 12);
			X[1] += X[5];
			X[13] = UInt512::RotL32(X[13] ^ X[1], 8);
			X[9] += X[13];
			X[5] = UInt512::RotL32(X[5] ^ X[9], 7);
			X[2] += X[6];
			X[14] = UInt512::RotL32(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = UInt512::RotL32(X[6] ^ X[10], 12);
			X[2] += X[6];
			X[14] = UInt512::RotL32(X[14] ^ X[2], 8);
			X[10] += X[14];
			X[6] = UInt512::RotL32(X[6] ^ X[10], 7);
			X[3] += X[7];
			X[15] = UInt512::RotL32(X[15] ^ X[3], 16);
			X[11] += X[15];
			X[7] = UInt512::RotL32(X[7] ^ X[11], 12);
			X[3] += X[7];
			X[15] = UInt512::RotL32(X[15] ^ X[3], 8);
			X[11] += X[15];
			X[7] = UInt512::RotL32(X[7] ^ X[11], 7);
			X[0] += X[5];
			X[15] = UInt512::RotL32(X[15] ^ X[0], 16);
			X[10] += X[15];
			X[5] = UInt512::RotL32(X[5] ^ X[10], 12);
			X[0] += X[5];
			X[15] = UInt512::RotL32(X[15] ^ X[0], 8);
			X[10] += X[15];
			X[5] = UInt512::RotL32(X[5] ^ X[10], 7);
			X[1] += X[6];
			X[12] = UInt512::RotL32(X[12] ^ X[1], 16);
			X[11] += X[12];
			X[6] = UInt512::RotL32(X[6] ^ X[11], 12);
			X[1] += X[6];
			X[12] = UInt512::RotL32(X[12] ^ X[1], 8);
			X[11] += X[12];
			X[6] = UInt512::RotL32(X[6] ^ X[11], 7);
			X[2] += X[7];
			X[13] = UInt512::RotL32(X[13] ^ X[2], 16);
			X[8] += X[13];
			X[7] = UInt512::RotL32(X[7] ^ X[8], 12);
			X[2] += X[7];
			X[13] = UInt512::RotL32(X[13] ^ X[2], 8);
			X[8] += X[13];
			X[7] = UInt512::RotL32(X[7] ^ X[8], 7);
			X[3] += X[4];
			X[14] = UInt512::RotL32(X[14] ^ X[3], 16);
			X[9] += X[14];
			X[4] = UInt512::RotL32(X[4] ^ X[9], 12);
			X[3] += X[4];
			X[14] = UInt512::RotL32(X[14] ^ X[3], 8);
			X[9] += X[14];
			X[4] = UInt512::RotL32(X[4] ^ X[9], 7);
			Rounds -= 2;
		}

		// last round
		X[0] += UInt512(State[0]);
		X[1] += UInt512(State[1]);
		X[2] += UInt512(State[2]);
		X[3] += UInt512(State[3]);
		X[4] += UInt512(State[4]);
		X[5] += UInt512(State[5]);
		X[6] += UInt512(State[6]);
		X[7] += UInt512(State[7]);
		X[8] += UInt512(State[8]);
		X[9] += UInt512(State[9]);
		X[10] += UInt512(State[10]);
		X[11] += UInt512(State[11]);
		X[12] += UInt512(Counter, 0);
		X[13] += UInt512(Counter, 16);
		X[14] += UInt512(State[12]);
		X[15] += UInt512(State[13]);

		Store16xUL512(X, Output, OutOffset);
	}

	/// <summary>
	/// The horizontally vectorized form of the CSX-512 (based on ChaCha) permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 20</param>
	template<typename ArrayU8, typename Array16xU64, typename Array14xU64>
	static void PermuteP8x1024H(ArrayU8 &Output, size_t OutOffset, Array16xU64 &Counter, Array14xU64 &State, size_t Rounds)
	{
		std::array<ULong512, 16> X{ ULong512(State[0]), ULong512(State[1]), ULong512(State[2]), ULong512(State[3]),
			ULong512(State[4]), ULong512(State[5]), ULong512(State[6]), ULong512(State[7]), 
			ULong512(State[8]), ULong512(State[9]), ULong512(State[10]), ULong512(State[11]), 
			UInt512(Counter, 0), UInt512(Counter, 8), ULong512(State[12]), ULong512(State[13]) };

		// new rotational constants = 
		// 38,19,10,55 
		// 33,4,51,13 
		// 16,34,56,51 
		// 4,53,42,41 
		// 34,41,59,17 
		// 23,31,37,20 
		// 31,44,47,46 
		// 12,47,44,30 

		while (Rounds != 0)
		{
			// round n
			X[0] += X[4];
			X[12] = ULong512::RotL64(X[12] ^ X[0], 38);
			X[8] += X[12];
			X[4] = ULong512::RotL64(X[4] ^ X[8], 19);
			X[0] += X[4];
			X[12] = ULong512::RotL64(X[12] ^ X[0], 10);
			X[8] += X[12];
			X[4] = ULong512::RotL64(X[4] ^ X[8], 55);
			X[1] += X[5];
			X[13] = ULong512::RotL64(X[13] ^ X[1], 33);
			X[9] += X[13];
			X[5] = ULong512::RotL64(X[5] ^ X[9], 4);
			X[1] += X[5];
			X[13] = ULong512::RotL64(X[13] ^ X[1], 51);
			X[9] += X[13];
			X[5] = ULong512::RotL64(X[5] ^ X[9], 13);
			X[2] += X[6];
			X[14] = ULong512::RotL64(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = ULong512::RotL64(X[6] ^ X[10], 34);
			X[2] += X[6];
			X[14] = ULong512::RotL64(X[14] ^ X[2], 56);
			X[10] += X[14];
			X[6] = ULong512::RotL64(X[6] ^ X[10], 51);
			X[3] += X[7];
			X[15] = ULong512::RotL64(X[15] ^ X[3], 4);
			X[11] += X[15];
			X[7] = ULong512::RotL64(X[7] ^ X[11], 53);
			X[3] += X[7];
			X[15] = ULong512::RotL64(X[15] ^ X[3], 42);
			X[11] += X[15];
			X[7] = ULong512::RotL64(X[7] ^ X[11], 41);
			X[0] += X[5];
			// round n+1
			X[15] = ULong512::RotL64(X[15] ^ X[0], 34);
			X[10] += X[15];
			X[5] = ULong512::RotL64(X[5] ^ X[10], 41);
			X[0] += X[5];
			X[15] = ULong512::RotL64(X[15] ^ X[0], 59);
			X[10] += X[15];
			X[5] = ULong512::RotL64(X[5] ^ X[10], 17);
			X[1] += X[6];
			X[12] = ULong512::RotL64(X[12] ^ X[1], 23);
			X[11] += X[12];
			X[6] = ULong512::RotL64(X[6] ^ X[11], 31);
			X[1] += X[6];
			X[12] = ULong512::RotL64(X[12] ^ X[1], 37);
			X[11] += X[12];
			X[6] = ULong512::RotL64(X[6] ^ X[11], 20);
			X[2] += X[7];
			X[13] = ULong512::RotL64(X[13] ^ X[2], 31);
			X[8] += X[13];
			X[7] = ULong512::RotL64(X[7] ^ X[8], 44);
			X[2] += X[7];
			X[13] = ULong512::RotL64(X[13] ^ X[2], 47);
			X[8] += X[13];
			X[7] = ULong512::RotL64(X[7] ^ X[8], 46);
			X[3] += X[4];
			X[14] = ULong512::RotL64(X[14] ^ X[3], 12);
			X[9] += X[14];
			X[4] = ULong512::RotL64(X[4] ^ X[9], 47);
			X[3] += X[4];
			X[14] = ULong512::RotL64(X[14] ^ X[3], 44);
			X[9] += X[14];
			X[4] = ULong512::RotL64(X[4] ^ X[9], 30);
			Rounds -= 2;
		}

		X[0] += ULong512(State[0]);
		X[1] += ULong512(State[1]);
		X[2] += ULong512(State[2]);
		X[3] += ULong512(State[3]);
		X[4] += ULong512(State[4]);
		X[5] += ULong512(State[5]);
		X[6] += ULong512(State[6]);
		X[7] += ULong512(State[7]);
		X[8] += ULong512(State[8]);
		X[9] += ULong512(State[9]);
		X[10] += ULong512(State[10]);
		X[11] += ULong512(State[11]);
		X[12] += ULong512(Counter, 0);
		X[13] += ULong512(Counter, 4);
		X[14] += ULong512(State[12]);
		X[15] += ULong512(State[13]);

		Store8xULL1024(X, Output, OutOffset);
	}

#elif defined(CEX_HAS_AVX2)

	/// <summary>
	/// The horizontally vectorized form of the ChaCha permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 20</param>
	template<typename ArrayU8, typename Array16xU32, typename Array14xU32>
	static void PermuteP8x512H(ArrayU8 &Output, size_t OutOffset, Array16xU32 &Counter, Array14xU32 &State, size_t Rounds)
	{
		std::array<UInt256, 16> X{ UInt256(State[0]), UInt256(State[1]), UInt256(State[2]), UInt256(State[3]),
			UInt256(State[4]), UInt256(State[5]), UInt256(State[6]), UInt256(State[7]),
			UInt256(State[8]), UInt256(State[9]), UInt256(State[10]), UInt256(State[11]),
			UInt256(Counter, 0), UInt256(Counter, 8), UInt256(State[12]), UInt256(State[13]) };

		while (Rounds != 0)
		{
			X[0] += X[4];
			X[12] = UInt256::RotL32(X[12] ^ X[0], 16);
			X[8] += X[12];
			X[4] = UInt256::RotL32(X[4] ^ X[8], 12);
			X[0] += X[4];
			X[12] = UInt256::RotL32(X[12] ^ X[0], 8);
			X[8] += X[12];
			X[4] = UInt256::RotL32(X[4] ^ X[8], 7);
			X[1] += X[5];
			X[13] = UInt256::RotL32(X[13] ^ X[1], 16);
			X[9] += X[13];
			X[5] = UInt256::RotL32(X[5] ^ X[9], 12);
			X[1] += X[5];
			X[13] = UInt256::RotL32(X[13] ^ X[1], 8);
			X[9] += X[13];
			X[5] = UInt256::RotL32(X[5] ^ X[9], 7);
			X[2] += X[6];
			X[14] = UInt256::RotL32(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = UInt256::RotL32(X[6] ^ X[10], 12);
			X[2] += X[6];
			X[14] = UInt256::RotL32(X[14] ^ X[2], 8);
			X[10] += X[14];
			X[6] = UInt256::RotL32(X[6] ^ X[10], 7);
			X[3] += X[7];
			X[15] = UInt256::RotL32(X[15] ^ X[3], 16);
			X[11] += X[15];
			X[7] = UInt256::RotL32(X[7] ^ X[11], 12);
			X[3] += X[7];
			X[15] = UInt256::RotL32(X[15] ^ X[3], 8);
			X[11] += X[15];
			X[7] = UInt256::RotL32(X[7] ^ X[11], 7);
			X[0] += X[5];
			X[15] = UInt256::RotL32(X[15] ^ X[0], 16);
			X[10] += X[15];
			X[5] = UInt256::RotL32(X[5] ^ X[10], 12);
			X[0] += X[5];
			X[15] = UInt256::RotL32(X[15] ^ X[0], 8);
			X[10] += X[15];
			X[5] = UInt256::RotL32(X[5] ^ X[10], 7);
			X[1] += X[6];
			X[12] = UInt256::RotL32(X[12] ^ X[1], 16);
			X[11] += X[12];
			X[6] = UInt256::RotL32(X[6] ^ X[11], 12);
			X[1] += X[6];
			X[12] = UInt256::RotL32(X[12] ^ X[1], 8);
			X[11] += X[12];
			X[6] = UInt256::RotL32(X[6] ^ X[11], 7);
			X[2] += X[7];
			X[13] = UInt256::RotL32(X[13] ^ X[2], 16);
			X[8] += X[13];
			X[7] = UInt256::RotL32(X[7] ^ X[8], 12);
			X[2] += X[7];
			X[13] = UInt256::RotL32(X[13] ^ X[2], 8);
			X[8] += X[13];
			X[7] = UInt256::RotL32(X[7] ^ X[8], 7);
			X[3] += X[4];
			X[14] = UInt256::RotL32(X[14] ^ X[3], 16);
			X[9] += X[14];
			X[4] = UInt256::RotL32(X[4] ^ X[9], 12);
			X[3] += X[4];
			X[14] = UInt256::RotL32(X[14] ^ X[3], 8);
			X[9] += X[14];
			X[4] = UInt256::RotL32(X[4] ^ X[9], 7);
			Rounds -= 2;
		}

		X[0] += UInt256(State[0]);
		X[1] += UInt256(State[1]);
		X[2] += UInt256(State[2]);
		X[3] += UInt256(State[3]);
		X[4] += UInt256(State[4]);
		X[5] += UInt256(State[5]);
		X[6] += UInt256(State[6]);
		X[7] += UInt256(State[7]);
		X[8] += UInt256(State[8]);
		X[9] += UInt256(State[9]);
		X[10] += UInt256(State[10]);
		X[11] += UInt256(State[11]);
		X[12] += UInt256(Counter, 0);
		X[13] += UInt256(Counter, 8);
		X[14] += UInt256(State[12]);
		X[15] += UInt256(State[13]);

		Store8xUL512(X, Output, OutOffset);
	}

	/// <summary>
	/// The horizontally vectorized form of the CSX-512 (based on ChaCha) permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 20</param>
	template<typename ArrayU8, typename Array8xU64, typename Array14xU64>
	static void PermuteP4x1024H(ArrayU8 &Output, size_t OutOffset, Array8xU64 &Counter, Array14xU64 &State, size_t Rounds)
	{
		std::array<ULong256, 16> X{ ULong256(State[0]), ULong256(State[1]), ULong256(State[2]), ULong256(State[3]),
			ULong256(State[4]), ULong256(State[5]), ULong256(State[6]), ULong256(State[7]), 
			ULong256(State[8]), ULong256(State[9]), ULong256(State[10]), ULong256(State[11]), 
			ULong256(Counter, 0), ULong256(Counter, 4), ULong256(State[12]), ULong256(State[13]) };

		// new rotational constants = 
		// 38,19,10,55 
		// 33,4,51,13 
		// 16,34,56,51 
		// 4,53,42,41 
		// 34,41,59,17 
		// 23,31,37,20 
		// 31,44,47,46 
		// 12,47,44,30 

		while (Rounds != 0)
		{
			// round n
			X[0] += X[4];
			X[12] = ULong256::RotL64(X[12] ^ X[0], 38);
			X[8] += X[12];
			X[4] = ULong256::RotL64(X[4] ^ X[8], 19);
			X[0] += X[4];
			X[12] = ULong256::RotL64(X[12] ^ X[0], 10);
			X[8] += X[12];
			X[4] = ULong256::RotL64(X[4] ^ X[8], 55);
			X[1] += X[5];
			X[13] = ULong256::RotL64(X[13] ^ X[1], 33);
			X[9] += X[13];
			X[5] = ULong256::RotL64(X[5] ^ X[9], 4);
			X[1] += X[5];
			X[13] = ULong256::RotL64(X[13] ^ X[1], 51);
			X[9] += X[13];
			X[5] = ULong256::RotL64(X[5] ^ X[9], 13);
			X[2] += X[6];
			X[14] = ULong256::RotL64(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = ULong256::RotL64(X[6] ^ X[10], 34);
			X[2] += X[6];
			X[14] = ULong256::RotL64(X[14] ^ X[2], 56);
			X[10] += X[14];
			X[6] = ULong256::RotL64(X[6] ^ X[10], 51);
			X[3] += X[7];
			X[15] = ULong256::RotL64(X[15] ^ X[3], 4);
			X[11] += X[15];
			X[7] = ULong256::RotL64(X[7] ^ X[11], 53);
			X[3] += X[7];
			X[15] = ULong256::RotL64(X[15] ^ X[3], 42);
			X[11] += X[15];
			X[7] = ULong256::RotL64(X[7] ^ X[11], 41);
			// round n+1
			X[0] += X[5];
			X[15] = ULong256::RotL64(X[15] ^ X[0], 34);
			X[10] += X[15];
			X[5] = ULong256::RotL64(X[5] ^ X[10], 41);
			X[0] += X[5];
			X[15] = ULong256::RotL64(X[15] ^ X[0], 59);
			X[10] += X[15];
			X[5] = ULong256::RotL64(X[5] ^ X[10], 17);
			X[1] += X[6];
			X[12] = ULong256::RotL64(X[12] ^ X[1], 23);
			X[11] += X[12];
			X[6] = ULong256::RotL64(X[6] ^ X[11], 31);
			X[1] += X[6];
			X[12] = ULong256::RotL64(X[12] ^ X[1], 37);
			X[11] += X[12];
			X[6] = ULong256::RotL64(X[6] ^ X[11], 20);
			X[2] += X[7];
			X[13] = ULong256::RotL64(X[13] ^ X[2], 31);
			X[8] += X[13];
			X[7] = ULong256::RotL64(X[7] ^ X[8], 44);
			X[2] += X[7];
			X[13] = ULong256::RotL64(X[13] ^ X[2], 47);
			X[8] += X[13];
			X[7] = ULong256::RotL64(X[7] ^ X[8], 46);
			X[3] += X[4];
			X[14] = ULong256::RotL64(X[14] ^ X[3], 12);
			X[9] += X[14];
			X[4] = ULong256::RotL64(X[4] ^ X[9], 47);
			X[3] += X[4];
			X[14] = ULong256::RotL64(X[14] ^ X[3], 44);
			X[9] += X[14];
			X[4] = ULong256::RotL64(X[4] ^ X[9], 30);
			Rounds -= 2;
		}

		X[0] += ULong256(State[0]);
		X[1] += ULong256(State[1]);
		X[2] += ULong256(State[2]);
		X[3] += ULong256(State[3]);
		X[4] += ULong256(State[4]);
		X[5] += ULong256(State[5]);
		X[6] += ULong256(State[6]);
		X[7] += ULong256(State[7]);
		X[8] += ULong256(State[8]);
		X[9] += ULong256(State[9]);
		X[10] += ULong256(State[10]);
		X[11] += ULong256(State[11]);
		X[12] += ULong256(Counter, 0);
		X[13] += ULong256(Counter, 4);
		X[14] += ULong256(State[12]);
		X[15] += ULong256(State[13]);

		Store4xULL1024(X, Output, OutOffset);
	}

#elif defined(CEX_HAS_AVX)

	/// <summary>
	/// The horizontally vectorized form of the ChaCha permutation function.
	/// <para>This function processes 4*64 blocks of input in parallel using AVX instructions.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output message array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 20</param>
	template<typename ArrayU8, typename Array8xU32, typename Array14xU32>
	static void PermuteP4x512H(ArrayU8 &Output, size_t OutOffset, Array8xU32 &Counter, Array14xU32 &State, size_t Rounds)
	{
		std::array<UInt128, 16> X{ UInt128(State[0]), UInt128(State[1]), UInt128(State[2]), UInt128(State[3]),
			UInt128(State[4]), UInt128(State[5]), UInt128(State[6]), UInt128(State[7]),
			UInt128(State[8]), UInt128(State[9]), UInt128(State[10]), UInt128(State[11]),
			UInt128(Counter, 0), UInt128(Counter, 4), UInt128(State[12]), UInt128(State[13]) };

		while (Rounds != 0)
		{
			X[0] += X[4];
			X[12] = UInt128::RotL32(X[12] ^ X[0], 16);
			X[8] += X[12];
			X[4] = UInt128::RotL32(X[4] ^ X[8], 12);
			X[0] += X[4];
			X[12] = UInt128::RotL32(X[12] ^ X[0], 8);
			X[8] += X[12];
			X[4] = UInt128::RotL32(X[4] ^ X[8], 7);
			X[1] += X[5];
			X[13] = UInt128::RotL32(X[13] ^ X[1], 16);
			X[9] += X[13];
			X[5] = UInt128::RotL32(X[5] ^ X[9], 12);
			X[1] += X[5];
			X[13] = UInt128::RotL32(X[13] ^ X[1], 8);
			X[9] += X[13];
			X[5] = UInt128::RotL32(X[5] ^ X[9], 7);
			X[2] += X[6];
			X[14] = UInt128::RotL32(X[14] ^ X[2], 16);
			X[10] += X[14];
			X[6] = UInt128::RotL32(X[6] ^ X[10], 12);
			X[2] += X[6];
			X[14] = UInt128::RotL32(X[14] ^ X[2], 8);
			X[10] += X[14];
			X[6] = UInt128::RotL32(X[6] ^ X[10], 7);
			X[3] += X[7];
			X[15] = UInt128::RotL32(X[15] ^ X[3], 16);
			X[11] += X[15];
			X[7] = UInt128::RotL32(X[7] ^ X[11], 12);
			X[3] += X[7];
			X[15] = UInt128::RotL32(X[15] ^ X[3], 8);
			X[11] += X[15];
			X[7] = UInt128::RotL32(X[7] ^ X[11], 7);
			X[0] += X[5];
			X[15] = UInt128::RotL32(X[15] ^ X[0], 16);
			X[10] += X[15];
			X[5] = UInt128::RotL32(X[5] ^ X[10], 12);
			X[0] += X[5];
			X[15] = UInt128::RotL32(X[15] ^ X[0], 8);
			X[10] += X[15];
			X[5] = UInt128::RotL32(X[5] ^ X[10], 7);
			X[1] += X[6];
			X[12] = UInt128::RotL32(X[12] ^ X[1], 16);
			X[11] += X[12];
			X[6] = UInt128::RotL32(X[6] ^ X[11], 12);
			X[1] += X[6];
			X[12] = UInt128::RotL32(X[12] ^ X[1], 8);
			X[11] += X[12];
			X[6] = UInt128::RotL32(X[6] ^ X[11], 7);
			X[2] += X[7];
			X[13] = UInt128::RotL32(X[13] ^ X[2], 16);
			X[8] += X[13];
			X[7] = UInt128::RotL32(X[7] ^ X[8], 12);
			X[2] += X[7];
			X[13] = UInt128::RotL32(X[13] ^ X[2], 8);
			X[8] += X[13];
			X[7] = UInt128::RotL32(X[7] ^ X[8], 7);
			X[3] += X[4];
			X[14] = UInt128::RotL32(X[14] ^ X[3], 16);
			X[9] += X[14];
			X[4] = UInt128::RotL32(X[4] ^ X[9], 12);
			X[3] += X[4];
			X[14] = UInt128::RotL32(X[14] ^ X[3], 8);
			X[9] += X[14];
			X[4] = UInt128::RotL32(X[4] ^ X[9], 7);
			Rounds -= 2;
		}

		X[0] += UInt128(State[0]);
		X[1] += UInt128(State[1]);
		X[2] += UInt128(State[2]);
		X[3] += UInt128(State[3]);
		X[4] += UInt128(State[4]);
		X[5] += UInt128(State[5]);
		X[6] += UInt128(State[6]);
		X[7] += UInt128(State[7]);
		X[8] += UInt128(State[8]);
		X[9] += UInt128(State[9]);
		X[10] += UInt128(State[10]);
		X[11] += UInt128(State[11]);
		X[12] += UInt128(Counter, 0);
		X[13] += UInt128(Counter, 4);
		X[14] += UInt128(State[12]);
		X[15] += UInt128(State[13]);

		Store4xUL512(X, Output, OutOffset);
	}

#endif

};

NAMESPACE_STREAMEND
#endif
