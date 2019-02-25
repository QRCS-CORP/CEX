// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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

NAMESPACE_STREAM

/// <summary>
/// Contains the ChaCha permutation functions.
/// <para>The function names are in the format; Permute-bits-suffix, ex. PermuteP512C, variable rounds, permutes 512 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
/// (enabled in the cipher functions by adding the CEX_CIPHER_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality (suffix U). \n
/// The H suffix denotes functions that take an SIMD wrapper class (UIntXXX) to process state in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PermuteP4x512H and PermuteP8x512H, which use the AVX and AVX2 instruction sets. \n
/// An experimental function using AVX512 instructions is also implemented; PermuteP16x512H. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX__, __AVX2__ or __AVX512__) is explicitly declared.</para>
/// </summary>
class ChaCha
{
private:

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
	static void PermuteP512C(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 2> &Counter, std::array<uint, 14> &State, size_t Rounds);

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
	static void PermuteR20P512U(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 2> &Counter, std::array<uint, 14> &State);

#if defined(__AVX__)

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
	static void PermuteP4x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 8> &Counter, std::array<uint, 14> &State, size_t Rounds);

#endif

#if defined(__AVX2__)

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
	static void PermuteP8x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 16> &Counter, std::array<uint, 14> &State, size_t Rounds);

#endif

#if defined(__AVX512__)

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
	static void PermuteP16x512H(std::vector<byte> &Output, size_t OutOffset, std::array<uint, 32> &Counter, std::array<uint, 14> &State, size_t Rounds);

#endif

};

NAMESPACE_STREAMEND
#endif
