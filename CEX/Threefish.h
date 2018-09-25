// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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

#ifndef CEX_THREEFISH_H
#define CEX_THREEFISH_H

#include "CexDomain.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "ULong512.h"
#endif

NAMESPACE_STREAM

#if defined(__AVX2__)
using Numeric::ULong256;
#endif
#if defined(__AVX512__)
using Numeric::ULong512;
#endif

/// <summary>
/// Contains the Threefish 256, 512, and 1024bit permutation functions.
/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PemuteR72P256C, 72 rounds, permutes 256 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality (suffix U), and the vertically vectorized functions have the V suffix. \n
/// The H suffix denotes functions that take an SIMD wrapper class (ULongXXX) as the state values, and process state in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PemuteP4x256H, PemuteP4x512H, and PemuteP4x1024H use AVX2 instructions. \n
/// Experimental functions using AVX512 instructions are also implemented; PemuteP4x512H, PemuteP8x512H, and PemuteP8x1024H. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX2__ or __AVX512__) is explicitly declared.</para>
/// </summary>
class Threefish
{
private:

	// AVX2
	template<typename T>
	static void Store4xULL256(std::array<T, 4> &C, std::array<ulong, 16> &State)
	{
		std::array<ulong, 4> tmp;
		size_t i;

		for (i = 0; i < 4; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 4] = tmp[1];
			State[i + 8] = tmp[2];
			State[i + 12] = tmp[3];
		}
	}

	template<typename T>
	static void Store8xULL256(std::array<T, 8> &C, std::array<ulong, 32> &State)
	{
		std::array<ulong, 4> tmp;
		size_t i;

		for (i = 0; i < 8; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 8] = tmp[1];
			State[i + 16] = tmp[2];
			State[i + 24] = tmp[3];
		}
	}

	template<typename T>
	static void Store16xULL256(std::array<T, 16> &C, std::array<ulong, 64> &State)
	{
		std::array<ulong, 4> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 16] = tmp[1];
			State[i + 32] = tmp[2];
			State[i + 48] = tmp[3];
		}
	}

	// AVX512
	template<typename T>
	static void Store4xULL512(std::array<T, 4> &C, std::array<ulong, 32> &State)
	{
		std::array<ulong, 8> tmp;
		size_t i;

		for (i = 0; i < 4; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 4] = tmp[1];
			State[i + 8] = tmp[2];
			State[i + 12] = tmp[3];
			State[i + 16] = tmp[4];
			State[i + 20] = tmp[5];
			State[i + 24] = tmp[6];
			State[i + 30] = tmp[7];
		}
	}

	template<typename T>
	static void Store8xULL512(std::array<T, 8> &C, std::array<ulong, 64> &State)
	{
		std::array<ulong, 8> tmp;
		size_t i;

		for (i = 0; i < 8; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 8] = tmp[1];
			State[i + 16] = tmp[2];
			State[i + 24] = tmp[3];
			State[i + 32] = tmp[4];
			State[i + 40] = tmp[5];
			State[i + 48] = tmp[6];
			State[i + 56] = tmp[7];
		}
	}

	template<typename T>
	static void Store16xULL512(std::array<T, 16> &C, std::array<ulong, 128> &State)
	{
		std::array<ulong, 8> tmp;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			C[i].Store(tmp, 0);
			State[i] = tmp[0];
			State[i + 16] = tmp[1];
			State[i + 32] = tmp[2];
			State[i + 48] = tmp[3];
			State[i + 64] = tmp[4];
			State[i + 80] = tmp[5];
			State[i + 96] = tmp[6];
			State[i + 112] = tmp[7];
		}
	}

public:

	//~~~Threefish-256~~~//

	/// <summary>
	/// The compact form of the Threefish-256 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	static void PemuteP256C(const std::array<ulong, 4> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 4> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Threefish-256 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR72P256U(const std::array<ulong, 4> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 4> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-256 permutation function.
	/// <para>This function processes 4*32 blocks of input in parallel using AVX2 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	static void PemuteP4x256H(const std::array<ulong, 4> &Key, const std::array<ulong, 8> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State, size_t Rounds);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-256 permutation function.
	/// <para>This function processes 8*32 blocks of input in parallel using AVX512 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 72</param>
	static void PemuteP4x512H(const std::array<ulong, 4> &Key, const std::array<ulong, 16> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 32> &State, size_t Rounds);

#endif

	//~~~Threefish-512~~~//

	/// <summary>
	/// The compact form of the Threefish-512 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 96</param>
	static void PemuteP512C(const std::array<ulong, 8> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Threefish-512 permutation function processing 96 rounds.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_CIPHER_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR96P512U(const std::array<ulong, 8> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-512 permutation function.
	/// <para>This function processes 4*64 blocks of input in parallel using AVX2 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 96</param>
	static void PemuteP4x512H(const std::array<ulong, 8> &Key, const std::array<ulong, 8> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 32> &State, size_t Rounds);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-512 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX512 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 96</param>
	static void PemuteP8x512H(const std::array<ulong, 8> &Key, const std::array<ulong, 16> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 64> &State, size_t Rounds);

#endif

	//~~~Threefish-1024~~~//

	/// <summary>
	/// The compact form of the Threefish-1024 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 128</param>
	static void PemuteP1024C(const std::array<ulong, 16> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State, size_t Rounds);

	/// <summary>
	/// The unrolled form of the Threefish-1024 permutation function processing 128 rounds
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	static void PemuteR120P1024U(const std::array<ulong, 16> &Key, const std::array<ulong, 2> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 16> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-1024 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 128</param>
	static void PemuteP4x1024H(const std::array<ulong, 16> &Key, const std::array<ulong, 8> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 64> &State, size_t Rounds);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Threefish-1024 permutation function.
	/// <para>This function processes 8*128 blocks of input in parallel using AVX512 instructions.
	/// Note: The rounds count must be at least 72 and evenly divisible by 8.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input cipher key array</param>
	/// <param name="Counter">The cipher counter array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Rounds">The number of mixing rounds; the default is 128</param>
	static void PemuteP8x1024H(const std::array<ulong, 16> &Key, const std::array<ulong, 16> &Counter, const std::array<ulong, 2> &Tweak, std::array<ulong, 128> &State, size_t Rounds);

#endif
};

NAMESPACE_STREAMEND
#endif
