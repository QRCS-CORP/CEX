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

#ifndef CEX_THREEFISH_H
#define CEX_THREEFISH_H

#include "CexDomain.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "ULong512.h"
#endif

NAMESPACE_DIGEST

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	/// <summary>
	/// Contains the Skein 256, 512, and 1024bit permutation functions.
	/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PemuteR72P256C, 72 rounds, permutes 256 bits, using the compact form of the function. \n
	/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
	/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
	/// The Unrolled forms are optimized for speed and timing neutrality (suffix U), and the vertically vectorized functions have the V suffix. \n
	/// The H suffix denotes functions that take an SIMD wrapper class (ULongXXX) as the state values, and process state in SIMD parallel blocks.</para>
	/// <para>This class contains wide forms of the functions; PemuteR72P1024H, PemuteR72P2048H, and PemuteR80P4096H use AVX2 instructions. \n
	/// Experimental functions using AVX512 instructions are also implemented; PemuteR72P2048H, PemuteR72P4096H, and PemuteR80P8192H. \n
	/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX2__ or __AVX512__) is explicitely declared.</para>
	/// </summary>
class Skein
{
public:

	//~~~Skein-256~~~//

	/// <summary>
	/// The compact form of the Skein-256 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P256C(std::array<ulong, 4> &Input, std::array<ulong, 4> &State, std::array<ulong, 2> &Tweak);

	/// <summary>
	/// The unrolled form of the Skein-256 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P256U(std::array<ulong, 4> &Input, std::array<ulong, 4> &State, std::array<ulong, 2> &Tweak);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-256 permutation function.
	/// <para>This function processes 4*32 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P1024H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State, std::vector<ULong256> &Tweak);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-256 permutation function.
	/// <para>This function processes 8*32 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P2048H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State, std::vector<ULong512> &Tweak);

#endif

	//~~~Skein-512~~~//

	/// <summary>
	/// The compact form of the Skein-512 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P512C(std::array<ulong, 8> &Input, std::array<ulong, 8> &State, std::array<ulong, 2> &Tweak);

	/// <summary>
	/// The unrolled form of the Skein-512 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P512U(std::array<ulong, 8> &Input, std::array<ulong, 8> &State, std::array<ulong, 2> &Tweak);

#if defined(__AVX2__)

	/// <summary>
	/// The vertically vectorized form of the Skein-512 permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P512V(std::array<ulong, 8> &Input, std::array<ulong, 8> &State, std::array<ulong, 2> &Tweak);

#endif

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-512 permutation function.
	/// <para>This function processes 4*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P2048H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State, std::vector<ULong256> &Tweak);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-512 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR72P4096H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State, std::vector<ULong512> &Tweak);

#endif

	//~~~Skein-1024~~~//

	/// <summary>
	/// The compact form of the Skein-1024 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR80P1024C(std::array<ulong, 16> &Input, std::array<ulong, 16> &State, std::array<ulong, 2> &Tweak);

	/// <summary>
	/// The unrolled form of the Skein-1024 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR80P1024U(std::array<ulong, 16> &Input, std::array<ulong, 16> &State, std::array<ulong, 2> &Tweak);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-1024 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR80P4096H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State, std::vector<ULong256> &Tweak);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Skein-1024 permutation function.
	/// <para>This function processes 8*128 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="Tweak">The cipher tweak array</param>
	static void PemuteR80P8192H(std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State, std::vector<ULong512> &Tweak);

#endif
};

NAMESPACE_DIGESTEND
#endif
