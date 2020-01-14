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

#ifndef CEX_BLAKE2_H
#define CEX_BLAKE2_H

#include "CexDomain.h"

#if defined(__AVX2__)
#	include "UInt256.h"
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "UInt512.h"
#	include "ULong512.h"
#endif

NAMESPACE_DIGEST

#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif

/// <summary>
/// Contains the Blake2-256 and 512bit permutation functions.
/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PermuteR10P512C, 10 rounds, permutes 512 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for speed and low memory consumption 
/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing-neutrality (suffix U), and the vertically vectorized functions have the V suffix. \n
/// The H suffix denotes functions that take an SIMD wrapper class (AVX2/AVX512) as the state values, and process input in SIMD parallel blocks.</para>
/// <para>This class contains horizontally vectorized (wide) forms of the functions; PermuteR10P8x512H and PermuteR12P4x1024H use AVX2, and
/// PermuteR10P16x512H and PermuteR12P8x1024H use the AVX512 instructions. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX2__ or __AVX512__) is explicitly declared.</para>
/// </summary>
class Blake
{
private:

	//~~~Inline Functions~~~//

#if defined(__AVX2__)

	// Misra exception: this is a common extension of the Intel intrinsics api
#	define _mm_roti_epi32(r, c) ( \
        (8==-(c)) ? _mm_shuffle_epi8(r,R8) \
        : (16==-(c)) ? _mm_shuffle_epi8(r,R16) \
        : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )

	// Misra exception: this is a common extension of the Intel intrinsics api
#	define _mm_roti_epi64(x, c) \
		(-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
		: (-(c) == 24) ? _mm_shuffle_epi8((x), R24) \
		: (-(c) == 16) ? _mm_shuffle_epi8((x), R16) \
		: (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
		: _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))

	template<typename T>
	inline static void Diagonalize(T &RL1, T &RL2, T &RL3, T &RL4, T &RH1, T &RH2, T &RH3, T &RH4)
	{
		T T0 = _mm_alignr_epi8(RH2, RL2, 8);
		T T1 = _mm_alignr_epi8(RL2, RH2, 8);
		RL2 = T0;
		RH2 = T1;
		T0 = RL3;
		RL3 = RH3;
		RH3 = T0;
		T0 = _mm_alignr_epi8(RH4, RL4, 8);
		T1 = _mm_alignr_epi8(RL4, RH4, 8);
		RL4 = T1;
		RH4 = T0;
	}

	template<typename T>
	inline static void UnDiagonalize(T &RL1, T &RL2, T &RL3, T &RL4, T &RH1, T &RH2, T &RH3, T &RH4)
	{
		T T0 = _mm_alignr_epi8(RL2, RH2, 8);
		T T1 = _mm_alignr_epi8(RH2, RL2, 8);
		RL2 = T0;
		RH2 = T1;
		T0 = RL3;
		RL3 = RH3;
		RH3 = T0;
		T0 = _mm_alignr_epi8(RL4, RH4, 8);
		T1 = _mm_alignr_epi8(RH4, RL4, 8);
		RL4 = T1;
		RH4 = T0;
	}

#endif

public:

	static const size_t BLAKE256_DIGEST_SIZE = 32;
	static const size_t BLAKE512_DIGEST_SIZE = 64;
	static const size_t BLAKE256_RATE_SIZE = 64;
	static const size_t BLAKE512_RATE_SIZE = 128;

	static const std::vector<uint> IV256;
	static const std::vector<ulong> IV512;
	static const std::vector<byte> Sigma256;
	static const std::vector<byte> Sigma512;

	/// <summary>
	/// The compact form of the Blake2-256 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR10P512C(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State, const std::array<uint, 8> &IV);

	/// <summary>
	/// The unrolled form of the Blake2-256 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR10P512U(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State, const std::array<uint, 8> &IV);

#if defined(__AVX2__)

	/// <summary>
	/// The vertically vectorized form of the Blake2-256 permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR10P512V(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State, const std::array<uint, 8> &IV);

#endif

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-256 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt256 state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR10P8x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &State, const std::vector<UInt256> &IV);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-256 permutation function.
	/// <para>This function process 16*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR10P16x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt512> &State, const std::vector<UInt512> &IV);

#endif

	/// <summary>
	/// The compact form of the Blake2-512 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR12P1024C(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State, const std::array<ulong, 8> &IV);

	/// <summary>
	/// The unrolled form of the Blake2-512 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR12P1024U(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State, const std::array<ulong, 8> &IV);

#if defined(__AVX2__)

	/// <summary>
	/// The vertically vectorized form of the Blake2-512 permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR12P1024V(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State, const std::array<ulong, 8> &IV);

#endif

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-512 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR12P4x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State, const std::vector<ULong256> &IV);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-512 permutation function.
	/// <para>This function process 8*128 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	/// <param name="IV">The permutations IV array</param>
	static void PermuteR12P8x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State, const std::vector<ULong512> &IV);

#endif
};

NAMESPACE_DIGESTEND
#endif
