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

#ifndef CEX_SHA2_H
#define CEX_SHA2_H

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
/// Contains the SHA2-256 and 512bit permutation functions.
/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PermuteR64P512C, 64 rounds, permutes 512 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality (suffix U), and the vertically vectorized functions have the V suffix. \n
/// The H suffix denotes functions that take an SIMD wrapper class (ULongXXX) as the state values, and process state in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PermuteR64P8x512H and PermuteR80P4x1024H uses AVX2. \n
/// Experimental functions using AVX512 instructions are also implemented; PermuteR64P16x512H and PermuteR80P8x1024H. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX2__ or __AVX512__) is explicitly declared.</para>
/// </summary>
class SHA2
{
private:

	static const std::vector<uint> K256;
	static const std::vector<ulong> K512;

	template<typename T>
	static void Round256W(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, T &P)
	{
		T R(H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + M + P);
		D += R;
		H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	}

	template<typename T>
	static void Round512W(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, T &P)
	{
		T R(H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + M + P);
		D += R;
		H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	}

	template<typename T>
	inline static T Sigma0(T &X)
	{
		return (((X << 63) | (X >> 1)) ^ ((X << 56) | (X >> 8)) ^ (X >> 7));
	}

	template<typename T>
	inline static T Sigma1(T &X)
	{
		return (((X << 45) | (X >> 19)) ^ ((X << 3) | (X >> 61)) ^ (X >> 6));
	}

	template<typename T>
	inline static T Theta0(T &X)
	{
		return T(((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3));
	}

	template<typename T>
	inline static T Theta1(T &X)
	{
		return T(((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10));
	}

	static void Round256(uint A, uint B, uint C, uint &D, uint E, uint F, uint G, uint &H, uint M, uint P);
	static void Round512(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P);

public:

	const static size_t SHA2_RATE256_SIZE = 64;
	const static size_t SHA2_RATE512_SIZE = 128;
	const static size_t SHA2_MESSAGE256_SIZE = 32;
	const static size_t SHA2_MESSAGE512_SIZE = 64;

	//~~~SHA2-256~~~//

	/// <summary>
	/// The compact form of the SHA2-256 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512C(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

	/// <summary>
	/// The unrolled form of the SHA2-256 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512U(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

	/// <summary>
	/// The vertically vectorized form of the SHA2-256 permutation function.
	/// <para>This function uses the Intel SHA-NI instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512V(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-256 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt256 state array</param>
	static void PermuteR64P8x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &State);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-256 permutation function.
	/// <para>This function process 16*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	static void PermuteR64P16x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt512> &State);

#endif

	//~~~SHA2-512~~~//

	/// <summary>
	/// The compact form of the SHA2-512 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P1024C(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State);

	/// <summary>
	/// The unrolled form of the SHA2-512 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P1024U(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-512 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P4x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-512 permutation function.
	/// <para>This function process 8*128 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	static void PermuteR80P8x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State);

#endif
};

NAMESPACE_DIGESTEND
#endif
