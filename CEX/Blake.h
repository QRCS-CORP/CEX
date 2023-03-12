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

#ifndef CEX_BLAKE2_H
#define CEX_BLAKE2_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

#if defined(CEX_HAS_AVX512)
#	include "UInt512.h"
#	include "ULong512.h"
#elif defined(CEX_HAS_AVX2)
#	include "UInt256.h"
#	include "ULong256.h"
#endif

NAMESPACE_DIGEST

using Tools::IntegerTools;
using Tools::MemoryTools;

#if defined(CEX_HAS_AVX512)
	using Numeric::UInt512;
	using Numeric::ULong512;
#elif defined(CEX_HAS_AVX2)
	using Numeric::UInt256;
	using Numeric::ULong256;
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
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (CEX_HAS_AVX2 or CEX_HAS_AVX512) is explicitly declared.</para>
/// </summary>
class Blake
{
private:

	//~~~Inline Functions~~~//

#if defined(CEX_HAS_AVX2)

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
	inline static void Diagonalize(T &RL2, T &RL3, T &RL4, T &RH2, T &RH3, T &RH4)
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
	inline static void UnDiagonalize(T &RL2, T &RL3, T &RL4, T &RH2, T &RH3, T &RH4)
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

	static const std::vector<uint32_t> IV256;
	static const std::vector<uint64_t> IV512;
	static const std::vector<uint8_t> Sigma256;
	static const std::vector<uint8_t> Sigma512;

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
	template<typename ArrayU8, typename ArrayU32x8>
	static void PermuteR10P512C(const ArrayU8 &Input, size_t InOffset, ArrayU32x8 &State, const ArrayU32x8 &IV)
	{
		std::array<uint32_t, 16> M;
		std::array<uint32_t, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

		IntegerTools::LeBytesToUL512(Input, InOffset, M, 0);

		for (i = 0; i < 10; ++i)
		{
			// round n
			R[0] += R[4] + M[Sigma256[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[0] += R[4] + M[Sigma256[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));

			R[1] += R[5] + M[Sigma256[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[1] += R[5] + M[Sigma256[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[2] += R[6] + M[Sigma256[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[2] += R[6] + M[Sigma256[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[3] += R[7] + M[Sigma256[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[3] += R[7] + M[Sigma256[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[0] += R[5] + M[Sigma256[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[0] += R[5] + M[Sigma256[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[1] += R[6] + M[Sigma256[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[1] += R[6] + M[Sigma256[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[2] += R[7] + M[Sigma256[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[2] += R[7] + M[Sigma256[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[3] += R[4] + M[Sigma256[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[3] += R[4] + M[Sigma256[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

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
	template<typename ArrayU8, typename ArrayU32x8>
	static void PermuteR10P512U(const ArrayU8 &Input, size_t InOffset, ArrayU32x8 &State, const ArrayU32x8 &IV)
	{
		uint32_t M0 = IntegerTools::LeBytesTo32(Input, InOffset);
		uint32_t M1 = IntegerTools::LeBytesTo32(Input, InOffset + 4);
		uint32_t M2 = IntegerTools::LeBytesTo32(Input, InOffset + 8);
		uint32_t M3 = IntegerTools::LeBytesTo32(Input, InOffset + 12);
		uint32_t M4 = IntegerTools::LeBytesTo32(Input, InOffset + 16);
		uint32_t M5 = IntegerTools::LeBytesTo32(Input, InOffset + 20);
		uint32_t M6 = IntegerTools::LeBytesTo32(Input, InOffset + 24);
		uint32_t M7 = IntegerTools::LeBytesTo32(Input, InOffset + 28);
		uint32_t M8 = IntegerTools::LeBytesTo32(Input, InOffset + 32);
		uint32_t M9 = IntegerTools::LeBytesTo32(Input, InOffset + 36);
		uint32_t M10 = IntegerTools::LeBytesTo32(Input, InOffset + 40);
		uint32_t M11 = IntegerTools::LeBytesTo32(Input, InOffset + 44);
		uint32_t M12 = IntegerTools::LeBytesTo32(Input, InOffset + 48);
		uint32_t M13 = IntegerTools::LeBytesTo32(Input, InOffset + 52);
		uint32_t M14 = IntegerTools::LeBytesTo32(Input, InOffset + 56);
		uint32_t M15 = IntegerTools::LeBytesTo32(Input, InOffset + 60);
		uint32_t R0 = State[0];
		uint32_t R1 = State[1];
		uint32_t R2 = State[2];
		uint32_t R3 = State[3];
		uint32_t R4 = State[4];
		uint32_t R5 = State[5];
		uint32_t R6 = State[6];
		uint32_t R7 = State[7];
		uint32_t R8 = IV[0];
		uint32_t R9 = IV[1];
		uint32_t R10 = IV[2];
		uint32_t R11 = IV[3];
		uint32_t R12 = IV[4];
		uint32_t R13 = IV[5];
		uint32_t R14 = IV[6];
		uint32_t R15 = IV[7];

		// round 0
		R0 += R4 + M0;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M1;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M2;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M3;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M4;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M5;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M7;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M8;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M9;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M10;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M11;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M12;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M13;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M14;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M15;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 1
		R0 += R4 + M14;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M10;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M4;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M8;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M9;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M15;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M13;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M1;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M12;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M0;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M2;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M11;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M7;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M5;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M3;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 2
		R0 += R4 + M11;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M8;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M12;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M0;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M5;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M2;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M15;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M13;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M10;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M14;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M3;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M6;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M7;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M1;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M9;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M4;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 3
		R0 += R4 + M7;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M9;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M3;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M1;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M13;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M12;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M11;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M14;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M2;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M6;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M5;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M10;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M4;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M0;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M15;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M8;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 4
		R0 += R4 + M9;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M0;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M5;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M7;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M2;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M4;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M10;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M15;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M14;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M1;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M11;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M12;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M6;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M8;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M3;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M13;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 5
		R0 += R4 + M2;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M12;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M6;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M10;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M0;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M11;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M8;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M3;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M4;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M13;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M7;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M5;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M15;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M14;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M1;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M9;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 6
		R0 += R4 + M12;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M5;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M1;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M15;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M14;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M13;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M4;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M10;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M0;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M7;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M6;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M3;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M9;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M2;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M8;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M11;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 7
		R0 += R4 + M13;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M11;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M7;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M14;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M12;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M1;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M3;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M9;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M5;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M0;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M15;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M4;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M8;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M6;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M2;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M10;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 8
		R0 += R4 + M6;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M15;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M14;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M9;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M11;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M3;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M0;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M8;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M12;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M2;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M13;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M7;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M1;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M4;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M10;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M5;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 9
		R0 += R4 + M10;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M2;
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M8;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M4;
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M7;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M6;
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M1;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M5;
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M15;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M11;
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M9;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M14;
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M3;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M12;
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M13;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M0;
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		State[0] ^= R0 ^ R8;
		State[1] ^= R1 ^ R9;
		State[2] ^= R2 ^ R10;
		State[3] ^= R3 ^ R11;
		State[4] ^= R4 ^ R12;
		State[5] ^= R5 ^ R13;
		State[6] ^= R6 ^ R14;
		State[7] ^= R7 ^ R15;
	}

#if defined(CEX_HAS_AVX2)

	/// <summary>
	/// The vertically vectorized form of the Blake2-256 permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU32x8>
	static void PermuteR10P512V(const ArrayU8 &Input, size_t InOffset, ArrayU32x8 &State, const ArrayU32x8 &IV)
	{
		__m128i R1, R2, R3, R4;
		__m128i B1, B2, B3, B4;
		__m128i FF0, FF1;
		__m128i T0, T1, T2;

		const __m128i R8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
		const __m128i R16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
		const __m128i M0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
		const __m128i M1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16]));
		const __m128i M2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 32]));
		const __m128i M3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 48]));

		FF0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[0]));
		FF1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[4]));
		R1 = FF0;
		R2 = FF1;
		R3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[0]));
		R4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[4]));

		// round 0
		// lm 0.1
		B1 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(M0), _mm_castsi128_ps(M1), _MM_SHUFFLE(2, 0, 2, 0)));
		// g1
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 0.2
		B2 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(M0), _mm_castsi128_ps(M1), _MM_SHUFFLE(3, 1, 3, 1)));
		// g2
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);

		// diag
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 0.3
		B3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(M2), _mm_castsi128_ps(M3), _MM_SHUFFLE(2, 0, 2, 0)));
		// g1
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 0.4
		B4 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(M2), _mm_castsi128_ps(M3), _MM_SHUFFLE(3, 1, 3, 1)));
		// g2
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 1
		// lm 1.1
		T0 = _mm_blend_epi16(M1, M2, 0x0C);
		T1 = _mm_slli_si128(M3, 4);
		T2 = _mm_blend_epi16(T0, T1, 0xF0);
		B1 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 1, 0, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 1.2
		T0 = _mm_shuffle_epi32(M2, _MM_SHUFFLE(0, 0, 2, 0));
		T1 = _mm_blend_epi16(M1, M3, 0xC0);
		T2 = _mm_blend_epi16(T0, T1, 0xF0);
		B2 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 3, 0, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 1.3
		T0 = _mm_slli_si128(M1, 4);
		T1 = _mm_blend_epi16(M2, T0, 0x30);
		T2 = _mm_blend_epi16(M0, T1, 0xF0);
		B3 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 3, 0, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 1.4
		T0 = _mm_unpackhi_epi32(M0, M1);
		T1 = _mm_slli_si128(M3, 4);
		T2 = _mm_blend_epi16(T0, T1, 0x0C);
		B4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 3, 0, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 2
		// lm 2.1
		T0 = _mm_unpackhi_epi32(M2, M3);
		T1 = _mm_blend_epi16(M3, M1, 0x0C);
		T2 = _mm_blend_epi16(T0, T1, 0x0F);
		B1 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(3, 1, 0, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 2.2
		T0 = _mm_unpacklo_epi32(M2, M0);
		T1 = _mm_blend_epi16(T0, M0, 0xF0);
		T2 = _mm_slli_si128(M3, 8);
		B2 = _mm_blend_epi16(T1, T2, 0xC0);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 2.3
		T0 = _mm_blend_epi16(M0, M2, 0x3C);
		T1 = _mm_srli_si128(M1, 12);
		T2 = _mm_blend_epi16(T0, T1, 0x03);
		B3 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 0, 3, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 2.4
		T0 = _mm_slli_si128(M3, 4);
		T1 = _mm_blend_epi16(M0, M1, 0x33);
		T2 = _mm_blend_epi16(T1, T0, 0xC0);
		B4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(0, 1, 2, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 3
		// lm 3.1
		T0 = _mm_unpackhi_epi32(M0, M1);
		T1 = _mm_unpackhi_epi32(T0, M2);
		T2 = _mm_blend_epi16(T1, M3, 0x0C);
		B1 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(3, 1, 0, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 3.2
		T0 = _mm_slli_si128(M2, 8);
		T1 = _mm_blend_epi16(M3, M0, 0x0C);
		T2 = _mm_blend_epi16(T1, T0, 0xC0);
		B2 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 0, 1, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 3.3
		T0 = _mm_blend_epi16(M0, M1, 0x0F);
		T1 = _mm_blend_epi16(T0, M3, 0xC0);
		B3 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(3, 0, 1, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 3.4
		T0 = _mm_unpacklo_epi32(M0, M2);
		T1 = _mm_unpackhi_epi32(M1, M2);
		B4 = _mm_unpacklo_epi64(T1, T0);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 4
		// lm 4.1
		T0 = _mm_unpacklo_epi64(M1, M2);
		T1 = _mm_unpackhi_epi64(M0, M2);
		T2 = _mm_blend_epi16(T0, T1, 0x33);
		B1 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 0, 1, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 4.2
		T0 = _mm_unpackhi_epi64(M1, M3);
		T1 = _mm_unpacklo_epi64(M0, M1);
		B2 = _mm_blend_epi16(T0, T1, 0x33);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 4.3
		T0 = _mm_unpackhi_epi64(M3, M1);
		T1 = _mm_unpackhi_epi64(M2, M0);
		B3 = _mm_blend_epi16(T1, T0, 0x33);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 4.4
		T0 = _mm_blend_epi16(M0, M2, 0x03);
		T1 = _mm_slli_si128(T0, 8);
		T2 = _mm_blend_epi16(T1, M3, 0x0F);
		B4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 2, 0, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 5
		// lm 5.1
		T0 = _mm_unpackhi_epi32(M0, M1);
		T1 = _mm_unpacklo_epi32(M0, M2);
		B1 = _mm_unpacklo_epi64(T0, T1);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 5.2
		T0 = _mm_srli_si128(M2, 4);
		T1 = _mm_blend_epi16(M0, M3, 0x03);
		B2 = _mm_blend_epi16(T1, T0, 0x3C);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 5.3
		T0 = _mm_blend_epi16(M1, M0, 0x0C);
		T1 = _mm_srli_si128(M3, 4);
		T2 = _mm_blend_epi16(T0, T1, 0x30);
		B3 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 2, 3, 0));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 5.4
		T0 = _mm_unpacklo_epi64(M1, M2);
		T1 = _mm_shuffle_epi32(M3, _MM_SHUFFLE(0, 2, 0, 1));
		B4 = _mm_blend_epi16(T0, T1, 0x33);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 6
		// lm 6.1
		T0 = _mm_slli_si128(M1, 12);
		T1 = _mm_blend_epi16(M0, M3, 0x33);
		B1 = _mm_blend_epi16(T1, T0, 0xC0);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 6.2
		T0 = _mm_blend_epi16(M3, M2, 0x30);
		T1 = _mm_srli_si128(M1, 4);
		T2 = _mm_blend_epi16(T0, T1, 0x03);
		B2 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(2, 1, 3, 0));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 6.3
		T0 = _mm_unpacklo_epi64(M0, M2);
		T1 = _mm_srli_si128(M1, 4);
		B3 = _mm_shuffle_epi32(_mm_blend_epi16(T0, T1, 0x0C), _MM_SHUFFLE(2, 3, 1, 0));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 6.4
		T0 = _mm_unpackhi_epi32(M1, M2);
		T1 = _mm_unpackhi_epi64(M0, T0);
		B4 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(3, 0, 1, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 7
		// lm 7.1
		T0 = _mm_unpackhi_epi32(M0, M1);
		T1 = _mm_blend_epi16(T0, M3, 0x0F);
		B1 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(2, 0, 3, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 7.2
		T0 = _mm_blend_epi16(M2, M3, 0x30);
		T1 = _mm_srli_si128(M0, 4);
		T2 = _mm_blend_epi16(T0, T1, 0x03);
		B2 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 0, 2, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 7.3
		T0 = _mm_unpackhi_epi64(M0, M3);
		T1 = _mm_unpacklo_epi64(M1, M2);
		T2 = _mm_blend_epi16(T0, T1, 0x3C);
		B3 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(0, 2, 3, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 7.4
		T0 = _mm_unpacklo_epi32(M0, M1);
		T1 = _mm_unpackhi_epi32(M1, M2);
		B4 = _mm_unpacklo_epi64(T0, T1);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 8
		// lm 8.1
		T0 = _mm_unpackhi_epi32(M1, M3);
		T1 = _mm_unpacklo_epi64(T0, M0);
		T2 = _mm_blend_epi16(T1, M2, 0xC0);
		B1 = _mm_shufflehi_epi16(T2, _MM_SHUFFLE(1, 0, 3, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 8.2
		T0 = _mm_unpackhi_epi32(M0, M3);
		T1 = _mm_blend_epi16(M2, T0, 0xF0);
		B2 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(0, 2, 1, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 8.3
		T0 = _mm_blend_epi16(M2, M0, 0x0C);
		T1 = _mm_slli_si128(T0, 4);
		B3 = _mm_blend_epi16(T1, M3, 0x0F);
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 8.4
		T0 = _mm_blend_epi16(M1, M0, 0x30);
		B4 = _mm_shuffle_epi32(T0, _MM_SHUFFLE(1, 0, 3, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		// round 9
		// lm 9.1
		T0 = _mm_blend_epi16(M0, M2, 0x03);
		T1 = _mm_blend_epi16(M1, M2, 0x30);
		T2 = _mm_blend_epi16(T1, T0, 0x0F);
		B1 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(1, 3, 0, 2));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 9.2
		T0 = _mm_slli_si128(M0, 4);
		T1 = _mm_blend_epi16(M1, T0, 0xC0);
		B2 = _mm_shuffle_epi32(T1, _MM_SHUFFLE(1, 2, 0, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B2), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(2, 1, 0, 3));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 9.3
		T0 = _mm_unpackhi_epi32(M0, M3);
		T1 = _mm_unpacklo_epi32(M2, M3);
		T2 = _mm_unpackhi_epi64(T0, T1);
		B3 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(3, 0, 2, 1));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 9.4
		T0 = _mm_blend_epi16(M3, M2, 0xC0);
		T1 = _mm_unpacklo_epi32(M0, M3);
		T2 = _mm_blend_epi16(T0, T1, 0x0F);
		B4 = _mm_shuffle_epi32(T2, _MM_SHUFFLE(0, 1, 2, 3));
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B4), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -8);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -7);
		R4 = _mm_shuffle_epi32(R4, _MM_SHUFFLE(0, 3, 2, 1));
		R3 = _mm_shuffle_epi32(R3, _MM_SHUFFLE(1, 0, 3, 2));
		R2 = _mm_shuffle_epi32(R2, _MM_SHUFFLE(2, 1, 0, 3));

		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[0]), _mm_xor_si128(FF0, _mm_xor_si128(R1, R3)));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[4]), _mm_xor_si128(FF1, _mm_xor_si128(R2, R4)));

	}

#endif

#if defined(CEX_HAS_AVX512)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-256 permutation function.
	/// <para>This function process 16*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU512>
	static void PermuteR10P16x512H(const ArrayU8 &Input, size_t InOffset, ArrayU512 &State, const ArrayU512 &IV)
	{
		std::array<UInt512, 16> M;
		std::array<UInt512, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, M, 0, M.size() * sizeof(UInt512));
#else
		for (i = 0; i < 16; ++i)
		{
			M[i].Load(
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4)),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 64),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 128),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 196),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 256),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 320),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 384),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 448),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 512),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 576),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 640),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 704),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 768),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 832),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 896),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 960));
		}
#endif

		for (i = 0; i < 10; ++i)
		{
			// round n
			R[0] += R[4] + M[Sigma256[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[0] += R[4] + M[Sigma256[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));

			R[1] += R[5] + M[Sigma256[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[1] += R[5] + M[Sigma256[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[2] += R[6] + M[Sigma256[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[2] += R[6] + M[Sigma256[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[3] += R[7] + M[Sigma256[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[3] += R[7] + M[Sigma256[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[0] += R[5] + M[Sigma256[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[0] += R[5] + M[Sigma256[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[1] += R[6] + M[Sigma256[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[1] += R[6] + M[Sigma256[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[2] += R[7] + M[Sigma256[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[2] += R[7] + M[Sigma256[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[3] += R[4] + M[Sigma256[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[3] += R[4] + M[Sigma256[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

#elif defined(CEX_HAS_AVX2)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-256 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt256 state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU256>
	static void PermuteR10P8x512H(const ArrayU8 &Input, size_t InOffset, ArrayU256 &State, const ArrayU256 &IV)
	{
		std::array<UInt256, 16> M;
		std::array<UInt256, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, M, 0, M.size() * sizeof(UInt256));
#else
		for (i = 0; i < 16; ++i)
		{
			M[i].Load(
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4)),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 64),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 128),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 196),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 256),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 320),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 384),
				IntegerTools::LeBytesTo32(Input, InOffset + (i * 4) + 448));
		}
#endif

		for (i = 0; i < 10; ++i)
		{
			// round n
			R[0] += R[4] + M[Sigma256[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[0] += R[4] + M[Sigma256[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));

			R[1] += R[5] + M[Sigma256[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[1] += R[5] + M[Sigma256[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[2] += R[6] + M[Sigma256[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[2] += R[6] + M[Sigma256[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[3] += R[7] + M[Sigma256[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[3] += R[7] + M[Sigma256[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[0] += R[5] + M[Sigma256[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (32 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 12) | (R[5] << (32 - 12)));
			R[0] += R[5] + M[Sigma256[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 8) | (R[15] << (32 - 8)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 7) | (R[5] << (32 - 7)));

			R[1] += R[6] + M[Sigma256[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (32 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 12) | (R[6] << (32 - 12)));
			R[1] += R[6] + M[Sigma256[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 8) | (R[12] << (32 - 8)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 7) | (R[6] << (32 - 7)));

			R[2] += R[7] + M[Sigma256[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (32 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 12) | (R[7] << (32 - 12)));
			R[2] += R[7] + M[Sigma256[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 8) | (R[13] << (32 - 8)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 7) | (R[7] << (32 - 7)));

			R[3] += R[4] + M[Sigma256[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (32 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 12) | (R[4] << (32 - 12)));
			R[3] += R[4] + M[Sigma256[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 8) | (R[14] << (32 - 8)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 7) | (R[4] << (32 - 7)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

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
	template<typename ArrayU8, typename ArrayU64x8>
	static void PermuteR12P1024C(const ArrayU8 &Input, size_t InOffset, ArrayU64x8 &State, const ArrayU64x8 &IV)
	{
		std::array<uint64_t, 16> M;
		std::array<uint64_t, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

		IntegerTools::LeBytesToULL1024(Input, InOffset, M, 0);

		for (i = 0; i < 12; ++i)
		{
			// round 0
			R[0] += R[4] + M[Sigma512[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[0] += R[4] + M[Sigma512[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));

			R[1] += R[5] + M[Sigma512[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[1] += R[5] + M[Sigma512[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[2] += R[6] + M[Sigma512[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[2] += R[6] + M[Sigma512[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[3] += R[7] + M[Sigma512[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[3] += R[7] + M[Sigma512[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[0] += R[5] + M[Sigma512[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[0] += R[5] + M[Sigma512[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[1] += R[6] + M[Sigma512[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[1] += R[6] + M[Sigma512[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[2] += R[7] + M[Sigma512[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[2] += R[7] + M[Sigma512[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[3] += R[4] + M[Sigma512[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[3] += R[4] + M[Sigma512[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

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
	template<typename ArrayU8, typename ArrayU64x8>
	static void PermuteR12P1024U(const ArrayU8 &Input, size_t InOffset, ArrayU64x8 &State, const ArrayU64x8 &IV)
	{
		uint64_t M0 = IntegerTools::LeBytesTo64(Input, InOffset);
		uint64_t M1 = IntegerTools::LeBytesTo64(Input, InOffset + 8);
		uint64_t M2 = IntegerTools::LeBytesTo64(Input, InOffset + 16);
		uint64_t M3 = IntegerTools::LeBytesTo64(Input, InOffset + 24);
		uint64_t M4 = IntegerTools::LeBytesTo64(Input, InOffset + 32);
		uint64_t M5 = IntegerTools::LeBytesTo64(Input, InOffset + 40);
		uint64_t M6 = IntegerTools::LeBytesTo64(Input, InOffset + 48);
		uint64_t M7 = IntegerTools::LeBytesTo64(Input, InOffset + 56);
		uint64_t M8 = IntegerTools::LeBytesTo64(Input, InOffset + 64);
		uint64_t M9 = IntegerTools::LeBytesTo64(Input, InOffset + 72);
		uint64_t M10 = IntegerTools::LeBytesTo64(Input, InOffset + 80);
		uint64_t M11 = IntegerTools::LeBytesTo64(Input, InOffset + 88);
		uint64_t M12 = IntegerTools::LeBytesTo64(Input, InOffset + 96);
		uint64_t M13 = IntegerTools::LeBytesTo64(Input, InOffset + 104);
		uint64_t M14 = IntegerTools::LeBytesTo64(Input, InOffset + 112);
		uint64_t M15 = IntegerTools::LeBytesTo64(Input, InOffset + 120);
		uint64_t R0 = State[0];
		uint64_t R1 = State[1];
		uint64_t R2 = State[2];
		uint64_t R3 = State[3];
		uint64_t R4 = State[4];
		uint64_t R5 = State[5];
		uint64_t R6 = State[6];
		uint64_t R7 = State[7];
		uint64_t R8 = IV[0];
		uint64_t R9 = IV[1];
		uint64_t R10 = IV[2];
		uint64_t R11 = IV[3];
		uint64_t R12 = IV[4];
		uint64_t R13 = IV[5];
		uint64_t R14 = IV[6];
		uint64_t R15 = IV[7];

		// round 0
		R0 += R4 + M0;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M1;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M2;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M3;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M4;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M5;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M7;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M8;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M9;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M10;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M11;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M12;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M13;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M14;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M15;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 1
		R0 += R4 + M14;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M10;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M4;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M8;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M9;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M15;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M13;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M1;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M12;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M0;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M2;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M11;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M7;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M5;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M3;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 2
		R0 += R4 + M11;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M8;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M12;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M0;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M5;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M2;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M15;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M13;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M10;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M14;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M3;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M6;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M7;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M1;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M9;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M4;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 3
		R0 += R4 + M7;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M9;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M3;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M1;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M13;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M12;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M11;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M14;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M2;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M6;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M5;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M10;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M4;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M0;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M15;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M8;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 4
		R0 += R4 + M9;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M0;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M5;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M7;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M2;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M4;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M10;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M15;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M14;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M1;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M11;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M12;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M6;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M8;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M3;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M13;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 5
		R0 += R4 + M2;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M12;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M6;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M10;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M0;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M11;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M8;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M3;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M4;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M13;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M7;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M5;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M15;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M14;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M1;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M9;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 6
		R0 += R4 + M12;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M5;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M1;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M15;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M14;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M13;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M4;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M10;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M0;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M7;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M6;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M3;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M9;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M2;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M8;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M11;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 7
		R0 += R4 + M13;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M11;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M7;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M14;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M12;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M1;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M3;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M9;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M5;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M0;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M15;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M4;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M8;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M6;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M2;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M10;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 8
		R0 += R4 + M6;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M15;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M14;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M9;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M11;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M3;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M0;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M8;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M12;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M2;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M13;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M7;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M1;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M4;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M10;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M5;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 9
		R0 += R4 + M10;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M2;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M8;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M4;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M7;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M6;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M1;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M5;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M15;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M11;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M9;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M14;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M3;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M12;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M13;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M0;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 10
		R0 += R4 + M0;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M1;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M2;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M3;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M4;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M5;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M7;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M8;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M9;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M10;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M11;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M12;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M13;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M14;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M15;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 11
		R0 += R4 + M14;
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M10;
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M4;
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M8;
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M9;
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M15;
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M13;
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M6;
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M1;
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M12;
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M0;
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M2;
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M11;
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M7;
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M5;
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M3;
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		State[0] ^= R0 ^ R8;
		State[1] ^= R1 ^ R9;
		State[2] ^= R2 ^ R10;
		State[3] ^= R3 ^ R11;
		State[4] ^= R4 ^ R12;
		State[5] ^= R5 ^ R13;
		State[6] ^= R6 ^ R14;
		State[7] ^= R7 ^ R15;
	}

#if defined(CEX_HAS_AVX2)

	/// <summary>
	/// The vertically vectorized form of the Blake2-512 permutation function.
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU64x8>
	static void PermuteR12P1024V(const ArrayU8 &Input, size_t InOffset, ArrayU64x8 &State, const ArrayU64x8 &IV)
	{
		const __m128i M0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
		const __m128i M1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16]));
		const __m128i M2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 32]));
		const __m128i M3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 48]));
		const __m128i M4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 64]));
		const __m128i M5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 80]));
		const __m128i M6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 96]));
		const __m128i M7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 112]));
		const __m128i R16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
		const __m128i R24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
		__m128i RL1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[0]));
		__m128i RH1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[2]));
		__m128i RL2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[4]));
		__m128i RH2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[6]));
		__m128i RL3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[0]));
		__m128i RH3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[2]));
		__m128i RL4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[4]));
		__m128i RH4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[6]));
		__m128i B0, B1;

		// round 0
		// lm 0.1
		B0 = _mm_unpacklo_epi64(M0, M1);
		B1 = _mm_unpacklo_epi64(M2, M3);
		// g1
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		// lm 0.2
		B0 = _mm_unpackhi_epi64(M0, M1);
		B1 = _mm_unpackhi_epi64(M2, M3);
		// g2
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);
		// diag
		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// lm 0.3
		B0 = _mm_unpacklo_epi64(M4, M5);
		B1 = _mm_unpacklo_epi64(M6, M7);
		// g1
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		// lm 0.4
		B0 = _mm_unpackhi_epi64(M4, M5);
		B1 = _mm_unpackhi_epi64(M6, M7);
		// g2
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);
		// undiag
		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 2
		B0 = _mm_unpacklo_epi64(M7, M2);
		B1 = _mm_unpackhi_epi64(M4, M6);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M5, M4);
		B1 = _mm_alignr_epi8(M3, M7, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_shuffle_epi32(M0, _MM_SHUFFLE(1, 0, 3, 2));
		B1 = _mm_unpackhi_epi64(M5, M2);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M6, M1);
		B1 = _mm_unpackhi_epi64(M3, M1);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 3
		B0 = _mm_alignr_epi8(M6, M5, 8);
		B1 = _mm_unpackhi_epi64(M2, M7);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M4, M0);
		B1 = _mm_blend_epi16(M1, M6, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_blend_epi16(M5, M1, 0xF0);
		B1 = _mm_unpackhi_epi64(M3, M4);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M7, M3);
		B1 = _mm_alignr_epi8(M2, M0, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 4
		B0 = _mm_unpackhi_epi64(M3, M1);
		B1 = _mm_unpackhi_epi64(M6, M5);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M4, M0);
		B1 = _mm_unpacklo_epi64(M6, M7);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_blend_epi16(M1, M2, 0xF0);
		B1 = _mm_blend_epi16(M2, M7, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M3, M5);
		B1 = _mm_unpacklo_epi64(M0, M4);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 5
		B0 = _mm_unpackhi_epi64(M4, M2);
		B1 = _mm_unpacklo_epi64(M1, M5);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_blend_epi16(M0, M3, 0xF0);
		B1 = _mm_blend_epi16(M2, M7, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_blend_epi16(M7, M5, 0xF0);
		B1 = _mm_blend_epi16(M3, M1, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_alignr_epi8(M6, M0, 8);
		B1 = _mm_blend_epi16(M4, M6, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 6
		B0 = _mm_unpacklo_epi64(M1, M3);
		B1 = _mm_unpacklo_epi64(M0, M4);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M6, M5);
		B1 = _mm_unpackhi_epi64(M5, M1);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_blend_epi16(M2, M3, 0xF0);
		B1 = _mm_unpackhi_epi64(M7, M0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M6, M2);
		B1 = _mm_blend_epi16(M7, M4, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 7
		B0 = _mm_blend_epi16(M6, M0, 0xF0);
		B1 = _mm_unpacklo_epi64(M7, M2);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M2, M7);
		B1 = _mm_alignr_epi8(M5, M6, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_unpacklo_epi64(M0, M3);
		B1 = _mm_shuffle_epi32(M4, _MM_SHUFFLE(1, 0, 3, 2));
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M3, M1);
		B1 = _mm_blend_epi16(M1, M5, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 8
		B0 = _mm_unpackhi_epi64(M6, M3);
		B1 = _mm_blend_epi16(M6, M1, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_alignr_epi8(M7, M5, 8);
		B1 = _mm_unpackhi_epi64(M0, M4);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_unpackhi_epi64(M2, M7);
		B1 = _mm_unpacklo_epi64(M4, M1);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M0, M2);
		B1 = _mm_unpacklo_epi64(M3, M5);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 9
		B0 = _mm_unpacklo_epi64(M3, M7);
		B1 = _mm_alignr_epi8(M0, M5, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M7, M4);
		B1 = _mm_alignr_epi8(M4, M1, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = M6;
		B1 = _mm_alignr_epi8(M5, M0, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_blend_epi16(M1, M3, 0xF0);
		B1 = M2;
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 10
		B0 = _mm_unpacklo_epi64(M5, M4);
		B1 = _mm_unpackhi_epi64(M3, M0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M1, M2);
		B1 = _mm_blend_epi16(M3, M2, 0xF0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_unpackhi_epi64(M7, M4);
		B1 = _mm_unpackhi_epi64(M1, M6);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_alignr_epi8(M7, M5, 8);
		B1 = _mm_unpacklo_epi64(M6, M0);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 11
		B0 = _mm_unpacklo_epi64(M0, M1);
		B1 = _mm_unpacklo_epi64(M2, M3);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M0, M1);
		B1 = _mm_unpackhi_epi64(M2, M3);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_unpacklo_epi64(M4, M5);
		B1 = _mm_unpacklo_epi64(M6, M7);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpackhi_epi64(M4, M5);
		B1 = _mm_unpackhi_epi64(M6, M7);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		// round 12
		B0 = _mm_unpacklo_epi64(M7, M2);
		B1 = _mm_unpackhi_epi64(M4, M6);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M5, M4);
		B1 = _mm_alignr_epi8(M3, M7, 8);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		Diagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		B0 = _mm_shuffle_epi32(M0, _MM_SHUFFLE(1, 0, 3, 2));
		B1 = _mm_unpackhi_epi64(M5, M2);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -32);
		RH4 = _mm_roti_epi64(RH4, -32);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -24);
		RH2 = _mm_roti_epi64(RH2, -24);

		B0 = _mm_unpacklo_epi64(M6, M1);
		B1 = _mm_unpackhi_epi64(M3, M1);
		RL1 = _mm_add_epi64(_mm_add_epi64(RL1, B0), RL2);
		RH1 = _mm_add_epi64(_mm_add_epi64(RH1, B1), RH2);
		RL4 = _mm_xor_si128(RL4, RL1);
		RH4 = _mm_xor_si128(RH4, RH1);
		RL4 = _mm_roti_epi64(RL4, -16);
		RH4 = _mm_roti_epi64(RH4, -16);
		RL3 = _mm_add_epi64(RL3, RL4);
		RH3 = _mm_add_epi64(RH3, RH4);
		RL2 = _mm_xor_si128(RL2, RL3);
		RH2 = _mm_xor_si128(RH2, RH3);
		RL2 = _mm_roti_epi64(RL2, -63);
		RH2 = _mm_roti_epi64(RH2, -63);

		UnDiagonalize(RL2, RL3, RL4, RH2, RH3, RH4);

		RL1 = _mm_xor_si128(RL3, RL1);
		RH1 = _mm_xor_si128(RH3, RH1);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[0]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[0])), RL1));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[2]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[2])), RH1));
		RL2 = _mm_xor_si128(RL4, RL2);
		RH2 = _mm_xor_si128(RH4, RH2);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[4]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[4])), RL2));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&State[6]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&State[6])), RH2));
	}

#endif

#if defined(CEX_HAS_AVX512)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-512 permutation function.
	/// <para>This function process 8*128 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU512>
	static void PermuteR12P8x1024H(const ArrayU8 &Input, size_t InOffset, ArrayU512 &State, const ArrayU512 &IV)
	{
		std::array<ULong512, 16> M;
		std::array<ULong512, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, M, 0, M.size() * sizeof(ULong512));
#else
		for (i = 0; i < 16; ++i)
		{
			M[i].Load(
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8)),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 128),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 256),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 384),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 512),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 640),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 768),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 896));
		}
#endif

		for (i = 0; i < 12; ++i)
		{
			// round 0
			R[0] += R[4] + M[Sigma512[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[0] += R[4] + M[Sigma512[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));

			R[1] += R[5] + M[Sigma512[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[1] += R[5] + M[Sigma512[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[2] += R[6] + M[Sigma512[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[2] += R[6] + M[Sigma512[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[3] += R[7] + M[Sigma512[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[3] += R[7] + M[Sigma512[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[0] += R[5] + M[Sigma512[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[0] += R[5] + M[Sigma512[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[1] += R[6] + M[Sigma512[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[1] += R[6] + M[Sigma512[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[2] += R[7] + M[Sigma512[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[2] += R[7] + M[Sigma512[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[3] += R[4] + M[Sigma512[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[3] += R[4] + M[Sigma512[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

#elif defined(CEX_HAS_AVX2)

	/// <summary>
	/// The horizontally vectorized form of the Blake2-512 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	/// <param name="IV">The permutations IV array</param>
	template<typename ArrayU8, typename ArrayU256>
	static void PermuteR12P4x1024H(const ArrayU8 &Input, size_t InOffset, ArrayU256 &State, const ArrayU256 &IV)
	{
		std::array<ULong256, 16> M;
		std::array<ULong256, 16> R{
			State[0],
			State[1],
			State[2],
			State[3],
			State[4],
			State[5],
			State[6],
			State[7],
			IV[0],
			IV[1],
			IV[2],
			IV[3],
			IV[4],
			IV[5],
			IV[6],
			IV[7] };
		size_t i;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::Copy(Input, InOffset, M, 0, M.size() * sizeof(ULong256));
#else
		for (i = 0; i < 16; ++i)
		{
			M[i].Load(
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8)),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 128),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 256),
				IntegerTools::LeBytesTo64(Input, InOffset + (i * 8) + 384));
		}
#endif

		for (i = 0; i < 12; ++i)
		{
			// round 0
			R[0] += R[4] + M[Sigma512[(i * 16)]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[0] += R[4] + M[Sigma512[(i * 16) + 1]];
			R[12] ^= R[0];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[8] += R[12];
			R[4] ^= R[8];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));

			R[1] += R[5] + M[Sigma512[(i * 16) + 2]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[1] += R[5] + M[Sigma512[(i * 16) + 3]];
			R[13] ^= R[1];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[9] += R[13];
			R[5] ^= R[9];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[2] += R[6] + M[Sigma512[(i * 16) + 4]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[2] += R[6] + M[Sigma512[(i * 16) + 5]];
			R[14] ^= R[2];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[10] += R[14];
			R[6] ^= R[10];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[3] += R[7] + M[Sigma512[(i * 16) + 6]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[3] += R[7] + M[Sigma512[(i * 16) + 7]];
			R[15] ^= R[3];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[11] += R[15];
			R[7] ^= R[11];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[0] += R[5] + M[Sigma512[(i * 16) + 8]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 32) | (R[15] << (64 - 32)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 24) | (R[5] << (64 - 24)));
			R[0] += R[5] + M[Sigma512[(i * 16) + 9]];
			R[15] ^= R[0];
			R[15] = ((R[15] >> 16) | (R[15] << (64 - 16)));
			R[10] += R[15];
			R[5] ^= R[10];
			R[5] = ((R[5] >> 63) | (R[5] << (64 - 63)));

			R[1] += R[6] + M[Sigma512[(i * 16) + 10]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 32) | (R[12] << (64 - 32)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 24) | (R[6] << (64 - 24)));
			R[1] += R[6] + M[Sigma512[(i * 16) + 11]];
			R[12] ^= R[1];
			R[12] = ((R[12] >> 16) | (R[12] << (64 - 16)));
			R[11] += R[12];
			R[6] ^= R[11];
			R[6] = ((R[6] >> 63) | (R[6] << (64 - 63)));

			R[2] += R[7] + M[Sigma512[(i * 16) + 12]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 32) | (R[13] << (64 - 32)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 24) | (R[7] << (64 - 24)));
			R[2] += R[7] + M[Sigma512[(i * 16) + 13]];
			R[13] ^= R[2];
			R[13] = ((R[13] >> 16) | (R[13] << (64 - 16)));
			R[8] += R[13];
			R[7] ^= R[8];
			R[7] = ((R[7] >> 63) | (R[7] << (64 - 63)));

			R[3] += R[4] + M[Sigma512[(i * 16) + 14]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 32) | (R[14] << (64 - 32)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 24) | (R[4] << (64 - 24)));
			R[3] += R[4] + M[Sigma512[(i * 16) + 15]];
			R[14] ^= R[3];
			R[14] = ((R[14] >> 16) | (R[14] << (64 - 16)));
			R[9] += R[14];
			R[4] ^= R[9];
			R[4] = ((R[4] >> 63) | (R[4] << (64 - 63)));
		}

		State[0] ^= R[0] ^ R[8];
		State[1] ^= R[1] ^ R[9];
		State[2] ^= R[2] ^ R[10];
		State[3] ^= R[3] ^ R[11];
		State[4] ^= R[4] ^ R[12];
		State[5] ^= R[5] ^ R[13];
		State[6] ^= R[6] ^ R[14];
		State[7] ^= R[7] ^ R[15];
	}

#endif

};

NAMESPACE_DIGESTEND
#endif
