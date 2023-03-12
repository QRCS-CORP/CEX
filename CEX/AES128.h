// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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

#ifndef CEX_AES128_H
#define CEX_AES128_H

#include "CexDomain.h"

#include "Intrinsics.h"
#include <wmmintrin.h>

NAMESPACE_NUMERIC

// minimum composition:
// _mm_loadu_si128, _mm_storeu_si128, _mm_slli_si128, _mm_srli_si128, _mm_shuffle_epi32, _mm_cvtsi128_si32, _mm_xor_si128
// _mm_aeskeygenassist_si128, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128

/// <summary>
/// An AES intrinsics wrapper
/// </summary>
class AES128
{
public:

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="Input">The source integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Input array</param>
	/// <param name="Output">The 128-bit integer output</param>
	template <typename Array>
	inline static void Load(const Array &Input, size_t Offset, __m128i &Output)
	{
		Output = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[Offset]));
	}

	/// <summary>
	/// Store register in an integer array
	/// </summary>
	///
	/// <param name="Input">The source 128-bit integer</param>
	/// <param name="Output">The destination integer array; must be at least 128 bits in length</param>
	/// <param name="Offset">The starting offset within the Output array</param>
	template <typename Array>
	inline void Store(__m128i &Input, Array &Output, size_t Offset) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), Input);
	}


	/// <summary>
	/// Computes the 32 bit left rotation of four unsigned integers
	/// </summary>
	///
	/// <param name="V">The 128-bit vector</param>
	/// <param name="Shift">The shift degree; maximum is 32</param>
	inline static __m128i RotL(__m128i &V, const int32_t Shift)
	{
		CEXASSERT(Shift <= 32, "Shift size is too large");

		return _mm_or_si128(_mm_slli_si128(V, static_cast<int32_t>(Shift)), _mm_slli_si128(V, static_cast<int32_t>(32 - Shift)));
	}

	/// <summary>
	/// Performs the InverseMixColumn operation on the source m128i and stores the result into m128i destination
	/// </summary>
	///
	/// <param name="V">The source vector</param>
	///
	/// <returns>The mixed vector</returns>
	inline static __m128i InverseMixColumn(__m128i &V)
	{
		return _mm_aesimc_si128(V);
	}

	/// <summary>
	/// Load an array into a register in Little Endian format
	/// </summary>
	///
	/// <param name="X">The source integer array; must be at least 128 bits in length</param>
	inline __m128i Load(const uint8_t* X)
	{
		return _mm_loadu_si128(reinterpret_cast<const __m128i*>(X));
	}

	/// <summary>
	/// Store a register in an integer array
	/// </summary>
	///
	/// <param name="V">The source 128-bit register</param>
	/// <param name="X">The destination integer array</param>
	inline static void Store(const __m128i V, uint8_t* X)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(X), V);
	}

	/// <summary>
	/// Performs one round of AES decryption
	/// </summary>
	///
	/// <param name="V">The encrypted vector</param>
	/// <param name="K">The round key</param>
	///
	/// <returns>The decrypted vector</returns>
	inline static __m128i DecryptFinal(const __m128i V, const __m128i K)
	{
		return _mm_aesdeclast_si128(V, K);
	}

	/// <summary>
	/// Performs the last round of AES decryption
	/// </summary>
	///
	/// <param name="V">The encrypted vector</param>
	/// <param name="K">The round key</param>
	///
	/// <returns>The decrypted vector</returns>
	inline static __m128i DecryptRound(const __m128i V, const __m128i K)
	{
		return _mm_aesdec_si128(V, K);
	}

	/// <summary>
	/// Performs the last round of AES encryption
	/// </summary>
	///
	/// <param name="V">The plain-text vector</param>
	/// <param name="K">The round key</param>
	///
	/// <returns>The encrypted vector</returns>
	inline static __m128i EncryptFinal(const __m128i V, const __m128i K)
	{
		return _mm_aesenclast_si128(V, K);
	}

	/// <summary>
	/// Performs one round of AES encryption
	/// </summary>
	///
	/// <param name="V">The plain-text vector</param>
	/// <param name="K">The round key</param>
	///
	/// <returns>The encrypted vector</returns>
	inline static __m128i EncryptRound(const __m128i V, const __m128i K)
	{
		return _mm_aesenc_si128(V, K);
	}

	 /// <summary>
	 /// Wraps the keygenassist api
	 /// </summary>
	 ///
	 /// <param name="K">The key vector</param>
	 /// <param name="R">The uint8_t round constant</param>
	 ///
	 /// <returns></returns>
	inline static __m128i KeyGenerate(const __m128i K, const int32_t R)
	{
		return _mm_aeskeygenassist_si128(K, R);
	}

	/// <summary>
	/// Performs carry-less integer multiplication of 64-bit halves of 128-bit input operands
	/// </summary>
	///
	/// <param name="V1">The first vector</param>
	/// <param name="V2">The second vector</param>
	/// <param name="P">Indicates which half of the vector to multiply</param>
	///
	/// <returns>The multiplied product</returns>
	inline static __m128i CMUL64(const __m128i V1, const __m128i V2, const int32_t P)
	{
		return _mm_clmulepi64_si128(V1, V2, P);
	}

	/// <summary>
	/// XOR two vectors
	/// </summary>
	///
	/// <param name="X">The first vector to multiply</param>
	/// <param name="Y">The second vector to multiply</param>
	///
	/// <returns>The multiplied vector</returns>
	inline static __m128i XOR(const __m128i X, const __m128i Y)
	{
		return _mm_xor_si128(X, Y);
	}
};

NAMESPACE_NUMERICEND

#endif
