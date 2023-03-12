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

#ifndef CEX_MEMUTILS_H
#define CEX_MEMUTILS_H

#include "CexDomain.h"
//#include <cstring>
#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	include "Intrinsics.h"
#endif

NAMESPACE_TOOLS

/// <summary>
/// Memory template functions class
/// <para>Functions that are defined in all caps, i.e. COPY128(...) are inlined and can optionally use intrinsics directly to vectorize an operation.</para>
/// </summary>
///
/// <remarks>
/// <para>The inlined intrinsics functions use arrays of at least the size indicated by their suffix, i.e. COPY256, expects an array of at least 256 bits in length.
/// All functions have sequential fallbacks, and the SIMD instruction set will default to the highest available on the compiling system (AVX/AVX2/AVX512).
/// The size of an operation relates to the size of the intrinsic function: a 128 copy, clear, set or xor function will use AVX, 
/// 256 will process 256 bits with AVX2, and the 512/1024 bit functions can use an experimental AVX512 implementation.
/// The minimum intrinsics set is AVX, AVX2 is available, and an experimental implementation of AVX512 (not tested yet!) has been added for future compatability.
/// The standard functions Copy, Clear, SetValue, and XOR, use intrinsics calls when the input/output size to that function is at least the size of the minimum available SIMD instruction set.
/// For example, XOR will loop through an array, and process with the largest available instruction set first. 
/// If the input/output size is a multiple of 32 bytes, the blocks will be processed by AVX2 until the remainder is less than a complete block, 
/// then it will fall back to AVX or sequential processing.</para>
/// </remarks>
class MemoryTools
{
public:

#if defined(CEX_HAS_AVX)
#define CEX_CACHE_SEGMENT 64

#define PREFETCHT0(address, length)									\
    do {															\
		_mm_prefetch((char*)((address) + (length)), _MM_HINT_T0);	\
    } while (false)

#define PREFETCHT1(address, length)									\
    do {															\
		_mm_prefetch((char*)((address) + (length)), _MM_HINT_T1);	\
    } while (false)

#define PREFETCHT2(address, length)									\
    do {															\
		_mm_prefetch((char*)((address) + (length)), _MM_HINT_T2);	\
    } while (false)

#define ALNMALLOC(output, length, alignment)						\
    do {															\
		(output) = _mm_malloc((length), (alignment));				\
    } while (false)

#define ALNFREE(output)												\
    do {															\
		_mm_free((output));											\
    } while (false)

#endif

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Load bytes from an integer array into L1 cache memory.
	/// <para>The Length is the number of *bytes* (8 bit integers) to load into L1 cache, this must be a compile time constant.</para>
	/// </summary>
	/// 
	/// <param name="Input">The target integer array to load into cache</param>
	/// <param name="Offset">The element offset within the target array</param>
	/// <param name="Length">The number of bytes to load, must be a compile time constant</param>
	template <typename Array>
	inline static void PrefetchL1(Array &Input, size_t Offset, size_t Length)
	{
		const size_t ELMLEN = sizeof(Array::value_type);

#if defined(CEX_HAS_AVX)
		PREFETCHT1(Input.data() + (Offset * ELMLEN), Length);
#else
		volatile Array::value_type tmp;

		tmp = 0;

		for (size_t i = 0; i < Length / ELMLEN; ++i)
		{
			tmp ^= Input[i + Offset];
		}
#endif
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Load bytes from an integer array into L2 cache memory.
	/// <para>The Length is the number of *bytes* (8 bit integers) to load into L2 cache, this must be a compile time constant.</para>
	/// </summary>
	/// 
	/// <param name="Input">The target integer array to load into cache</param>
	/// <param name="Offset">The element offset within the target array</param>
	/// <param name="Length">The number of bytes to load, must be a compile time constant</param>
	template <typename Array>
	inline static void PrefetchL2(Array &Input, size_t Offset, size_t Length)
	{
		const size_t ELMLEN = sizeof(Array::value_type);

#if defined(CEX_HAS_AVX)
		PREFETCHT2(Input.data() + (Offset * ELMLEN), Length);
#else
		volatile Array::value_type tmp;

		tmp = 0;

		for (size_t i = 0; i < Length / ELMLEN; ++i)
		{
			tmp ^= Input[i + Offset];
		}
#endif
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// <summary>
	/// Bitwise AND a specified number of 8-bit bytes to process.
	/// <para>The Length is the number of *bytes* (8 bit integers) to AND.
	/// If the length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential AND operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename ArrayA, typename ArrayB>
	inline static void AND(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);
		size_t i;
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * INPLEN >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= Length, "Length is larger than output size");
		CEXASSERT(INPLEN <= Length, "Integer type is larger than length");
		CEXASSERT(OTPLEN <= Length, "Integer type is larger than length");

		if (Length != 0)
		{
			const size_t ELMLEN = sizeof(ArrayA::value_type);
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32;
#	else
			const size_t SMDBLK = 16;
#	endif

			if (Length >= SMDBLK)
			{
				const size_t ALNLEN = Length - (Length % SMDBLK);

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					AND512(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX2)
					AND256(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX)
					AND128(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	endif
					pctr += SMDBLK;
				}
			}
#endif
			for (i = 0; i < Length - (pctr * ELMLEN); ++i)
			{
				Output[OutOffset + pctr] &= Input[InOffset + pctr];
			}
		}
	}

	/// <summary>
	/// Bitwise AND a 128 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void AND128(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 16, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 16, "Length is larger than output size");

#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_and_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
		for (size_t i = 0; i < (16 / OTPLEN); ++i)
		{
			Output[OutOffset + i] &= Input[InOffset + i];
		}
#endif
	}

	/// <summary>
	/// Bitwise AND a 256 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void AND256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 32, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 32, "Length is larger than output size");

#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_and_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
#else
		AND128(Input, InOffset, Output, OutOffset);
		AND128(Input, InOffset + (16 / INPLEN), Output, OutOffset + (16 / OTPLEN));
#endif
	}

	/// <summary>
	/// Bitwise AND a 512 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void AND512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 64, "Length is larger than output size");

#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_and_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Output[OutOffset]))));
#else
		AND256(Input, InOffset, Output, OutOffset);
		AND256(Input, InOffset + (32 / INPLEN), Output, OutOffset + (32 / OTPLEN));
#endif
	}

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Clear bytes from an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Clear.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64/128=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential clear operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination integer array to clear</param>
	/// <param name="Offset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to clear</param>
	template <typename Array>
	inline static void Clear(Array& Output, size_t Offset, size_t Length)
	{
		size_t pctr;

		if (Length != 0)
		{
			const size_t ELMLEN = sizeof(Array::value_type);
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64 / ELMLEN;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32 / ELMLEN;
#	else
			const size_t SMDBLK = 16 / ELMLEN;
#	endif

			if (Length / ELMLEN >= SMDBLK)
			{
				const size_t ALNLEN = (Length / (SMDBLK * ELMLEN)) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					CLEAR512(Output, Offset + pctr);
#	elif defined(CEX_HAS_AVX2)
					CLEAR256(Output, Offset + pctr);
#	elif defined(CEX_HAS_AVX)
					CLEAR128(Output, Offset + pctr);
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr * ELMLEN != Length)
			{
				std::memset(&Output[Offset + pctr], 0, Length - (pctr * ELMLEN));
			}
		}
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// cond PRIVATE
	CEX_OPTIMIZE_IGNORE
	/// endcond
	/// <summary>
	/// Clear bytes from an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Clear.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64/128=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential clear operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination integer array to clear</param>
	/// <param name="Length">The number of bytes to clear</param>
	static void ClearRaw(uint8_t* Output, size_t Length)
	{
		size_t pctr;

		CEXASSERT(Length > 0, "Length can not be zero");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32;
#	else
			const size_t SMDBLK = 16;
#	endif

			if (Length >= SMDBLK)
			{
				const size_t ALNLEN = (Length / SMDBLK) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					_mm512_storeu_si512(reinterpret_cast<__m512i*>(Output + pctr), _mm512_setzero_si512());
#	elif defined(CEX_HAS_AVX2)
					_mm256_storeu_si256(reinterpret_cast<__m256i*>(Output + pctr), _mm256_setzero_si256());
#	elif defined(CEX_HAS_AVX)
					_mm_storeu_si128(reinterpret_cast<__m128i*>(Output + pctr), _mm_setzero_si128());
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr != Length)
			{
				std::memset(Output + pctr, 0, Length - pctr);
			}
		}
	}
	/// cond PRIVATE
	CEX_OPTIMIZE_RESUME
	/// endcond

	/// <summary>
	/// Clear 128 bits from an integer array.
	/// <para>This is an AVX vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset Array within the destination array</param>
	template <typename Array>
	inline static void CLEAR128(Array &Output, size_t Offset)
	{
#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), _mm_setzero_si128());
#else
		std::memset(&Output[Offset], 0, 16);
#endif
	}

	/// <summary>
	/// Clear 256 bits from an integer array.
	/// <para>This is an AVX/AVX2 vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset within the destination array</param>
	template <typename Array>
	inline static void CLEAR256(Array &Output, size_t Offset)
	{
#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_setzero_si256());
#else
		CLEAR128(Output, Offset);
		CLEAR128(Output, Offset + (16 / sizeof(Array::value_type)));
#endif
	}

	/// <summary>
	/// Clear 512 bits in an integer array.
	/// <para>This is an AVX/AVX2/AVX512 vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset within the destination array</param>
	template <typename Array>
	inline static void CLEAR512(Array &Output, size_t Offset)
	{
#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_setzero_si512());
#else
		CLEAR256(Output, Offset);
		CLEAR256(Output, Offset + (32 / sizeof(Array::value_type)));
#endif
	}

	/// <summary>
	/// Compare two arrays for equality.
	/// <para>This is a constant time (not vectorized) function.</para>
	/// </summary>
	/// 
	/// <param name="A">The first integer array</param>
	/// <param name="AOffset">The offset within the first array</param>
	/// <param name="B">The second integer array</param>
	/// <param name="BOffset">The offset within the second array</param>
	/// <param name="Elements">The number of array element to compare</param>
	template<typename Array>
	inline static bool Compare(const Array &A, size_t AOffset, const Array &B, size_t BOffset, size_t Elements)
	{
		size_t diff;

		diff = 0;

		for (size_t i = 0; i != Elements; ++i)
		{
			diff |= (A[AOffset + i] ^ B[BOffset + i]);
		}

		return diff == 0;
	}

	/// <summary>
	/// Copy memory from an object using a pointer to an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512),
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The object pointer to copy memory from</param>
	/// <param name="Output">The integer destination array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename Object, typename Array>
	inline static void CopyFromObject(const Object* Input, Array &Output, size_t OutOffset, size_t Length)
	{
		const size_t ELMLEN = sizeof(Array::value_type);
		size_t pctr;

		CEXASSERT((Output.size() - OutOffset) * ELMLEN >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64 / ELMLEN;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32 / ELMLEN;
#	else
			const size_t SMDBLK = 16 / ELMLEN;
#	endif

			if (Length / ELMLEN >= SMDBLK)
			{
				const size_t ALNLEN = (Length / (SMDBLK * ELMLEN)) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					COPY512FROMOBJECT(Input + pctr, Output, OutOffset + pctr);
#	elif defined(CEX_HAS_AVX2)
					COPY256FROMOBJECT(Input + pctr, Output, OutOffset + pctr);
#	elif defined(CEX_HAS_AVX)
					COPY128FROMOBJECT(Input + pctr, Output, OutOffset + pctr);
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr * ELMLEN != Length)
			{
				std::memcpy(&Output[OutOffset + pctr], Input + pctr, Length - (pctr * ELMLEN));
			}
		}
	}

	/// <summary>
	/// Copy an integer array to an objects memory pointer.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512),
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The integer source array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destinations object pointer</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename Object, typename Array>
	inline static void CopyToObject(const Array &Input, size_t InOffset, Object* Output, size_t Length)
	{
		const size_t ELMLEN = sizeof(Array::value_type);
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * ELMLEN >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64 / ELMLEN;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32 / ELMLEN;
#	else
			const size_t SMDBLK = 16 / ELMLEN;
#	endif

			if (Length / ELMLEN >= SMDBLK)
			{
				const size_t ALNLEN = (Length / (SMDBLK * ELMLEN)) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					COPY512TOOBJECT(Input, InOffset + pctr, Output + pctr);
#	elif defined(CEX_HAS_AVX2)
					COPY256TOOBJECT(Input, InOffset + pctr, Output + pctr);
#	elif defined(CEX_HAS_AVX)
					COPY128TOOBJECT(Input, InOffset + pctr, Output + pctr);
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr * ELMLEN != Length)
			{
				std::memcpy(Output + pctr, &Input[InOffset + pctr], Length - (pctr * ELMLEN));
			}
		}
	}

	/// <summary>
	/// Copy bytes from an array to an integer.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer (V) type uint8_t size.</para>
	/// </summary>
	/// 
	/// <param name="Input">The integer source array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Value">The destination value</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename Array, typename V>
	inline static void CopyToValue(const Array &Input, size_t InOffset, V &Value, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(Array::value_type) >= Length, "Length is larger than input size");

		std::memcpy(&Value, &Input[InOffset], Length);
	}

	/// <summary>
	/// Copy bytes from an integer to an array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer arrays uint8_t size.</para>
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename V, typename Array>
	inline static void CopyFromValue(const V Value, Array &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Output.size() - OutOffset) * sizeof(Array::value_type) >= Length, "Length is larger than input size");

		std::memcpy(&Output[OutOffset], &Value, Length);
	}

	/// <summary>
	/// Copy an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512),
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The integer source array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The integer destination array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename Array>
	inline static void Copy(const Array &Input, size_t InOffset, Array &Output, size_t OutOffset, size_t Length)
	{
		const size_t ELMLEN = sizeof(Array::value_type);
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * ELMLEN >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * ELMLEN >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64 / ELMLEN;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32 / ELMLEN;
#	else
			const size_t SMDBLK = 16 / ELMLEN;
#	endif

			if (Length / ELMLEN >= SMDBLK)
			{
				const size_t ALNLEN = (Length / (SMDBLK * ELMLEN)) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					COPY512(Input, InOffset + pctr, Output, OutOffset + pctr);
#	elif defined(CEX_HAS_AVX2)
					COPY256(Input, InOffset + pctr, Output, OutOffset + pctr);
#	elif defined(CEX_HAS_AVX)
					COPY128(Input, InOffset + pctr, Output, OutOffset + pctr);
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr * ELMLEN != Length)
			{
				std::memcpy(&Output[OutOffset + pctr], &Input[InOffset + pctr], Length - (pctr * ELMLEN));
			}
		}
	}

	/// <summary>
	/// Copy an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename ArrayA, typename ArrayB>
	inline static void Copy(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * INPLEN >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			pctr = 0;

#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32;
#	elif defined(CEX_HAS_AVX)
			const size_t SMDBLK = 16;
#	endif

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
			if (Length >= SMDBLK)
			{
				const size_t ALNLEN = Length - (Length % SMDBLK);

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					COPY512(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX2)
					COPY256(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX)
					COPY128(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr != Length)
			{
				std::memcpy(&Output[OutOffset + (pctr / OTPLEN)], &Input[InOffset + (pctr / INPLEN)], Length - pctr);
			}
		}
	}

	/// <summary>
	/// Copy a raw uint8_t array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512),
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The uint8_t source array to copy</param>
	/// <param name="Output">The uint8_t destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	inline static void CopyRaw(const uint8_t* Input, uint8_t* Output, size_t Length)
	{
		size_t pctr;

		CEXASSERT(Length > 0, "Length can not be zero");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32;
#	else
			const size_t SMDBLK = 16;
#	endif

			if (Length >= SMDBLK)
			{
				const size_t ALNLEN = (Length / SMDBLK) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					_mm512_storeu_si512(reinterpret_cast<__m512i*>(Output + pctr), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(Input + pctr)));
#	elif defined(CEX_HAS_AVX2)
					_mm256_storeu_si256(reinterpret_cast<__m256i*>(Output + pctr), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Input + pctr)));
#	elif defined(CEX_HAS_AVX)
					_mm_storeu_si128(reinterpret_cast<__m128i*>(Output + pctr), _mm_loadu_si128(reinterpret_cast<const __m128i*>(Input + pctr)));
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr != Length)
			{
				std::memcpy(Output + pctr, Input + pctr, Length - pctr);
			}
		}
	}

	/// <summary>
	/// Copy 128 bits from an object pointer to an array.
	/// <para>This is an AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The object pointer to copy memory from</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename Object, typename Array>
	inline static void COPY128FROMOBJECT(const Object* Input, Array &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_loadu_si128(reinterpret_cast<const __m128i*>(Input)));
#else
		std::memcpy(&Output[OutOffset], Input, 16);
#endif
	}

	/// <summary>
	/// Copy 128 bits from an array to an object pointer.
	/// <para>This is an AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination object pointer</param>
	template <typename Object, typename Array>
	inline static void COPY128TOOBJECT(Array &Input, size_t InOffset, Object* Output)
	{
#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(Output), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])));
#else
		std::memcpy(Output, &Input[InOffset], 16);
#endif
	}

	/// <summary>
	/// Copy 128 bits between integer arrays.
	/// <para>This is an AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY128(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])));
#else
		std::memcpy(&Output[OutOffset], &Input[InOffset], 16);
#endif
	}

	/// <summary>
	/// Copy 256 bits from an object pointer to an array.
	/// <para>This is an AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The object pointer to copy memory from</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename Object, typename Array>
	inline static void COPY256FROMOBJECT(const Object* Input, Array &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Input)));
#else
		COPY128(Input, Output, OutOffset);
		COPY128(Input + 16, Output, OutOffset + (16 / sizeof(Array::value_type)));
#endif
	}

	/// <summary>
	/// Copy 256 bits from an array to an object pointer.
	/// <para>This is an AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination object pointer</param>
	template <typename Object, typename Array>
	inline static void COPY256TOOBJECT(const Array &Input, size_t InOffset, Object* Output)
	{
#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(Output), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])));
#else
		COPY128(Input, InOffset, Output);
		COPY128(Input + InOffset + (16 / sizeof(Array::value_type)), Output + 16);
#endif
	}

	/// <summary>
	/// Copy 256 bits between integer arrays.
	/// <para>This is an AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])));
#else
		COPY128(Input, InOffset, Output, OutOffset);
		COPY128(Input, InOffset + (16 / sizeof(ArrayA::value_type)), Output, OutOffset + (16 / sizeof(ArrayB::value_type)));
#endif
	}

	/// <summary>
	/// Copy 512 bits from an object pointer to an array.
	/// <para>This is an AVX512/AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The object pointer to copy memory from</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename Object, typename Array>
	inline static void COPY512FROMOBJECT(const Object* Input, Array &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(Input)));
#else
		COPY256(Input, Output, OutOffset);
		COPY256(Input + 32, Output, OutOffset + (32 / sizeof(Array::value_type)));
#endif
	}

	/// <summary>
	/// Copy 512 bits from an array to an object pointer.
	/// <para>This is an AVX512/AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination object pointer</param>
	template <typename Object, typename Array>
	inline static void COPY512TOOBJECT(const Array &Input, size_t InOffset, Object* Output)
	{
#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(Output), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])));
#else
		COPY256(Input, InOffset, Output);
		COPY256(Input, InOffset + (32 / sizeof(Array::value_type)), Output + 32);
#endif
	}

	/// <summary>
	/// Copy 512 bits between integer arrays.
	/// <para>This is an AVX512/AVX2/AVX vectorized copy operation.
	/// Warning! This is an internal function and may not work properly if called directly, 
	/// use the Copy method instead.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])));
#else
		COPY256(Input, InOffset, Output, OutOffset);
		COPY256(Input, InOffset + (32 / sizeof(ArrayA::value_type)), Output, OutOffset + (32 / sizeof(ArrayB::value_type)));
#endif
	}

	/// <summary>
	/// Allocate a block of memory
	/// </summary>
	/// 
	/// <param name="Length">The length of the requested block</param>
	///
	/// <returns>Returns the aligned array of bytes, or NULL on failure</returns>
	static void* Malloc(size_t Length)
	{
		void* ret;

		ret = NULL;

		if (Length != 0)
		{
#if defined(CEX_COMPILER_MSC)
			ret = _aligned_malloc(Length, CEX_SIMD_ALIGNMENT);
#else
			ret = malloc(Length);
#endif
		}

		return ret;
	}

	/// <summary>
	/// Resize a block of memory
	/// </summary>
	/// 
	/// <param name="Block">A pointer to a block of memory</param>
	/// <param name="Length">The length of the requested block</param>
	///
	/// <returns>Returns the aligned array of bytes, or NULL on failure</returns>
	static void* Realloc(void* Block, size_t Length)
	{
		void* ret;

		ret = NULL;

		if (Length != 0)
		{
#if defined(CEX_COMPILER_MSC)
			ret = _aligned_realloc(Block, Length, CEX_SIMD_ALIGNMENT);
#else
			ret = realloc(Block, Length);
#endif
		}

		return ret;
	}

	/// <summary>
	/// Free a memory block created with alloc
	/// </summary>
	/// 
	/// <param name="Block">A pointer to the memory block to release</param>
	static void MallocFree(void* Block)
	{
		if (Block != NULL)
		{
#if defined(CEX_COMPILER_MSC)
			_aligned_free(Block);
#else
			free(Block);
#endif
		}
	}

	/// <summary>
	/// Move an integer array.
	/// <para>This is a sequential move operation.
	/// The Length is the number of *bytes* (8 bit integers) to Move.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to clear</param>
	template <typename ArrayA, typename ArrayB>
	inline static void Move(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(ArrayA::value_type) >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * sizeof(ArrayB::value_type) >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			std::memmove(&Output[OutOffset], &Input[InOffset], Length);
		}
	}

	/// <summary>
	/// Bitwise OR a specified number of 8-bit bytes to process.
	/// <para>The Length is the number of *bytes* (8 bit integers) to OR.
	/// If the length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential OR operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename ArrayA, typename ArrayB>
	inline static void OR(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);
		const size_t ELMLEN = sizeof(ArrayA::value_type);
		size_t i;
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * INPLEN >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= Length, "Length is larger than output size");
		CEXASSERT(INPLEN <= Length, "Integer type is larger than length");
		CEXASSERT(OTPLEN <= Length, "Integer type is larger than length");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32;
#	else
			const size_t SMDBLK = 16;
#	endif

			if (Length >= SMDBLK)
			{
				const size_t ALNLEN = Length - (Length % SMDBLK);

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					OR512(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX2)
					OR256(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX)
					OR128(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	endif
					pctr += SMDBLK;
				}
			}
#endif
			for (i = 0; i < Length - (pctr * ELMLEN); ++i)
			{
				Output[OutOffset + pctr] |= Input[InOffset + pctr];
			}
		}
	}

	/// <summary>
	/// Bitwise OR a 128 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void OR128(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 16, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 16, "Length is larger than output size");

#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_or_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
		for (size_t i = 0; i < (16 / OTPLEN); ++i)
		{
			Output[OutOffset + i] &= Input[InOffset + i];
		}
#endif
	}

	/// <summary>
	/// Bitwise OR a 256 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void OR256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 32, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 32, "Length is larger than output size");

#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_or_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
#else
		OR128(Input, InOffset, Output, OutOffset);
		OR128(Input, InOffset + (16 / INPLEN), Output, OutOffset + (16 / OTPLEN));
#endif
	}

	/// <summary>
	/// Bitwise OR a 512 bit block
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void OR512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 64, "Length is larger than output size");

#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_or_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Output[OutOffset]))));
#else
		OR256(Input, InOffset, Output, OutOffset);
		OR256(Input, InOffset + (32 / INPLEN), Output, OutOffset + (32 / OTPLEN));
#endif
	}

	/// <summary>
	/// Set memory to a fixed value.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Set.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The source integer array to modify</param>
	/// <param name="Offset">The offset within the source array</param>
	/// <param name="Length">The number of bytes to change</param>
	/// <param name="Value">The 8 bit uint8_t value to set</param>
	template <typename Array>
	inline static void SetValue(Array &Output, size_t Offset, size_t Length, uint8_t Value)
	{
		const size_t ELMLEN = sizeof(Array::value_type);
		size_t pctr;

		CEXASSERT((Output.size() - Offset) * ELMLEN >= Length, "Length is larger than output size");

		if (Length != 0)
		{
			pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
			const size_t SMDBLK = 64 / ELMLEN;
#	elif defined(CEX_HAS_AVX2)
			const size_t SMDBLK = 32 / ELMLEN;
#	else
			const size_t SMDBLK = 16 / ELMLEN;
#	endif

			if (Length / ELMLEN >= SMDBLK)
			{
				const size_t ALNLEN = (Length / (SMDBLK * ELMLEN)) * SMDBLK;

				while (pctr != ALNLEN)
				{
#	if defined(CEX_HAS_AVX512)
					SETVAL512(Output, Offset + pctr, Value);
#	elif defined(CEX_HAS_AVX2)
					SETVAL256(Output, Offset + pctr, Value);
#	elif defined(CEX_HAS_AVX)
					SETVAL128(Output, Offset + pctr, Value);
#	endif
					pctr += SMDBLK;
				}
			}
#endif

			if (pctr * ELMLEN != Length)
			{
				std::memset(&Output[Offset + pctr], Value, Length - (pctr * ELMLEN));
			}
		}
	}

	/// <summary>
	/// Set 128 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The source integer array to modify</param>
	/// <param name="Offset">The offset within the source array</param>
	/// <param name="Value">The 8 bit uint8_t value to set</param>
	template <typename Array>
	inline static void SETVAL128(Array &Output, size_t Offset, uint8_t Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(Array::value_type) >= 16, "Length is larger than output size");

#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), _mm_set1_epi8(Value));
#else
		std::memset(&Output[Offset], Value, 16);
#endif
	}

	/// <summary>
	/// Set 256 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The source integer array to modify</param>
	/// <param name="Offset">The offset within the source array</param>
	/// <param name="Value">The 8 bit uint8_t value to set</param>
	template <typename Array>
	inline static void SETVAL256(Array &Output, size_t Offset, uint8_t Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(Array::value_type) >= 32, "Length is larger than output size");

#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_set1_epi8(Value));
#else
		SETVAL128(Output, Offset, Value);
		SETVAL128(Output, Offset + (16 / sizeof(Array::value_type)), Value);
#endif
	}

	/// <summary>
	/// Set 512 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The source integer array to modify</param>
	/// <param name="Offset">The offset within the source array</param>
	/// <param name="Value">The 8 bit uint8_t value to set</param>
	template <typename Array>
	inline static void SETVAL512(Array &Output, size_t Offset, uint8_t Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(Array::value_type) >= 64, "Length is larger than output size");

#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_set1_epi8(Value));
#else
		SETVAL256(Output, Offset, Value);
		SETVAL256(Output, Offset + (32 / sizeof(Array::value_type)), Value);
#endif
	}

	/// <summary>
	/// Block XOR a specified number of 8-bit bytes to process.
	/// <para>The Length is the number of *bytes* (8 bit integers) to XOR.
	/// If the length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential XOR operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XOR(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);
		size_t pctr;

		CEXASSERT((Input.size() - InOffset) * INPLEN >= Length, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= Length, "Length is larger than output size");
		CEXASSERT(Length > 0, "Length can not be zero");
		CEXASSERT(INPLEN <= Length, "Integer type is larger than length");
		CEXASSERT(OTPLEN <= Length, "Integer type is larger than length");

		pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (Length >= SMDBLK)
		{
			const size_t ALNLEN = Length - (Length % SMDBLK);

			while (pctr != ALNLEN)
			{
#	if defined(CEX_HAS_AVX512)
				XOR512(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX2)
				XOR256(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	elif defined(CEX_HAS_AVX)
				XOR128(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN));
#	endif
				pctr += SMDBLK;
			}
		}
#endif
		if (pctr * OTPLEN != Length)
		{
			XorPartial(Input, InOffset + (pctr / INPLEN), Output, OutOffset + (pctr / OTPLEN), Length - pctr);
		}
	}

	/// <summary>
	/// Block XOR a specified number of 8-bit bytes to process.
	/// <para>The Length is the number of *bytes* (8 bit integers) to XOR.
	/// If the length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), 
	/// the operation is vectorized, otherwise this is a sequential XOR operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="Length">The number of bytes to process</param>
	inline static void XorRaw(const uint8_t* Input, uint8_t* Output, size_t Length)
	{
		size_t pctr;

		CEXASSERT(Length > 0, "Length can not be zero");

		pctr = 0;

#if defined(CEX_HAS_AVX) || defined(CEX_HAS_AVX2) || defined(CEX_HAS_AVX512)
#	if defined(CEX_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(CEX_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (Length >= SMDBLK)
		{
			const size_t ALNLEN = Length - (Length % SMDBLK);

			while (pctr != ALNLEN)
			{
#	if defined(CEX_HAS_AVX512)
				_mm512_storeu_si512(reinterpret_cast<__m512i*>(Output + pctr), _mm512_xor_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(Input + pctr)), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(Output + pctr))));
#	elif defined(CEX_HAS_AVX2)
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(Output + pctr), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(Input + pctr)), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Output + pctr))));
#	elif defined(CEX_HAS_AVX)
				_mm_storeu_si128(reinterpret_cast<__m128i*>(Output + pctr), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(Input + pctr)), _mm_loadu_si128(reinterpret_cast<__m128i*>(Output + pctr))));
#	endif
				pctr += SMDBLK;
			}
		}
#endif
		while (pctr < Length)
		{
			Output[pctr] ^= Input[pctr];
			++pctr;
		}
	}

	/// <summary>
	/// Block XOR 128 bits
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XOR128(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 16, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 16, "Length is larger than output size");

#if defined(CEX_HAS_AVX)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
		for (size_t i = 0; i < (16 / OTPLEN); ++i)
		{
			Output[OutOffset + i] ^= Input[InOffset + i];
		}
#endif
	}

	/// <summary>
	/// Block XOR 256 bits
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XOR256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 32, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 32, "Length is larger than output size");

#if defined(CEX_HAS_AVX2)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
#else
		XOR128(Input, InOffset, Output, OutOffset);
		XOR128(Input, InOffset + (16 / INPLEN), Output, OutOffset + (16 / OTPLEN));
#endif
	}

	/// <summary>
	/// Block XOR 512 bits
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XOR512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 64, "Length is larger than output size");

#if defined(CEX_HAS_AVX512)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_xor_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Output[OutOffset]))));
#else
		XOR256(Input, InOffset, Output, OutOffset);
		XOR256(Input, InOffset + (32 / INPLEN), Output, OutOffset + (32 / OTPLEN));
#endif
	}

	/// <summary>
	/// Block XOR 1024 bits
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XOR1024(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);

		CEXASSERT((Input.size() - InOffset) * INPLEN >= 64, "Length is larger than input size");
		CEXASSERT((Output.size() - OutOffset) * OTPLEN >= 64, "Length is larger than output size");

		XOR512(Input, InOffset, Output, OutOffset);
		XOR512(Input, InOffset + (64 / INPLEN), Output, OutOffset + (64 / OTPLEN));
	}

	/// <summary>
	/// XOR unaligned bit blocks (less than 16 bytes).
	/// <para>The Length must be the size in bytes (8 bit integers) to XOR.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename ArrayA, typename ArrayB>
	inline static void XorPartial(ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t INPLEN = sizeof(ArrayA::value_type);
		const size_t OTPLEN = sizeof(ArrayB::value_type);
		size_t i;

		uint8_t* pinp = (uint8_t*)Input.data() + (InOffset * INPLEN);
		uint8_t* potp = (uint8_t*)Output.data() + (OutOffset * OTPLEN);

		for (i = 0; i < Length; ++i)
		{
			potp[i] ^= pinp[i];
		}
	}

	template <typename Array>
	inline static void XorPad(Array &Output, uint8_t N)
	{
		size_t pctr;

		pctr = 0;

#if defined(CEX_HAS_AVX512)

		const size_t SMDLEN = sizeof(__m512i);
		const size_t ALNLEN = (Output.size() / SMDLEN) * SMDLEN;

		if (ALNLEN != 0)
		{
			__m512i zmm = _mm512_set1_epi8(N);

			while (pctr != ALNLEN)
			{
				_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[pctr]), _mm512_xor_si512(zmm, _mm512_loadu_si512(reinterpret_cast<__m512i*>(&Output[pctr]))));
				pctr += SMDLEN;
			}
		}

#elif defined(CEX_HAS_AVX2)

		const size_t SMDLEN = sizeof(__m256i);
		const size_t ALNLEN = (Output.size() / SMDLEN) * SMDLEN;

		if (ALNLEN != 0)
		{
			__m256i ymm = _mm256_set1_epi8(N);

			while (pctr != ALNLEN)
			{
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[pctr]), _mm256_xor_si256(ymm, _mm256_loadu_si256(reinterpret_cast<__m256i*>(&Output[pctr]))));
				pctr += SMDLEN;
			}
		}

#elif defined(CEX_HAS_AVX)

		const size_t SMDLEN = sizeof(__m128i);
		const size_t ALNLEN = (Output.size() / SMDLEN) * SMDLEN;

		if (ALNLEN != 0)
		{
			__m128i xmm = _mm_set1_epi8(N);

			while (pctr != ALNLEN)
			{
				_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[pctr]), _mm_xor_si128(xmm, _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[pctr]))));
				pctr += SMDLEN;
			}
		}

#endif

		while (pctr < Output.size())
		{
			Output[pctr] ^= N;
			++pctr;
		}
	}
};

NAMESPACE_TOOLSEND
#endif
