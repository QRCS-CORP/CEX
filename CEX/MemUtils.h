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

#ifndef CEX_MEMUTILS_H
#define CEX_MEMUTILS_H

#include "CexDomain.h"
#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	include "Intrinsics.h"
#endif

NAMESPACE_UTILITY

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
/// The standard functions Copy, Clear, SetValue, and XorBlock, use intrinsics calls when the input/output size to that function is at least the size of the minimum available SIMD instruction set.
/// For example, XorBlock will loop through an array, and process with the largest available instruction set first. 
/// If the input/output size is a multiple of 32 bytes, the blocks will be processed by AVX2 until the remainder is less than a complete block, 
/// then it will fall back to AVX or sequential processing.</para>
/// </remarks>
class MemUtils
{
public:

#if defined(__AVX__)
#define CEX_CACHE_SEGMENT 64

#define PREFETCHT0(address, length)								\
    do {														\
		_mm_prefetch(((char*)(address)) + length, _MM_HINT_T0);	\
    } while (false)

#define PREFETCHT1(address, length)								\
    do {														\
		_mm_prefetch(((char*)(address)) + length, _MM_HINT_T1);	\
    } while (false)

#define PREFETCHT2(address, length)								\
    do {														\
		_mm_prefetch(((char*)(address)) + length, _MM_HINT_T2);	\
    } while (false)

#define ALNMALLOC(output, length, alignment)					\
    do {														\
		output = _mm_malloc(length, alignment);					\
    } while (false)

#define ALNFREE(output)											\
    do {														\
		_mm_free(output);										\
    } while (false)

#endif

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
	inline static void Clear(Array &Output, size_t Offset, size_t Length)
	{
		if (Length != 0)
		{
			const size_t ELMSZE = sizeof(Array::value_type);
			CexAssert((Output.size() - Offset) * ELMSZE >= Length, "Length is larger than output capacity");
			CexAssert(ELMSZE <= Length, "Integer type is larger than length");

			size_t prcCtr = 0;

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			const size_t SMDBLK = 64 / ELMSZE;
#	elif defined(__AVX2__)
			const size_t SMDBLK = 32 / ELMSZE;
#	else
			const size_t SMDBLK = 16 / ELMSZE;
#	endif

			if (Length / ELMSZE >= SMDBLK)
			{
				const size_t ALNSZE = (Length / (SMDBLK * ELMSZE)) * SMDBLK;

				while (prcCtr != ALNSZE)
				{
#if defined(__AVX512__)
					CLEAR512(Output, Offset + prcCtr);
#elif defined(__AVX2__)
					CLEAR256(Output, Offset + prcCtr);
#elif defined(__AVX__)
					CLEAR128(Output, Offset + prcCtr);
#endif
					prcCtr += SMDBLK;
				}
			}
#endif

			if (prcCtr * ELMSZE != Length)
			{
				std::memset(&Output[Offset + prcCtr], 0, Length - (prcCtr * ELMSZE));
			}
		}
	}

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
#if defined(__AVX__)
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
#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_setzero_si256());
#else
		CLEAR128(Output, Offset);
		CLEAR128(Output, Offset + (16 / sizeof(Output[0])));
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
#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_setzero_si512());
#else
		CLEAR256(Output, Offset);
		CLEAR256(Output, Offset + (32 / sizeof(Output[0])));
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
		CexAssert((A.size() - AOffset) >= Length, "Length is larger than A size");
		CexAssert((B.size() - BOffset) >= Length, "Length is larger than B size");

		size_t diff = 0;

		for (size_t i = 0; i != Elements; ++i)
		{
			diff |= (A[AOffset + i] ^ B[BOffset + i]);
		}

		return diff == 0;
	}

	/// <summary>
	/// Copy bytes from an array to an integer.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer (V) type byte size.</para>
	/// </summary>
	/// 
	/// <param name="Input">The integer source array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Value">The destination value</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename Array, typename V>
	inline static void CopyToValue(const Array &Input, size_t InOffset, V &Value, size_t Length)
	{
		CexAssert((Input.size() - InOffset) * sizeof(Array::value_type) >= Length, "Length is larger than input capacity");
		CexAssert(Length <= sizeof(V), "Length is larger than value");

		std::memcpy(&Value, &Input[InOffset], Length);
	}

	/// <summary>
	/// Copy bytes from an integer to an array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer arrays byte size.</para>
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename V, typename Array>
	inline static void CopyFromValue(const V Value, Array &Output, size_t OutOffset, size_t Length)
	{
		CexAssert((Output.size() - OutOffset) * sizeof(Array::value_type) >= Length, "Length is larger than input capacity");
		CexAssert(Length <= sizeof(V), "Length is larger than value");

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
		if (Length != 0)
		{
			const size_t ELMSZE = sizeof(Array::value_type);

			CexAssert((Input.size() - InOffset) * ELMSZE >= Length, "Length is larger than input capacity");
			CexAssert((Output.size() - OutOffset) * ELMSZE >= Length, "Length is larger than output capacity");

			size_t prcCtr = 0;

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			const size_t SMDBLK = 64 / ELMSZE;
#	elif defined(__AVX2__)
			const size_t SMDBLK = 32 / ELMSZE;
#	else
			const size_t SMDBLK = 16 / ELMSZE;
#	endif

			if (Length / ELMSZE >= SMDBLK)
			{
				const size_t ALNSZE = (Length / (SMDBLK * ELMSZE)) * SMDBLK;

				while (prcCtr != ALNSZE)
				{
#if defined(__AVX512__)
					COPY512(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX2__)
					COPY256(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX__)
					COPY128(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#endif
					prcCtr += SMDBLK;
				}
			}
#endif

			if (prcCtr * ELMSZE != Length)
			{
				std::memcpy(&Output[OutOffset + prcCtr], &Input[InOffset + prcCtr], Length - (prcCtr * ELMSZE));
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
		if (Length != 0)
		{
			const size_t INPSZE = sizeof(ArrayA::value_type);
			const size_t OUTSZE = sizeof(ArrayB::value_type);

			CexAssert((Input.size() - InOffset) * INPSZE >= Length, "Length is larger than input capacity");
			CexAssert((Output.size() - OutOffset) * OUTSZE >= Length, "Length is larger than output capacity");
			CexAssert(INPSZE <= 16 && OUTSZE <= 16, "Integer type is larger than 128 bits");

#if defined(__AVX512__)
			const size_t SMDBLK = 64;
#elif defined(__AVX2__)
			const size_t SMDBLK = 32;
#elif defined(__AVX__)
			const size_t SMDBLK = 16;
#endif

			size_t prcCtr = 0;

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
			if (Length >= SMDBLK)
			{
				const size_t ALNSZE = Length - (Length % SMDBLK);

				while (prcCtr != ALNSZE)
				{
#if defined(__AVX512__)
					COPY512(Input, InOffset + (prcCtr / INPSZE), Output, OutOffset + (prcCtr / OUTSZE));
#elif defined(__AVX2__)
					COPY256(Input, InOffset + (prcCtr / INPSZE), Output, OutOffset + (prcCtr / OUTSZE));
#elif defined(__AVX__)
					COPY128(Input, InOffset + (prcCtr / INPSZE), Output, OutOffset + (prcCtr / OUTSZE));
#endif
					prcCtr += SMDBLK;
				}
			}
#endif

			if (prcCtr != Length)
			{
				std::memcpy(&Output[OutOffset + (prcCtr / OUTSZE)], &Input[InOffset + (prcCtr / INPSZE)], Length - prcCtr);
			}
		}
	}

	/// <summary>
	/// Copy 128 bits between integer arrays.
	/// <para>This is an AVX vectorized copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY128(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(__AVX__)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])));
#else
		std::memcpy(&Output[OutOffset], &Input[InOffset], 16);
#endif
	}

	/// <summary>
	/// Copy 256 bits between integer arrays.
	/// <para>This is an AVX2/AVX vectorized copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY256(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])));
#else
		COPY128(Input, InOffset, Output, OutOffset);
		COPY128(Input, InOffset + (16 / sizeof(Input[0])), Output, OutOffset + (16 / sizeof(Output[0])));
#endif
	}

	/// <summary>
	/// Copy 512 bits between integer arrays.
	/// <para>This is an AVX512/AVX2/AVX vectorized copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The source integer array to copy</param>
	/// <param name="InOffset">The offset within the source array</param>
	/// <param name="Output">The destination integer array</param>
	/// <param name="OutOffset">The offset within the destination array</param>
	template <typename ArrayA, typename ArrayB>
	inline static void COPY512(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset)
	{
#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])));
#else
		COPY256(Input, InOffset, Output, OutOffset);
		COPY256(Input, InOffset + (32 / sizeof(Input[0])), Output, OutOffset + (32 / sizeof(Output[0])));
#endif
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
		if (Length != 0)
		{
			CexAssert((Input.size() - InOffset) * sizeof(ArrayA::value_type) >= Length, "Length is larger than input capacity");
			CexAssert((Output.size() - OutOffset) * sizeof(ArrayB::value_type) >= Length, "Length is larger than output capacity");

			std::memmove(&Output[OutOffset], &Input[InOffset], Length);
		}
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
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename Array>
	inline static void SetValue(Array &Output, size_t Offset, size_t Length, byte Value)
	{
		if (Length != 0)
		{
			const size_t ELMSZE = sizeof(Array::value_type);

			CexAssert((Output.size() - Offset) * ELMSZE >= Length, "Length is larger than output capacity");
			CexAssert(ELMSZE <= Length, "Integer type is larger than length");

			size_t prcCtr = 0;

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
			const size_t SMDBLK = 64 / ELMSZE;
#	elif defined(__AVX2__)
			const size_t SMDBLK = 32 / ELMSZE;
#	else
			const size_t SMDBLK = 16 / ELMSZE;
#	endif

			if (Length / ELMSZE >= SMDBLK)
			{
				const size_t ALNSZE = (Length / (SMDBLK * ELMSZE)) * SMDBLK;

				while (prcCtr != ALNSZE)
				{
#if defined(__AVX512__)
					SETVAL512(Output, Offset + prcCtr, Value);
#elif defined(__AVX2__)
					SETVAL256(Output, Offset + prcCtr, Value);
#elif defined(__AVX__)
					SETVAL128(Output, Offset + prcCtr, Value);
#endif
					prcCtr += SMDBLK;
				}
			}
#endif

			if (prcCtr * ELMSZE != Length)
			{
				std::memset(&Output[Offset + prcCtr], Value, Length - (prcCtr * ELMSZE));
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
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename Array>
	inline static void SETVAL128(Array &Output, size_t Offset, byte Value)
	{
		CexAssert((Output.size() - Offset) * sizeof(Array::value_type) >= 16, "Length is larger than output capacity");

#if defined(__AVX__)
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
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename Array>
	inline static void SETVAL256(Array &Output, size_t Offset, byte Value)
	{
		CexAssert((Output.size() - Offset) * sizeof(Array::value_type) >= 32, "Length is larger than output capacity");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_set1_epi8(Value));
#else
		SETVAL128(Output, Offset, Value);
		SETVAL128(Output, Offset + (16 / sizeof(Output[0])), Value);
#endif
	}

	/// <summary>
	/// Set 512 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The source integer array to modify</param>
	/// <param name="Offset">The offset within the source array</param>
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename Array>
	inline static void SETVAL512(Array &Output, size_t Offset, byte Value)
	{
		CexAssert((Output.size() - Offset) * sizeof(Array::value_type) >= 64, "Length is larger than output capacity");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_set1_epi8(Value));
#else
		SETVAL256(Output, Offset, Value);
		SETVAL256(Output, Offset + (32 / sizeof(Output[0])), Value);
#endif
	}

	/// <summary>
	/// Block XOR a specified number of 8 bit bytes to process.
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
	inline static void XorBlock(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		const size_t ELMSZE = sizeof(ArrayA::value_type);

		CexAssert((Input.size() - InOffset) * ELMSZE >= Length, "Length is larger than input capacity");
		CexAssert((Output.size() - OutOffset) * ELMSZE >= Length, "Length is larger than output capacity");
		CexAssert(Length > 0, "Length can not be zero");
		CexAssert(ELMSZE <= Length, "Integer type is larger than length");

		size_t prcCtr = 0;

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	if defined(__AVX512__)
		const size_t SMDBLK = 64 / ELMSZE;
#	elif defined(__AVX2__)
		const size_t SMDBLK = 32 / ELMSZE;
#	else
		const size_t SMDBLK = 16 / ELMSZE;
#	endif

		if (Length / ELMSZE >= SMDBLK)
		{
			const size_t ALNSZE = (Length / (SMDBLK * ELMSZE)) * SMDBLK;

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				XOR512(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX2__)
				XOR256(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX__)
				XOR128(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#endif
				prcCtr += SMDBLK;
			} 
		}
#endif

		if (prcCtr * ELMSZE != Length)
		{
			XorPartial(Input, InOffset + prcCtr, Output, OutOffset + prcCtr, Length - (prcCtr * ELMSZE));
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
		const size_t ELMSZE = sizeof(ArrayA::value_type);

		CexAssert((Input.size() - InOffset) * ELMSZE >= 16, "Length is larger than input capacity");
		CexAssert((Output.size() - OutOffset) * ELMSZE >= 16, "Length is larger than output capacity");
		CexAssert(ELMSZE <= 16, "Integer type is larger than 128 bits");

#if defined(__AVX__)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
		for (size_t i = 0; i < (16 / ELMSZE); ++i)
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
		const size_t ELMSZE = sizeof(ArrayA::value_type);

		CexAssert((Input.size() - InOffset) * ELMSZE >= 32, "Length is larger than input capacity");
		CexAssert((Output.size() - OutOffset) * ELMSZE >= 32, "Length is larger than output capacity");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
#else
		XOR128(Input, InOffset, Output, OutOffset);
		XOR128(Input, InOffset + (16 / ELMSZE), Output, OutOffset + (16 / ELMSZE));
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
		const size_t ELMSZE = sizeof(ArrayA::value_type);

		CexAssert((Input.size() - InOffset) * ELMSZE >= 64, "Length is larger than input capacity");
		CexAssert((Output.size() - OutOffset) * ELMSZE >= 64, "Length is larger than output capacity");
		CexAssert(ELMSZE <= 64, "Integer type is larger than 512 bits");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_xor_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Output[OutOffset]))));
#else
		XOR256(Input, InOffset, Output, OutOffset);
		XOR256(Input, InOffset + (32 / ELMSZE), Output, OutOffset + (32 / ELMSZE));
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
		const size_t ELMSZE = sizeof(ArrayA::value_type);

		CexAssert((Input.size() - InOffset) * ELMSZE >= 128, "Length is larger than input capacity");
		CexAssert((Output.size() - OutOffset) * ELMSZE >= 128, "Length is larger than output capacity");
		CexAssert(ELMSZE <= 128, "Integer type is larger than 1024 bits");

		XOR512(Input, InOffset, Output, OutOffset);
		XOR512(Input, InOffset + (64 / ELMSZE), Output, OutOffset + (64 / ELMSZE));
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
	inline static void XorPartial(const ArrayA &Input, size_t InOffset, ArrayB &Output, size_t OutOffset, size_t Length)
	{
		for (size_t i = 0; i < (Length / sizeof(Input[0])); ++i)
		{
			Output[OutOffset + i] ^= Input[InOffset + i];
		}
	}
};

NAMESPACE_UTILITYEND
#endif
