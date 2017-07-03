#ifndef _CEX_MEMUTILS_H
#define _CEX_MEMUTILS_H

#include "CexDomain.h"
#if defined(__AVX__)
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
	/// Clear bytes from a type T integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Clear.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64/128=AVX512), the operation is vectorized, otherwise this is a sequential clear operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination type T array to clear</param>
	/// <param name="Offset">The offset T within the destination array</param>
	/// <param name="Length">The number of bytes to clear</param>
	template <typename T>
	static void Clear(std::vector<T> &Output, size_t Offset, size_t Length)
	{
		if (Length == 0)
			return;

		CEXASSERT((Output.size() - Offset) * sizeof(T) >= Length, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= Length, "Integer type is larger than length");

		size_t prcCtr = 0;

#if defined(__AVX__)
#	if defined(__AVX512__)
		const size_t SMDBLK = 64 / sizeof(T);
#	elif defined(__AVX2__)
		const size_t SMDBLK = 32 / sizeof(T);
#	else
		const size_t SMDBLK = 16 / sizeof(T);
#	endif

		if (Length / sizeof(T) >= SMDBLK)
		{
			const size_t ALNSZE = (Length / (SMDBLK * sizeof(T))) * SMDBLK;

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				CLEAR512<T>(Output, Offset + prcCtr);
#elif defined(__AVX2__)
				CLEAR256<T>(Output, Offset + prcCtr);
#elif defined(__AVX__)
				CLEAR128<T>(Output, Offset + prcCtr);
#endif
				prcCtr += SMDBLK;
			}
		}
#endif

		if (prcCtr * sizeof(T) != Length)
			std::memset(&Output[Offset + prcCtr], (byte)0x0, Length - (prcCtr * sizeof(T)));
	}

	/// <summary>
	/// Clear 128 bits in a type T integer array.
	/// <para>This is an AVX vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset T within the destination array</param>
	template <typename T>
	inline static void CLEAR128(std::vector<T> &Output, size_t Offset)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 16, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 16, "Integer type is larger than 128 bits");

#if defined(__AVX__)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[Offset]), _mm_setzero_si128());
#else
		std::memset(&Output[Offset], (byte)0, 16);
#endif
	}

	/// <summary>
	/// Clear 256 bits in a type T integer array.
	/// <para>This is an AVX/AVX2 vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset T within the destination array</param>
	template <typename T>
	inline static void CLEAR256(std::vector<T> &Output, size_t Offset)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 32, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 32, "Integer type is larger than 256 bits");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_setzero_si256());
#else
		CLEAR128(Output, Offset);
		CLEAR128(Output, Offset + (16 / sizeof(T)));
#endif
	}

	/// <summary>
	/// Clear 512 bits in a type T integer array.
	/// <para>This is an AVX/AVX2/AVX512 vectorized function.</para>
	/// </summary>
	/// 
	/// <param name="Output">The destination array to clear</param>
	/// <param name="Offset">The offset T within the destination array</param>
	template <typename T>
	inline static void CLEAR512(std::vector<T> &Output, size_t Offset)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 64, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 64, "Integer type is larger than 512 bits");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_setzero_si512());
#else
		CLEAR256(Output, Offset);
		CLEAR256(Output, Offset + (32 / sizeof(T)));
#endif
	}

	/// <summary>
	/// Compare two type T arrays for equality.
	/// <para>This is a constant time (not vectorized) function.</para>
	/// </summary>
	/// 
	/// <param name="A">The first type T array</param>
	/// <param name="AOffset">The offset T within the first array</param>
	/// <param name="B">The second type T array</param>
	/// <param name="BOffset">The offset T within the second array</param>
	/// <param name="Length">The number of integers to compare</param>
	template<typename T>
	static bool Compare(const std::vector<T> &A, size_t AOffset, const std::vector<T> &B, size_t BOffset, size_t Length)
	{
		CEXASSERT((A.size() - AOffset) >= Length, "Length is larger than A capacity");
		CEXASSERT((B.size() - BOffset) >= Length, "Length is larger than B capacity");

		T diff = 0;

		for (size_t i = 0; i != Length; ++i)
			diff |= (A[AOffset + i] ^ B[BOffset + i]);

		return diff == 0;
	}

	/// <summary>
	/// Copy bytes from an array to an integer.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer (V) type byte size.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Value">The destination value</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename A, typename V>
	static void Copy(const std::vector<A> &Input, size_t InOffset, V &Value, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= Length, "Length is larger than input capacity");
		CEXASSERT(Length <= sizeof(V), "Length is larger than value");

		std::memcpy(&Value, &Input[InOffset], Length);
	}

	/// <summary>
	/// Copy bytes from an integer to an array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// The length must not be larger than the integer (V) type byte size.</para>
	/// </summary>
	/// 
	/// <param name="Value">The source integer value</param>
	/// <param name="Output">The type A destination array</param>
	/// <param name="OutOffset">The offset A within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename V, typename A>
	inline static void Copy(const V &Value, std::vector<A> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Output.size() - OutOffset) * sizeof(A) >= Length, "Length is larger than input capacity");
		CEXASSERT(Length <= sizeof(V), "Length is larger than value");

		std::memcpy(&Output[OutOffset], &Value, Length);
	}

	/// <summary>
	/// Copy an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename T>
	inline static void Copy(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Length)
	{
		if (Length == 0)
			return;

		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= Length, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 16, "Integer type is larger than 128 bits");

		size_t prcCtr = 0;

#if defined(__AVX__)
#	if defined(__AVX512__)
		const size_t SMDBLK = 64 / sizeof(T);
#	elif defined(__AVX2__)
		const size_t SMDBLK = 32 / sizeof(T);
#	else
		const size_t SMDBLK = 16 / sizeof(T);
#	endif

		if (Length / sizeof(T) >= SMDBLK)
		{
			const size_t ALNSZE = (Length / (SMDBLK * sizeof(T))) * SMDBLK;

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				COPY512<T, T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX2__)
				COPY256<T, T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX__)
				COPY128<T, T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#endif
				prcCtr += SMDBLK;
			}
		}
#endif

		if (prcCtr * sizeof(T) != Length)
			std::memcpy(&Output[OutOffset + prcCtr], &Input[InOffset + prcCtr], Length - (prcCtr * sizeof(T)));
	}

	/// <summary>
	/// Copy an integer array.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Copy.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	/// <param name="Length">The number of bytes to copy</param>
	template <typename A, typename B>
	inline static void Copy(const std::vector<A> &Input, size_t InOffset, std::vector<B> &Output, size_t OutOffset, size_t Length)
	{
		if (Length == 0)
			return;

		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(B) >= Length, "Length is larger than output capacity");
		CEXASSERT(sizeof(A) <= 16 && sizeof(B) <= 16, "Integer type is larger than 128 bits");

#if defined(__AVX512__)
		const size_t SMDBLK = 64;
#elif defined(__AVX2__)
		const size_t SMDBLK = 32;
#elif defined(__AVX__)
		const size_t SMDBLK = 16;
#endif

		size_t prcCtr = 0;

#if defined(__AVX__)
		if (Length >= SMDBLK)
		{
			const size_t ALNSZE = Length - (Length % SMDBLK);

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				COPY512<A, B>(Input, InOffset + (prcCtr / sizeof(A)), Output, OutOffset + (prcCtr / sizeof(B)));
#elif defined(__AVX2__)
				COPY256<A, B>(Input, InOffset + (prcCtr / sizeof(A)), Output, OutOffset + (prcCtr / sizeof(B)));
#elif defined(__AVX__)
				COPY128<A, B>(Input, InOffset + (prcCtr / sizeof(A)), Output, OutOffset + (prcCtr / sizeof(B)));
#endif
				prcCtr += SMDBLK;
			}
		}
#endif

		if (prcCtr != Length)
			std::memcpy(&Output[OutOffset + (prcCtr / sizeof(B))], &Input[InOffset + (prcCtr / sizeof(A))], Length - prcCtr);
	}

	/// <summary>
	/// Copy 128 bits between integer arrays.
	/// <para>This is an AVX vectorized copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	template <typename A, typename B>
	inline static void COPY128(const std::vector<A> &Input, size_t InOffset, std::vector<B> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= 16, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(B) >= 16, "Length is larger than output capacity");
		CEXASSERT(sizeof(A) <= 16 && sizeof(B) <= 16, "Integer type is larger than 128 bits");

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
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	template <typename A, typename B>
	inline static void COPY256(const std::vector<A> &Input, size_t InOffset, std::vector<B> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= 32, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(B) >= 32, "Length is larger than output capacity");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])));
#else
		COPY128<A, B>(Input, InOffset, Output, OutOffset);
		COPY128<A, B>(Input, InOffset + (16 / sizeof(A)), Output, OutOffset + (16 / sizeof(B)));
#endif
	}

	/// <summary>
	/// Copy 512 bits between integer arrays.
	/// <para>This is an AVX512/AVX2/AVX vectorized copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	template <typename A, typename B>
	inline static void COPY512(const std::vector<A> &Input, size_t InOffset, std::vector<B> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= 64, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(B) >= 64, "Length is larger than output capacity");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])));
#else
		COPY256<A, B>(Input, InOffset, Output, OutOffset);
		COPY256<A, B>(Input, InOffset + (32 / sizeof(A)), Output, OutOffset + (32 / sizeof(B)));
#endif
	}

	/// <summary>
	/// Move an integer array.
	/// <para>This is a sequential move operation.
	/// The Length is the number of *bytes* (8 bit integers) to Move.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type A source array to copy</param>
	/// <param name="InOffset">The offset A within the source array</param>
	/// <param name="Output">The type B destination array</param>
	/// <param name="OutOffset">The offset B within the destination array</param>
	/// <param name="Length">The number of bytes to clear</param>
	template <typename A, typename B>
	inline static void Move(const std::vector<A> &Input, size_t InOffset, std::vector<B> &Output, size_t OutOffset, size_t Length)
	{
		if (Length == 0)
			return;

		CEXASSERT((Input.size() - InOffset) * sizeof(A) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(B) >= Length, "Length is larger than output capacity");

		std::memmove(&Output[OutOffset], &Input[InOffset], Length);
	}

	/// <summary>
	/// Set memory to a fixed value.
	/// <para>The Length is the number of *bytes* (8 bit integers) to Set.
	/// If length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), the operation is vectorized, otherwise this is a sequential copy operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The type T source array to modify</param>
	/// <param name="Offset">The offset T within the source array</param>
	/// <param name="Length">The number of bytes to change</param>
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename T>
	static void SetValue(std::vector<T> &Output, size_t Offset, size_t Length, byte Value)
	{
		if (Length == 0)
			return;

		CEXASSERT((Output.size() - Offset) * sizeof(T) >= Length, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= Length, "Integer type is larger than length");

		size_t prcCtr = 0;

#if defined(__AVX__)
#	if defined(__AVX512__)
		const size_t SMDBLK = 64 / sizeof(T);
#	elif defined(__AVX2__)
		const size_t SMDBLK = 32 / sizeof(T);
#	else
		const size_t SMDBLK = 16 / sizeof(T);
#	endif

		if (Length / sizeof(T) >= SMDBLK)
		{
			const size_t ALNSZE = (Length / (SMDBLK * sizeof(T))) * SMDBLK;

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				SETVAL512<T>(Output, Offset + prcCtr, Value);
#elif defined(__AVX2__)
				SETVAL256<T>(Output, Offset + prcCtr, Value);
#elif defined(__AVX__)
				SETVAL128<T>(Output, Offset + prcCtr, Value);
#endif
				prcCtr += SMDBLK;
			}
		}
#endif

		if (prcCtr * sizeof(T) != Length)
			std::memset(&Output[Offset + prcCtr], Value, Length - (prcCtr * sizeof(T)));
	}

	/// <summary>
	/// Set 128 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The type T source array to modify</param>
	/// <param name="Offset">The offset T within the source array</param>
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename T>
	inline static void SETVAL128(std::vector<T> &Output, size_t Offset, byte Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 16, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 16, "Integer type is larger than 128 bits");

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
	/// <param name="Output">The type T source array to modify</param>
	/// <param name="Offset">The offset T within the source array</param>
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename T>
	inline static void SETVAL256(std::vector<T> &Output, size_t Offset, byte Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 32, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 32, "Integer type is larger than 256 bits");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), _mm256_set1_epi8(Value));
#else
		SETVAL128(Output, Offset, Value);
		SETVAL128(Output, Offset + (16 / sizeof(T)), Value);
#endif
	}

	/// <summary>
	/// Set 512 bits of memory to a fixed value.
	/// <para>This is a sequential memset operation.</para>
	/// </summary>
	/// 
	/// <param name="Output">The type T source array to modify</param>
	/// <param name="Offset">The offset T within the source array</param>
	/// <param name="Value">The 8 bit byte value to set</param>
	template <typename T>
	inline static void SETVAL512(std::vector<T> &Output, size_t Offset, byte Value)
	{
		CEXASSERT((Output.size() - Offset) * sizeof(T) >= 64, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 64, "Integer type is larger than 512 bits");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[Offset]), _mm512_set1_epi8(Value));
#else
		SETVAL256(Output, Offset, Value);
		SETVAL256(Output, Offset + (32 / sizeof(T)), Value);
#endif
	}

	/// <summary>
	/// Block XOR a specified number of 8 bit bytes to process.
	/// <para>The Length is the number of *bytes* (8 bit integers) to XOR.
	/// If the length is at least the size of an intrinsics integer boundary: (16=AVX, 32=AVX2, 64=AVX512), the operation is vectorized, otherwise this is a sequential XOR operation.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The T sized offset within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The sized T offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename T>
	static void XorBlock(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Length)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= Length, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= Length, "Length is larger than output capacity");
		CEXASSERT(Length > 0, "Length can not be zero");
		CEXASSERT(sizeof(T) <= Length, "Integer type is larger than length");

		size_t prcCtr = 0;

#if defined(__AVX__)
#	if defined(__AVX512__)
		const size_t SMDBLK = 64 / sizeof(T);
#	elif defined(__AVX2__)
		const size_t SMDBLK = 32 / sizeof(T);
#	else
		const size_t SMDBLK = 16 / sizeof(T);
#	endif

		if (Length / sizeof(T) >= SMDBLK)
		{
			const size_t ALNSZE = (Length / (SMDBLK * sizeof(T))) * SMDBLK;

			while (prcCtr != ALNSZE)
			{
#if defined(__AVX512__)
				XOR512<T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX2__)
				XOR256<T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#elif defined(__AVX__)
				XOR128<T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr);
#endif
				prcCtr += SMDBLK;
			} 
		}
#endif

		if (prcCtr * sizeof(T) != Length)
			XorPartial<T>(Input, InOffset + prcCtr, Output, OutOffset + prcCtr, Length - (prcCtr * sizeof(T)));
	}

	/// <summary>
	/// Block XOR 128 bits
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The T sized offset within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The sized T offset within the destination array</param>
	template <typename T>
	inline static void XOR128(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= 16, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= 16, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 16, "Integer type is larger than 128 bits");

#if defined(__AVX__)
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
#else
		for (size_t i = 0; i < (16 / sizeof(T)); ++i)
			Output[OutOffset + i] ^= Input[InOffset + i];
#endif
	}

	/// <summary>
	/// Block XOR 256 bits
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The offset T within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The offset T within the destination array</param>
	template <typename T>
	inline static void XOR256(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= 32, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= 32, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 32, "Integer type is larger than 256 bits");

#if defined(__AVX2__)
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
#else
		XOR128(Input, InOffset, Output, OutOffset);
		XOR128(Input, InOffset + (16 / sizeof(T)), Output, OutOffset + (16 / sizeof(T)));
#endif
	}

	/// <summary>
	/// Block XOR 512 bits
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The offset T within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The offset T within the destination array</param>
	template <typename T>
	inline static void XOR512(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= 64, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= 64, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 64, "Integer type is larger than 512 bits");

#if defined(__AVX512__)
		_mm512_storeu_si512(reinterpret_cast<__m512i*>(&Output[OutOffset]), _mm512_xor_si512(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Input[InOffset])), _mm512_loadu_si512(reinterpret_cast<const __m512i*>(&Output[OutOffset]))));
#else
		XOR256(Input, InOffset, Output, OutOffset);
		XOR256(Input, InOffset + (32 / sizeof(T)), Output, OutOffset + (32 / sizeof(T)));
#endif
	}

	/// <summary>
	/// Block XOR 1024 bits
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The offset T within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The offset T within the destination array</param>
	template <typename T>
	inline static void XOR1024(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
		CEXASSERT((Input.size() - InOffset) * sizeof(T) >= 128, "Length is larger than input capacity");
		CEXASSERT((Output.size() - OutOffset) * sizeof(T) >= 128, "Length is larger than output capacity");
		CEXASSERT(sizeof(T) <= 128, "Integer type is larger than 1024 bits");

		XOR512(Input, InOffset, Output, OutOffset);
		XOR512(Input, InOffset + (64 / sizeof(T)), Output, OutOffset + (64 / sizeof(T)));
	}

	/// <summary>
	/// Block XOR unaligned bit blocks less than 16 / T.
	/// <para>The Length must be the size in bytes (8 bit integers) to XOR.</para>
	/// </summary>
	/// 
	/// <param name="Input">The type T source array</param>
	/// <param name="InOffset">The T sized offset within the source array</param>
	/// <param name="Output">The type T destination array</param>
	/// <param name="OutOffset">The sized T offset within the destination array</param>
	/// <param name="Length">The number of bytes to process</param>
	template <typename T>
	inline static void XorPartial(const std::vector<T> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset, size_t Length)
	{
		for (size_t i = 0; i < (Length / sizeof(T)); ++i)
			Output[OutOffset + i] ^= Input[InOffset + i];
	}
};

NAMESPACE_UTILITYEND
#endif