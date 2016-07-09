#ifndef _CEXENGINE_INTRINSICMATH_H
#define _CEXENGINE_INTRINSICMATH_H

#include "Common.h"
#if defined(HAS_MINSSE)
#	include "Intrinsics.h"
#endif
NAMESPACE_UTILITY

// not completed yet; borrowed from Botans simd_sse2.h as a reference
typedef struct Int128
{
#if defined(HAS_MINSSE)
private:
	__m128i m_register;

	explicit Int128(__m128i in) { m_register = in; }

public:
	explicit Int128(const uint B[4])
	{
		m_register = _mm_loadu_si128(reinterpret_cast<const __m128i*>(B));
	}

	Int128(uint B0, uint B1, uint B2, uint B3)
	{
		m_register = _mm_set_epi32(B0, B1, B2, B3);
	}

	explicit Int128(uint B)
	{
		m_register = _mm_set1_epi32(B);
	}

	static Int128 load_le(const void* Input)
	{
		return Int128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(Input)));
	}

	static Int128 load_be(const void* Input)
	{
		return load_le(Input).bswap();
	}

	void store_le(byte Output[]) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(Output), m_register);
	}

	void store_be(byte Output[]) const
	{
		bswap().store_le(Output);
	}

	void rotate_left32(size_t Shift)
	{
		m_register = _mm_or_si128(_mm_slli_epi32(m_register, static_cast<int>(Shift)), _mm_srli_epi32(m_register, static_cast<int>(32 - Shift)));
	}

	void rotate_right32(size_t Shift)
	{
		rotate_left32(32 - Shift);
	}

	void operator+=(const Int128& Obj)
	{
		m_register = _mm_add_epi32(m_register, Obj.m_register);
	}

	Int128 operator+(const Int128& Obj) const
	{
		return Int128(_mm_add_epi32(m_register, Obj.m_register));
	}

	void operator-=(const Int128& Obj)
	{
		m_register = _mm_sub_epi32(m_register, Obj.m_register);
	}

	Int128 operator-(const Int128& Obj) const
	{
		return Int128(_mm_sub_epi32(m_register, Obj.m_register));
	}

	void operator^=(const Int128& Obj)
	{
		m_register = _mm_xor_si128(m_register, Obj.m_register);
	}

	Int128 operator^(const Int128& Obj) const
	{
		return Int128(_mm_xor_si128(m_register, Obj.m_register));
	}

	void operator|=(const Int128& Obj)
	{
		m_register = _mm_or_si128(m_register, Obj.m_register);
	}

	Int128 operator&(const Int128& Obj)
	{
		return Int128(_mm_and_si128(m_register, Obj.m_register));
	}

	void operator&=(const Int128& Obj)
	{
		m_register = _mm_and_si128(m_register, Obj.m_register);
	}

	Int128 operator<<(size_t shift) const
	{
		return Int128(_mm_slli_epi32(m_register, static_cast<int>(shift)));
	}

	Int128 operator >> (size_t shift) const
	{
		return Int128(_mm_srli_epi32(m_register, static_cast<int>(shift)));
	}

	Int128 operator~() const
	{
		return Int128(_mm_xor_si128(m_register, _mm_set1_epi32(0xFFFFFFFF)));
	}

	// (~reg) & Obj
	Int128 andc(const Int128& Obj)
	{
		return Int128(_mm_andnot_si128(m_register, Obj.m_register));
	}

	Int128 bswap() const
	{
		__m128i T = m_register;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return Int128(_mm_or_si128(_mm_srli_epi16(T, 8),
			_mm_slli_epi16(T, 8)));
	}

	static void transpose(Int128& B0, Int128& B1, Int128& B2, Int128& B3)
	{
		__m128i T0 = _mm_unpacklo_epi32(B0.m_register, B1.m_register);
		__m128i T1 = _mm_unpacklo_epi32(B2.m_register, B3.m_register);
		__m128i T2 = _mm_unpackhi_epi32(B0.m_register, B1.m_register);
		__m128i T3 = _mm_unpackhi_epi32(B2.m_register, B3.m_register);
		B0.m_register = _mm_unpacklo_epi64(T0, T1);
		B1.m_register = _mm_unpackhi_epi64(T0, T1);
		B2.m_register = _mm_unpacklo_epi64(T2, T3);
		B3.m_register = _mm_unpackhi_epi64(T2, T3);
	}
#else
#
#endif
};

NAMESPACE_UTILITYEND
#endif