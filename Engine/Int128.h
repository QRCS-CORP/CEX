#ifndef _CEXENGINE_INTRINSICMATH_H
#define _CEXENGINE_INTRINSICMATH_H

#include "Common.h"

#if defined(INTEL_INTRINSICS)
#include <emmintrin.h>

NAMESPACE_UTILITY

// not completed yet; borrowed from Botans simd_sse2.h as a reference
class Int128
{
public:
	explicit Int128(const uint B[4])
	{
		m_reg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(B));
	}

	Int128(uint B0, uint B1, uint B2, uint B3)
	{
		m_reg = _mm_set_epi32(B0, B1, B2, B3);
	}

	explicit Int128(uint B)
	{
		m_reg = _mm_set1_epi32(B);
	}

	static Int128 load_le(const void* in)
	{
		return Int128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
	}

	static Int128 load_be(const void* in)
	{
		return load_le(in).bswap();
	}

	void store_le(byte out[]) const
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_reg);
	}

	void store_be(byte out[]) const
	{
		bswap().store_le(out);
	}

	void rotate_left(size_t rot)
	{
		m_reg = _mm_or_si128(_mm_slli_epi32(m_reg, static_cast<int>(rot)),
			_mm_srli_epi32(m_reg, static_cast<int>(32 - rot)));
	}

	void rotate_right(size_t rot)
	{
		rotate_left(32 - rot);
	}

	void operator+=(const Int128& other)
	{
		m_reg = _mm_add_epi32(m_reg, other.m_reg);
	}

	Int128 operator+(const Int128& other) const
	{
		return Int128(_mm_add_epi32(m_reg, other.m_reg));
	}

	void operator-=(const Int128& other)
	{
		m_reg = _mm_sub_epi32(m_reg, other.m_reg);
	}

	Int128 operator-(const Int128& other) const
	{
		return Int128(_mm_sub_epi32(m_reg, other.m_reg));
	}

	void operator^=(const Int128& other)
	{
		m_reg = _mm_xor_si128(m_reg, other.m_reg);
	}

	Int128 operator^(const Int128& other) const
	{
		return Int128(_mm_xor_si128(m_reg, other.m_reg));
	}

	void operator|=(const Int128& other)
	{
		m_reg = _mm_or_si128(m_reg, other.m_reg);
	}

	Int128 operator&(const Int128& other)
	{
		return Int128(_mm_and_si128(m_reg, other.m_reg));
	}

	void operator&=(const Int128& other)
	{
		m_reg = _mm_and_si128(m_reg, other.m_reg);
	}

	Int128 operator<<(size_t shift) const
	{
		return Int128(_mm_slli_epi32(m_reg, static_cast<int>(shift)));
	}

	Int128 operator >> (size_t shift) const
	{
		return Int128(_mm_srli_epi32(m_reg, static_cast<int>(shift)));
	}

	Int128 operator~() const
	{
		return Int128(_mm_xor_si128(m_reg, _mm_set1_epi32(0xFFFFFFFF)));
	}

	// (~reg) & other
	Int128 andc(const Int128& other)
	{
		return Int128(_mm_andnot_si128(m_reg, other.m_reg));
	}

	Int128 bswap() const
	{
		__m128i T = m_reg;

		T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
		T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

		return Int128(_mm_or_si128(_mm_srli_epi16(T, 8),
			_mm_slli_epi16(T, 8)));
	}

	static void transpose(Int128& B0, Int128& B1,
		Int128& B2, Int128& B3)
	{
		__m128i T0 = _mm_unpacklo_epi32(B0.m_reg, B1.m_reg);
		__m128i T1 = _mm_unpacklo_epi32(B2.m_reg, B3.m_reg);
		__m128i T2 = _mm_unpackhi_epi32(B0.m_reg, B1.m_reg);
		__m128i T3 = _mm_unpackhi_epi32(B2.m_reg, B3.m_reg);
		B0.m_reg = _mm_unpacklo_epi64(T0, T1);
		B1.m_reg = _mm_unpackhi_epi64(T0, T1);
		B2.m_reg = _mm_unpacklo_epi64(T2, T3);
		B3.m_reg = _mm_unpackhi_epi64(T2, T3);
	}

private:
	__m128i m_reg;

	explicit Int128(__m128i in) { m_reg = in; }
};

NAMESPACE_UTILITYEND
#endif
#endif