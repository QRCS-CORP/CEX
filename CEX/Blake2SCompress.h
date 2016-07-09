#ifndef _CEXENGINE_BLAKE2SCOMPRESS_H
#define _CEXENGINE_BLAKE2SCOMPRESS_H

#include "IntUtils.h"
#if defined(HAS_MINSSE)
#	include "Intrinsics.h"
#endif

NAMESPACE_DIGEST

class Blake2SCompress
{
public:

#if defined(HAS_MINSSE)
#	if defined(HAS_XOP)
#		define TOB(x) ((x)*4*0x01010101 + 0x03020100) 
#	endif

#	if defined(HAS_SSE4)
#		define TOF(reg) _mm_castsi128_ps((reg))
#		define TOI(reg) _mm_castps_si128((reg))
#	endif

#	if !defined(HAS_XOP)
#		if !defined(HAS_SSSE3)
#			define _mm_roti_epi32(r, c) ( \
                (8==-(c)) ? _mm_shuffle_epi8(r,r8) \
              : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
              : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )
#		else
#			define _mm_roti_epi32(r, c) _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) ))
#		endif
#	endif
#endif

	template <typename T>
	static inline void SCompress(const std::vector<uint8_t> &Input, size_t InOffset, T &State, const std::vector<uint32_t> &IV)
	{
#if defined(HAS_MINSSE)
		__m128i row1, row2, row3, row4;
		__m128i buf1, buf2, buf3, buf4;
		__m128i ff0, ff1;

#    if defined(HAS_SSE4)
		__m128i t0, t1;
#		if !defined(HAS_XOP)
			__m128i t2;
#		endif
#    endif

#    if defined(HAS_SSSE3) && !defined(HAS_XOP)
		const __m128i r8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
		const __m128i r16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
#    endif

#    if defined(HAS_SSE4)
		const __m128i m0 = _mm_loadu_si128((const __m128i*)&Input[InOffset]);
		const __m128i m1 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 16]);
		const __m128i m2 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 32]);
		const __m128i m3 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 48]);
#    else
		uint8_t* block = (uint8_t*)Input.data() + InOffset;
		const uint32_t  m0 = ((uint32_t *)block)[0];
		const uint32_t  m1 = ((uint32_t *)block)[1];
		const uint32_t  m2 = ((uint32_t *)block)[2];
		const uint32_t  m3 = ((uint32_t *)block)[3];
		const uint32_t  m4 = ((uint32_t *)block)[4];
		const uint32_t  m5 = ((uint32_t *)block)[5];
		const uint32_t  m6 = ((uint32_t *)block)[6];
		const uint32_t  m7 = ((uint32_t *)block)[7];
		const uint32_t  m8 = ((uint32_t *)block)[8];
		const uint32_t  m9 = ((uint32_t *)block)[9];
		const uint32_t m10 = ((uint32_t *)block)[10];
		const uint32_t m11 = ((uint32_t *)block)[11];
		const uint32_t m12 = ((uint32_t *)block)[12];
		const uint32_t m13 = ((uint32_t *)block)[13];
		const uint32_t m14 = ((uint32_t *)block)[14];
		const uint32_t m15 = ((uint32_t *)block)[15];
#    endif

		row1 = ff0 = _mm_loadu_si128((const __m128i*)&State.H[0]);
		row2 = ff1 = _mm_loadu_si128((const __m128i*)&State.H[4]);
		row3 = _mm_loadu_si128((const __m128i*)&IV[0]);
		std::vector<uint8_t> taf(16);
		memcpy(&taf[0], &State.T[0], 8);
		memcpy(&taf[8], &State.F[0], 8);
		row4 = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[4]), _mm_loadu_si128((const __m128i*)&taf[0]));

		// round 0
		// lm 0.1
#    if defined(HAS_XOP)
		buf1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(6), TOB(4), TOB(2), TOB(0)));
#    elif defined(HAS_SSE4)
		buf1 = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(2, 0, 2, 0)));
#    else
		buf1 = _mm_set_epi32(m6, m4, m2, m0);
#    endif
		// g1
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 0.2
#    if defined(HAS_XOP)
		buf2 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(7), TOB(5), TOB(3), TOB(1)));
#    elif defined(HAS_SSE4)
		buf2 = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(3, 1, 3, 1)));
#    else
		buf2 = _mm_set_epi32(m7, m5, m3, m1);
#    endif
		// g2
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);

		// diag
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));


		// lm 0.3
#    if defined(HAS_XOP)
		buf3 = _mm_perm_epi8(m2, m3, _mm_set_epi32(TOB(6), TOB(4), TOB(2), TOB(0)));
#    elif defined(HAS_SSE4)
		buf3 = TOI(_mm_shuffle_ps(TOF(m2), TOF(m3), _MM_SHUFFLE(2, 0, 2, 0)));
#    else
		buf3 = _mm_set_epi32(m14, m12, m10, m8);
#    endif

		// g1
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 0.4
#    if defined(HAS_XOP)
		buf4 = _mm_perm_epi8(m2, m3, _mm_set_epi32(TOB(7), TOB(5), TOB(3), TOB(1)));
#    elif defined(HAS_SSE4)
		buf4 = TOI(_mm_shuffle_ps(TOF(m2), TOF(m3), _MM_SHUFFLE(3, 1, 3, 1)));
#    else
		buf4 = _mm_set_epi32(m15, m13, m11, m9);
#    endif
		// g2
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 1
		// lm 1.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(0), TOB(5), TOB(0), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(5), TOB(2), TOB(1), TOB(6)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m1, m2, 0x0C);
		t1 = _mm_slli_si128(m3, 4);
		t2 = _mm_blend_epi16(t0, t1, 0xF0);
		buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 0, 3));
#    else
		buf1 = _mm_set_epi32(m13, m9, m4, m14);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 1.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(2), TOB(0), TOB(4), TOB(6)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(7), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(0, 0, 2, 0));
		t1 = _mm_blend_epi16(m1, m3, 0xC0);
		t2 = _mm_blend_epi16(t0, t1, 0xF0);
		buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1));
#    else
		buf2 = _mm_set_epi32(m6, m15, m8, m10);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 1.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(5), TOB(0), TOB(0), TOB(1)));
		buf3 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3), TOB(7), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_slli_si128(m1, 4);
		t1 = _mm_blend_epi16(m2, t0, 0x30);
		t2 = _mm_blend_epi16(m0, t1, 0xF0);
		buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1));
#    else
		buf3 = _mm_set_epi32(m5, m11, m0, m1);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 1.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3), TOB(7), TOB(2), TOB(0)));
		buf4 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(1), TOB(4)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m1);
		t1 = _mm_slli_si128(m3, 4);
		t2 = _mm_blend_epi16(t0, t1, 0x0C);
		buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 3, 0, 1));
#    else
		buf4 = _mm_set_epi32(m3, m7, m2, m12);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 2
		// lm 2.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(0), TOB(1), TOB(0), TOB(7)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(7), TOB(2), TOB(4), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m2, m3);
		t1 = _mm_blend_epi16(m3, m1, 0x0C);
		t2 = _mm_blend_epi16(t0, t1, 0x0F);
		buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 1, 0, 2));
#    else
		buf1 = _mm_set_epi32(m15, m5, m12, m11);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 2.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0), TOB(2), TOB(0), TOB(4)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(5), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi32(m2, m0);
		t1 = _mm_blend_epi16(t0, m0, 0xF0);
		t2 = _mm_slli_si128(m3, 8);
		buf2 = _mm_blend_epi16(t1, t2, 0xC0);
#    else
		buf2 = _mm_set_epi32(m13, m2, m0, m8);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 2.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(7), TOB(3), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(5), TOB(2), TOB(1), TOB(6)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m0, m2, 0x3C);
		t1 = _mm_srli_si128(m1, 12);
		t2 = _mm_blend_epi16(t0, t1, 0x03);
		buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 0, 3, 2));
#    else
		buf3 = _mm_set_epi32(m9, m7, m3, m10);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 2.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(4), TOB(1), TOB(6), TOB(0)));
		buf4 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(1), TOB(6)));
#    elif defined(HAS_SSE4)
		t0 = _mm_slli_si128(m3, 4);
		t1 = _mm_blend_epi16(m0, m1, 0x33);
		t2 = _mm_blend_epi16(t1, t0, 0xC0);
		buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 1, 2, 3));
#    else
		buf4 = _mm_set_epi32(m4, m1, m6, m14);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 3
		// lm 3.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(0), TOB(3), TOB(7)));
		t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(7), TOB(2), TOB(1), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(5), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m1);
		t1 = _mm_unpackhi_epi32(t0, m2);
		t2 = _mm_blend_epi16(t1, m3, 0x0C);
		buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 1, 0, 2));
#    else
		buf1 = _mm_set_epi32(m11, m13, m3, m7);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 3.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0), TOB(0), TOB(1), TOB(5)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(6), TOB(4), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_slli_si128(m2, 8);
		t1 = _mm_blend_epi16(m3, m0, 0x0C);
		t2 = _mm_blend_epi16(t1, t0, 0xC0);
		buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 0, 1, 3));
#    else
		buf2 = _mm_set_epi32(m14, m12, m1, m9);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 3.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(4), TOB(5), TOB(2)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(7), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m0, m1, 0x0F);
		t1 = _mm_blend_epi16(t0, m3, 0xC0);
		buf3 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(3, 0, 1, 2));
#    else
		buf3 = _mm_set_epi32(m15, m4, m5, m2);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 3.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(0), TOB(0), TOB(6)));
		buf4 = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(4), TOB(2), TOB(6), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi32(m0, m2);
		t1 = _mm_unpackhi_epi32(m1, m2);
		buf4 = _mm_unpacklo_epi64(t1, t0);
#    else
		buf4 = _mm_set_epi32(m8, m0, m10, m6);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 4
		// lm 4.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(2), TOB(5), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(6), TOB(2), TOB(1), TOB(5)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi64(m1, m2);
		t1 = _mm_unpackhi_epi64(m0, m2);
		t2 = _mm_blend_epi16(t0, t1, 0x33);
		buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 0, 1, 3));
#    else
		buf1 = _mm_set_epi32(m10, m2, m5, m9);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 4.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(4), TOB(7), TOB(0)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(7), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi64(m1, m3);
		t1 = _mm_unpacklo_epi64(m0, m1);
		buf2 = _mm_blend_epi16(t0, t1, 0x33);
#    else
		buf2 = _mm_set_epi32(m15, m4, m7, m0);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 4.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3), TOB(6), TOB(0), TOB(0)));
		t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3), TOB(2), TOB(7), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(1), TOB(6)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi64(m3, m1);
		t1 = _mm_unpackhi_epi64(m2, m0);
		buf3 = _mm_blend_epi16(t1, t0, 0x33);
#    else
		buf3 = _mm_set_epi32(m3, m6, m11, m14);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 4.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0), TOB(4), TOB(0), TOB(1)));
		buf4 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(5), TOB(2), TOB(4), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m0, m2, 0x03);
		t1 = _mm_slli_si128(t0, 8);
		t2 = _mm_blend_epi16(t1, m3, 0x0F);
		buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 2, 0, 3));
#    else
		buf4 = _mm_set_epi32(m13, m8, m12, m1);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 5
		// lm 5.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(0), TOB(6), TOB(2)));
		buf1 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(4), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m1);
		t1 = _mm_unpacklo_epi32(m0, m2);
		buf1 = _mm_unpacklo_epi64(t0, t1);
#    else
		buf1 = _mm_set_epi32(m8, m0, m6, m2);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 5.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(3), TOB(7), TOB(6), TOB(0)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(1), TOB(4)));
#    elif defined(HAS_SSE4)
		t0 = _mm_srli_si128(m2, 4);
		t1 = _mm_blend_epi16(m0, m3, 0x03);
		buf2 = _mm_blend_epi16(t1, t0, 0x3C);
#    else
		buf2 = _mm_set_epi32(m3, m11, m10, m12);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 5.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(1), TOB(0), TOB(7), TOB(4)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(7), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m1, m0, 0x0C);
		t1 = _mm_srli_si128(m3, 4);
		t2 = _mm_blend_epi16(t0, t1, 0x30);
		buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 2, 3, 0));
#    else
		buf3 = _mm_set_epi32(m1, m15, m7, m4);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 5.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(5), TOB(0), TOB(1), TOB(0)));
		buf4 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(6), TOB(1), TOB(5)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi64(m1, m2);
		t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0, 2, 0, 1));
		buf4 = _mm_blend_epi16(t0, t1, 0x33);
#    else
		buf4 = _mm_set_epi32(m9, m14, m5, m13);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 6
		// lm 6.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(4), TOB(0), TOB(1), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(6), TOB(1), TOB(4)));
#    elif defined(HAS_SSE4)
		t0 = _mm_slli_si128(m1, 12);
		t1 = _mm_blend_epi16(m0, m3, 0x33);
		buf1 = _mm_blend_epi16(t1, t0, 0xC0);
#    else
		buf1 = _mm_set_epi32(m4, m14, m1, m12);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 6.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(6), TOB(0), TOB(0), TOB(1)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(5), TOB(7), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m3, m2, 0x30);
		t1 = _mm_srli_si128(m1, 4);
		t2 = _mm_blend_epi16(t0, t1, 0x03);
		buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 3, 0));
#    else
		buf2 = _mm_set_epi32(m10, m13, m15, m5);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 6.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(0), TOB(6), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(4), TOB(5), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi64(m0, m2);
		t1 = _mm_srli_si128(m1, 4);
		buf3 = _mm_shuffle_epi32(_mm_blend_epi16(t0, t1, 0x0C), _MM_SHUFFLE(2, 3, 1, 0));
#    else
		buf3 = _mm_set_epi32(m8, m9, m6, m0);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 6.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(2), TOB(3), TOB(7)));
		buf4 = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(7), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m1, m2);
		t1 = _mm_unpackhi_epi64(m0, t0);
		buf4 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(3, 0, 1, 2));
#    else
		buf4 = _mm_set_epi32(m11, m2, m3, m7);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 7
		// lm 7.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3), TOB(0), TOB(7), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(4), TOB(1), TOB(5)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m1);
		t1 = _mm_blend_epi16(t0, m3, 0x0F);
		buf1 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(2, 0, 3, 1));
#    else
		buf1 = _mm_set_epi32(m3, m12, m7, m13);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 7.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(5), TOB(1), TOB(0), TOB(7)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(6), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m2, m3, 0x30);
		t1 = _mm_srli_si128(m0, 4);
		t2 = _mm_blend_epi16(t0, t1, 0x03);
		buf2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 0, 2, 3));
#    else
		buf2 = _mm_set_epi32(m9, m1, m14, m11);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 7.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(2), TOB(0), TOB(0), TOB(5)));
		t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3), TOB(4), TOB(1), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(7), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi64(m0, m3);
		t1 = _mm_unpacklo_epi64(m1, m2);
		t2 = _mm_blend_epi16(t0, t1, 0x3C);
		buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 2, 3, 1));
#    else
		buf3 = _mm_set_epi32(m2, m8, m15, m5);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 7.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(6), TOB(4), TOB(0)));
		buf4 = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(6), TOB(2), TOB(1), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpacklo_epi32(m0, m1);
		t1 = _mm_unpackhi_epi32(m1, m2);
		buf4 = _mm_unpacklo_epi64(t0, t1);
#    else
		buf4 = _mm_set_epi32(m10, m6, m4, m0);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 8
		// lm 8.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0), TOB(0), TOB(0), TOB(6)));
		t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3), TOB(7), TOB(1), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(6), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m1, m3);
		t1 = _mm_unpacklo_epi64(t0, m0);
		t2 = _mm_blend_epi16(t1, m2, 0xC0);
		buf1 = _mm_shufflehi_epi16(t2, _MM_SHUFFLE(1, 0, 3, 2));
#    else
		buf1 = _mm_set_epi32(m0, m11, m14, m6);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 8.2
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(4), TOB(3), TOB(5), TOB(0)));
		buf2 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(1), TOB(7)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m3);
		t1 = _mm_blend_epi16(m2, t0, 0xF0);
		buf2 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0, 2, 1, 3));
#    else
		buf2 = _mm_set_epi32(m8, m3, m9, m15);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 8.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(6), TOB(1), TOB(0), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3), TOB(2), TOB(5), TOB(4)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m2, m0, 0x0C);
		t1 = _mm_slli_si128(t0, 4);
		buf3 = _mm_blend_epi16(t1, m3, 0x0F);
#    else
		buf3 = _mm_set_epi32(m10, m1, m13, m12);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 8.4
#    if defined(HAS_XOP)
		buf4 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(5), TOB(4), TOB(7), TOB(2)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m1, m0, 0x30);
		buf4 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(1, 0, 3, 2));
#    else
		buf4 = _mm_set_epi32(m5, m4, m7, m2);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		// round 9
		// lm 9.1
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(1), TOB(7), TOB(0), TOB(0)));
		buf1 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3), TOB(2), TOB(4), TOB(6)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m0, m2, 0x03);
		t1 = _mm_blend_epi16(m1, m2, 0x30);
		t2 = _mm_blend_epi16(t1, t0, 0x0F);
		buf1 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1, 3, 0, 2));
#    else
		buf1 = _mm_set_epi32(m1, m7, m8, m10);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf1), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 9.2
#    if defined(HAS_XOP)
		buf2 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(5), TOB(6), TOB(4), TOB(2)));
#    elif defined(HAS_SSE4)
		t0 = _mm_slli_si128(m0, 4);
		t1 = _mm_blend_epi16(m1, t0, 0xC0);
		buf2 = _mm_shuffle_epi32(t1, _MM_SHUFFLE(1, 2, 0, 3));
#    else
		buf2 = _mm_set_epi32(m5, m6, m4, m2);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf2), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(2, 1, 0, 3));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(0, 3, 2, 1));

		// lm 9.3
#    if defined(HAS_XOP)
		t0 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0), TOB(3), TOB(5), TOB(0)));
		buf3 = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(5), TOB(2), TOB(1), TOB(7)));
#    elif defined(HAS_SSE4)
		t0 = _mm_unpackhi_epi32(m0, m3);
		t1 = _mm_unpacklo_epi32(m2, m3);
		t2 = _mm_unpackhi_epi64(t0, t1);
		buf3 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3, 0, 2, 1));
#    else
		buf3 = _mm_set_epi32(m13, m3, m9, m15);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf3), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -16);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -12);

		// lm 9.4
#    if defined(HAS_XOP)
		t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0), TOB(0), TOB(0), TOB(7)));
		buf4 = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3), TOB(4), TOB(6), TOB(0)));
#    elif defined(HAS_SSE4)
		t0 = _mm_blend_epi16(m3, m2, 0xC0);
		t1 = _mm_unpacklo_epi32(m0, m3);
		t2 = _mm_blend_epi16(t0, t1, 0x0F);
		buf4 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0, 1, 2, 3));
#    else
		buf4 = _mm_set_epi32(m0, m12, m14, m11);
#    endif
		row1 = _mm_add_epi32(_mm_add_epi32(row1, buf4), row2);
		row4 = _mm_xor_si128(row4, row1);
		row4 = _mm_roti_epi32(row4, -8);
		row3 = _mm_add_epi32(row3, row4);
		row2 = _mm_xor_si128(row2, row3);
		row2 = _mm_roti_epi32(row2, -7);
		row4 = _mm_shuffle_epi32(row4, _MM_SHUFFLE(0, 3, 2, 1));
		row3 = _mm_shuffle_epi32(row3, _MM_SHUFFLE(1, 0, 3, 2));
		row2 = _mm_shuffle_epi32(row2, _MM_SHUFFLE(2, 1, 0, 3));


		_mm_storeu_si128((__m128i*)&State.H[0], _mm_xor_si128(ff0, _mm_xor_si128(row1, row3)));
		_mm_storeu_si128((__m128i*)&State.H[4], _mm_xor_si128(ff1, _mm_xor_si128(row2, row4)));
#    else
		UCompress(Input, InOffset, State, IV);
#endif
	}

	template <typename T>
	static inline void UCompress(const std::vector<uint8_t> &Input, size_t InOffset, T &State, const std::vector<uint32_t> &IV)
	{
		std::vector<uint32_t> msg(16);
		CEX::Utility::IntUtils::BytesToLeUL512(Input, InOffset, msg, 0);

		uint32_t v0 = State.H[0];
		uint32_t v1 = State.H[1];
		uint32_t v2 = State.H[2];
		uint32_t v3 = State.H[3];
		uint32_t v4 = State.H[4];
		uint32_t v5 = State.H[5];
		uint32_t v6 = State.H[6];
		uint32_t v7 = State.H[7];
		uint32_t v8 = IV[0];
		uint32_t v9 = IV[1];
		uint32_t v10 = IV[2];
		uint32_t v11 = IV[3];
		uint32_t v12 = IV[4] ^ State.T[0];
		uint32_t v13 = IV[5] ^ State.T[1];
		uint32_t v14 = IV[6] ^ State.F[0];
		uint32_t v15 = IV[7] ^ State.F[1];

		// round 0
		v0 += v4 + msg[0];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[1];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[2];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[3];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[4];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[5];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[7];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[8];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[9];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[10];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[11];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[12];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[13];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[14];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[15];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 1
		v0 += v4 + msg[14];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[10];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[4];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[8];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[9];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[15];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[13];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[1];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[12];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[0];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[2];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[11];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[7];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[5];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[3];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 2
		v0 += v4 + msg[11];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[8];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[12];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[0];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[5];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[2];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[15];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[13];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[10];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[14];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[3];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[6];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[7];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[1];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[9];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[4];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 3
		v0 += v4 + msg[7];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[9];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[3];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[1];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[13];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[12];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[11];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[14];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[2];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[6];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[5];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[10];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[4];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[0];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[15];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[8];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 4
		v0 += v4 + msg[9];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[0];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[5];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[7];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[2];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[4];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[10];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[15];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[14];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[1];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[11];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[12];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[6];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[8];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[3];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[13];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 5
		v0 += v4 + msg[2];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[12];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[6];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[10];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[0];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[11];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[8];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[3];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[4];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[13];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[7];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[5];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[15];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[14];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[1];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[9];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 6
		v0 += v4 + msg[12];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[5];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[1];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[15];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[14];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[13];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[4];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[10];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[0];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[7];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[6];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[3];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[9];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[2];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[8];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[11];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 7
		v0 += v4 + msg[13];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[11];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[7];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[14];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[12];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[1];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[3];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[9];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[5];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[0];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[15];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[4];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[8];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[6];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[2];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[10];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 8
		v0 += v4 + msg[6];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[15];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[14];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[9];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[11];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[3];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[0];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[8];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[12];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[2];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[13];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[7];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[1];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[4];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[10];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[5];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		// round 9
		v0 += v4 + msg[10];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v0 += v4 + msg[2];
		v12 ^= v0;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		v1 += v5 + msg[8];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v1 += v5 + msg[4];
		v13 ^= v1;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v2 += v6 + msg[7];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v2 += v6 + msg[6];
		v14 ^= v2;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v3 += v7 + msg[1];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v3 += v7 + msg[5];
		v15 ^= v3;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v0 += v5 + msg[15];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (32 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 12) | (v5 << (32 - 12)));
		v0 += v5 + msg[11];
		v15 ^= v0;
		v15 = ((v15 >> 8) | (v15 << (32 - 8)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 7) | (v5 << (32 - 7)));

		v1 += v6 + msg[9];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (32 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 12) | (v6 << (32 - 12)));
		v1 += v6 + msg[14];
		v12 ^= v1;
		v12 = ((v12 >> 8) | (v12 << (32 - 8)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 7) | (v6 << (32 - 7)));

		v2 += v7 + msg[3];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (32 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 12) | (v7 << (32 - 12)));
		v2 += v7 + msg[12];
		v13 ^= v2;
		v13 = ((v13 >> 8) | (v13 << (32 - 8)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 7) | (v7 << (32 - 7)));

		v3 += v4 + msg[13];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (32 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 12) | (v4 << (32 - 12)));
		v3 += v4 + msg[0];
		v14 ^= v3;
		v14 = ((v14 >> 8) | (v14 << (32 - 8)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 7) | (v4 << (32 - 7)));

		State.H[0] ^= v0 ^ v8;
		State.H[1] ^= v1 ^ v9;
		State.H[2] ^= v2 ^ v10;
		State.H[3] ^= v3 ^ v11;
		State.H[4] ^= v4 ^ v12;
		State.H[5] ^= v5 ^ v13;
		State.H[6] ^= v6 ^ v14;
		State.H[7] ^= v7 ^ v15;
	}
};

NAMESPACE_DIGESTEND
#endif