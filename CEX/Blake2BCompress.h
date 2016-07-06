#ifndef _CEXENGINE_BLAKE2BCOMPRESS_H
#define _CEXENGINE_BLAKE2BCOMPRESS_H

#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

class Blake2BCompress
{
public:

#if defined(HAS_ADVINTRIN)
#	if !defined(HAS_XOP)
#		if defined(HAS_SSSE3)
#			define _mm_roti_epi64(x, c) \
					(-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
					: (-(c) == 24) ? _mm_shuffle_epi8((x), r24) \
					: (-(c) == 16) ? _mm_shuffle_epi8((x), r16) \
					: (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
					: _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))
#		else
#			define _mm_roti_epi64(r, c) _mm_xor_si128(_mm_srli_epi64( (r), -(c) ),_mm_slli_epi64( (r), 64-(-(c)) ))
#		endif
#	endif

#	if defined(HAS_SSSE3)
#		define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
			  t0 = _mm_alignr_epi8(row2h, row2l, 8); \
			  t1 = _mm_alignr_epi8(row2l, row2h, 8); \
			  row2l = t0; \
			  row2h = t1; \
			  \
			  t0 = row3l; \
			  row3l = row3h; \
			  row3h = t0;    \
			  \
			  t0 = _mm_alignr_epi8(row4h, row4l, 8); \
			  t1 = _mm_alignr_epi8(row4l, row4h, 8); \
			  row4l = t1; \
			  row4h = t0;

#		define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
			  t0 = _mm_alignr_epi8(row2l, row2h, 8); \
			  t1 = _mm_alignr_epi8(row2h, row2l, 8); \
			  row2l = t0; \
			  row2h = t1; \
			  \
			  t0 = row3l; \
			  row3l = row3h; \
			  row3h = t0; \
			  \
			  t0 = _mm_alignr_epi8(row4l, row4h, 8); \
			  t1 = _mm_alignr_epi8(row4h, row4l, 8); \
			  row4l = t1; \
			  row4h = t0;
#	else
#		define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
			  t0 = row4l;\
			  t1 = row2l;\
			  row4l = row3l;\
			  row3l = row3h;\
			  row3h = row4l;\
			  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0)); \
			  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h)); \
			  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h)); \
			  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1))

#		define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
			  t0 = row3l;\
			  row3l = row3h;\
			  row3h = t0;\
			  t0 = row2l;\
			  t1 = row4l;\
			  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l)); \
			  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h)); \
			  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h)); \
			  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1))
#	endif
	template <typename T>
	static inline void Compress(const std::vector<uint8_t> &Input, size_t InOffset, T &State, const std::vector<uint64_t> &IV)
	{
#if defined(HAS_SSE4)
		const __m128i m0 = _mm_loadu_si128((const __m128i*)&Input[InOffset]);
		const __m128i m1 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 16]);
		const __m128i m2 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 32]);
		const __m128i m3 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 48]);
		const __m128i m4 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 64]);
		const __m128i m5 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 80]);
		const __m128i m6 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 96]);
		const __m128i m7 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 112]);
#else
		uint8_t* block = (uint8_t*)Input.data() + InOffset;
		const uint64_t m0 = ((uint64_t*)block)[0];
		const uint64_t m1 = ((uint64_t*)block)[1];
		const uint64_t m2 = ((uint64_t*)block)[2];
		const uint64_t m3 = ((uint64_t*)block)[3];
		const uint64_t m4 = ((uint64_t*)block)[4];
		const uint64_t m5 = ((uint64_t*)block)[5];
		const uint64_t m6 = ((uint64_t*)block)[6];
		const uint64_t m7 = ((uint64_t*)block)[7];
		const uint64_t m8 = ((uint64_t*)block)[8];
		const uint64_t m9 = ((uint64_t*)block)[9];
		const uint64_t m10 = ((uint64_t*)block)[10];
		const uint64_t m11 = ((uint64_t*)block)[11];
		const uint64_t m12 = ((uint64_t*)block)[12];
		const uint64_t m13 = ((uint64_t*)block)[13];
		const uint64_t m14 = ((uint64_t*)block)[14];
		const uint64_t m15 = ((uint64_t*)block)[15];
#endif
#if defined(HAS_SSSE3) && !defined(HAS_XOP)
		const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
		const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
#endif
		__m128i row1l = _mm_loadu_si128((const __m128i*)&State.H[0]);
		__m128i row1h = _mm_loadu_si128((const __m128i*)&State.H[2]);
		__m128i row2l = _mm_loadu_si128((const __m128i*)&State.H[4]);
		__m128i row2h = _mm_loadu_si128((const __m128i*)&State.H[6]);
		__m128i row3l = _mm_loadu_si128((const __m128i*)&IV[0]);
		__m128i row3h = _mm_loadu_si128((const __m128i*)&IV[2]);
		__m128i row4l = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[4]), _mm_loadu_si128((const __m128i*)&State.T[0]));
		__m128i row4h = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[6]), _mm_loadu_si128((const __m128i*)&State.F[0]));
		__m128i b0, b1, t0, t1;

		// round 0
		// lm 0.1
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m0, m1);
		b1 = _mm_unpacklo_epi64(m2, m3);
#else
		b0 = _mm_set_epi64x(m2, m0);
		b1 = _mm_set_epi64x(m6, m4);
#endif
		// g1
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

		// lm 0.2
#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m0, m1);
		b1 = _mm_unpackhi_epi64(m2, m3);
#else
		b0 = _mm_set_epi64x(m3, m1);
		b1 = _mm_set_epi64x(m7, m5);
#endif
		// g2
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);
		// diag
		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// lm 0.3
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m4, m5);
		b1 = _mm_unpacklo_epi64(m6, m7);
#else
		b0 = _mm_set_epi64x(m10, m8);
		b1 = _mm_set_epi64x(m14, m12);
#endif
		// g1
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

		// lm 0.4
#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m4, m5);
		b1 = _mm_unpackhi_epi64(m6, m7);
#else
		b0 = _mm_set_epi64x(m11, m9);
		b1 = _mm_set_epi64x(m15, m13);
#endif
		// g2
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);
		// undiag
		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 2
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m7, m2);
		b1 = _mm_unpackhi_epi64(m4, m6);
#else
		b0 = _mm_set_epi64x(m4, m14);
		b1 = _mm_set_epi64x(m13, m9);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m5, m4);
		b1 = _mm_alignr_epi8(m3, m7, 8);
#else
		b0 = _mm_set_epi64x(m8, m10);
		b1 = _mm_set_epi64x(m6, m15);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1, 0, 3, 2));
		b1 = _mm_unpackhi_epi64(m5, m2);
#else
		b0 = _mm_set_epi64x(m0, m1);
		b1 = _mm_set_epi64x(m5, m11);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m6, m1);
		b1 = _mm_unpackhi_epi64(m3, m1);
#else
		b0 = _mm_set_epi64x(m2, m12);
		b1 = _mm_set_epi64x(m3, m7);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 3
#if defined(HAS_SSE4)
		b0 = _mm_alignr_epi8(m6, m5, 8);
		b1 = _mm_unpackhi_epi64(m2, m7);
#else
		b0 = _mm_set_epi64x(m12, m11);
		b1 = _mm_set_epi64x(m15, m5);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m4, m0);
		b1 = _mm_blend_epi16(m1, m6, 0xF0);
#else
		b0 = _mm_set_epi64x(m0, m8);
		b1 = _mm_set_epi64x(m13, m2);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m5, m1, 0xF0);
		b1 = _mm_unpackhi_epi64(m3, m4);
#else
		b0 = _mm_set_epi64x(m3, m10);
		b1 = _mm_set_epi64x(m9, m7);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m7, m3);
		b1 = _mm_alignr_epi8(m2, m0, 8);
#else
		b0 = _mm_set_epi64x(m6, m14);
		b1 = _mm_set_epi64x(m4, m1);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 4
#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m3, m1);
		b1 = _mm_unpackhi_epi64(m6, m5);
#else
		b0 = _mm_set_epi64x(m3, m7);
		b1 = _mm_set_epi64x(m11, m13);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m4, m0);
		b1 = _mm_unpacklo_epi64(m6, m7);
#else
		b0 = _mm_set_epi64x(m1, m9);
		b1 = _mm_set_epi64x(m14, m12);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m1, m2, 0xF0);
		b1 = _mm_blend_epi16(m2, m7, 0xF0);
#else
		b0 = _mm_set_epi64x(m5, m2);
		b1 = _mm_set_epi64x(m15, m4);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m3, m5);
		b1 = _mm_unpacklo_epi64(m0, m4);
#else
		b0 = _mm_set_epi64x(m10, m6);
		b1 = _mm_set_epi64x(m8, m0);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 5
#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m4, m2);
		b1 = _mm_unpacklo_epi64(m1, m5);
#else
		b0 = _mm_set_epi64x(m5, m9);
		b1 = _mm_set_epi64x(m10, m2);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m0, m3, 0xF0);
		b1 = _mm_blend_epi16(m2, m7, 0xF0);
#else
		b0 = _mm_set_epi64x(m7, m0);
		b1 = _mm_set_epi64x(m15, m4);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m7, m5, 0xF0);
		b1 = _mm_blend_epi16(m3, m1, 0xF0);
#else
		b0 = _mm_set_epi64x(m11, m14);
		b1 = _mm_set_epi64x(m3, m6);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_alignr_epi8(m6, m0, 8);
		b1 = _mm_blend_epi16(m4, m6, 0xF0);
#else
		b0 = _mm_set_epi64x(m12, m1);
		b1 = _mm_set_epi64x(m13, m8);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 6
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m1, m3);
		b1 = _mm_unpacklo_epi64(m0, m4);
#else
		b0 = _mm_set_epi64x(m6, m2);
		b1 = _mm_set_epi64x(m8, m0);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m6, m5);
		b1 = _mm_unpackhi_epi64(m5, m1);
#else
		b0 = _mm_set_epi64x(m10, m12);
		b1 = _mm_set_epi64x(m3, m11);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m2, m3, 0xF0);
		b1 = _mm_unpackhi_epi64(m7, m0);
#else
		b0 = _mm_set_epi64x(m7, m4);
		b1 = _mm_set_epi64x(m1, m15);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m6, m2);
		b1 = _mm_blend_epi16(m7, m4, 0xF0);
#else
		b0 = _mm_set_epi64x(m5, m13);
		b1 = _mm_set_epi64x(m9, m14);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 7
#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m6, m0, 0xF0);
		b1 = _mm_unpacklo_epi64(m7, m2);
#else
		b0 = _mm_set_epi64x(m1, m12);
		b1 = _mm_set_epi64x(m4, m14);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m2, m7);
		b1 = _mm_alignr_epi8(m5, m6, 8);
#else
		b0 = _mm_set_epi64x(m15, m5);
		b1 = _mm_set_epi64x(m10, m13);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m0, m3);
		b1 = _mm_shuffle_epi32(m4, _MM_SHUFFLE(1, 0, 3, 2));
#else
		b0 = _mm_set_epi64x(m6, m0);
		b1 = _mm_set_epi64x(m8, m9);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m3, m1);
		b1 = _mm_blend_epi16(m1, m5, 0xF0);
#else
		b0 = _mm_set_epi64x(m3, m7);
		b1 = _mm_set_epi64x(m11, m2);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 8
#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m6, m3);
		b1 = _mm_blend_epi16(m6, m1, 0xF0);
#else
		b0 = _mm_set_epi64x(m7, m13);
		b1 = _mm_set_epi64x(m3, m12);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_alignr_epi8(m7, m5, 8);
		b1 = _mm_unpackhi_epi64(m0, m4);
#else
		b0 = _mm_set_epi64x(m14, m11);
		b1 = _mm_set_epi64x(m9, m1);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m2, m7);
		b1 = _mm_unpacklo_epi64(m4, m1);
#else
		b0 = _mm_set_epi64x(m15, m5);
		b1 = _mm_set_epi64x(m2, m8);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m0, m2);
		b1 = _mm_unpacklo_epi64(m3, m5);
#else
		b0 = _mm_set_epi64x(m4, m0);
		b1 = _mm_set_epi64x(m10, m6);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 9
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m3, m7);
		b1 = _mm_alignr_epi8(m0, m5, 8);
#else
		b0 = _mm_set_epi64x(m14, m6);
		b1 = _mm_set_epi64x(m0, m11);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m7, m4);
		b1 = _mm_alignr_epi8(m4, m1, 8);
#else
		b0 = _mm_set_epi64x(m9, m15);
		b1 = _mm_set_epi64x(m8, m3);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = m6;
		b1 = _mm_alignr_epi8(m5, m0, 8);
#else
		b0 = _mm_set_epi64x(m13, m12);
		b1 = _mm_set_epi64x(m10, m1);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_blend_epi16(m1, m3, 0xF0);
		b1 = m2;
#else
		b0 = _mm_set_epi64x(m7, m2);
		b1 = _mm_set_epi64x(m5, m4);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 10
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m5, m4);
		b1 = _mm_unpackhi_epi64(m3, m0);
#else
		b0 = _mm_set_epi64x(m8, m10);
		b1 = _mm_set_epi64x(m1, m7);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m1, m2);
		b1 = _mm_blend_epi16(m3, m2, 0xF0);
#else
		b0 = _mm_set_epi64x(m4, m2);
		b1 = _mm_set_epi64x(m5, m6);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m7, m4);
		b1 = _mm_unpackhi_epi64(m1, m6);
#else
		b0 = _mm_set_epi64x(m9, m15);
		b1 = _mm_set_epi64x(m13, m3);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_alignr_epi8(m7, m5, 8);
		b1 = _mm_unpacklo_epi64(m6, m0);
#else
		b0 = _mm_set_epi64x(m14, m11);
		b1 = _mm_set_epi64x(m0, m12);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 11
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m0, m1);
		b1 = _mm_unpacklo_epi64(m2, m3);
#else
		b0 = _mm_set_epi64x(m2, m0);
		b1 = _mm_set_epi64x(m6, m4);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m0, m1);
		b1 = _mm_unpackhi_epi64(m2, m3);
#else
		b0 = _mm_set_epi64x(m3, m1);
		b1 = _mm_set_epi64x(m7, m5);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m4, m5);
		b1 = _mm_unpacklo_epi64(m6, m7);
#else
		b0 = _mm_set_epi64x(m10, m8);
		b1 = _mm_set_epi64x(m14, m12);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpackhi_epi64(m4, m5);
		b1 = _mm_unpackhi_epi64(m6, m7);
#else
		b0 = _mm_set_epi64x(m11, m9);
		b1 = _mm_set_epi64x(m15, m13);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		// round 12
#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m7, m2);
		b1 = _mm_unpackhi_epi64(m4, m6);
#else
		b0 = _mm_set_epi64x(m4, m14);
		b1 = _mm_set_epi64x(m13, m9);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m5, m4);
		b1 = _mm_alignr_epi8(m3, m7, 8);
#else
		b0 = _mm_set_epi64x(m8, m10);
		b1 = _mm_set_epi64x(m6, m15);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		DIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

#if defined(HAS_SSE4)
		b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1, 0, 3, 2));
		b1 = _mm_unpackhi_epi64(m5, m2);
#else
		b0 = _mm_set_epi64x(m0, m1);
		b1 = _mm_set_epi64x(m5, m11);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -32);
		row4h = _mm_roti_epi64(row4h, -32);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -24);
		row2h = _mm_roti_epi64(row2h, -24);

#if defined(HAS_SSE4)
		b0 = _mm_unpacklo_epi64(m6, m1);
		b1 = _mm_unpackhi_epi64(m3, m1);
#else
		b0 = _mm_set_epi64x(m2, m12);
		b1 = _mm_set_epi64x(m3, m7);
#endif
		row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);
		row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);
		row4l = _mm_xor_si128(row4l, row1l);
		row4h = _mm_xor_si128(row4h, row1h);
		row4l = _mm_roti_epi64(row4l, -16);
		row4h = _mm_roti_epi64(row4h, -16);
		row3l = _mm_add_epi64(row3l, row4l);
		row3h = _mm_add_epi64(row3h, row4h);
		row2l = _mm_xor_si128(row2l, row3l);
		row2h = _mm_xor_si128(row2h, row3h);
		row2l = _mm_roti_epi64(row2l, -63);
		row2h = _mm_roti_epi64(row2h, -63);

		UNDIAGONALIZE(row1l, row2l, row3l, row4l, row1h, row2h, row3h, row4h);

		row1l = _mm_xor_si128(row3l, row1l);
		row1h = _mm_xor_si128(row3h, row1h);
		_mm_storeu_si128((__m128i*)&State.H[0], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[0]), row1l));
		_mm_storeu_si128((__m128i*)&State.H[2], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[2]), row1h));
		row2l = _mm_xor_si128(row4l, row2l);
		row2h = _mm_xor_si128(row4h, row2h);
		_mm_storeu_si128((__m128i*)&State.H[4], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[4]), row2l));
		_mm_storeu_si128((__m128i*)&State.H[6], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[6]), row2h));
	}
#else
	template <typename T>
	static inline void Compress(const std::vector<uint8_t> &Input, size_t InOffset, T &State, const std::vector<uint64_t> &IV)
	{
		std::vector<uint64_t> msg(16);

		msg[0] = IntUtils::BytesToLe64(Input, InOffset);
		msg[1] = IntUtils::BytesToLe64(Input, InOffset + 8);
		msg[2] = IntUtils::BytesToLe64(Input, InOffset + 16);
		msg[3] = IntUtils::BytesToLe64(Input, InOffset + 24);
		msg[4] = IntUtils::BytesToLe64(Input, InOffset + 32);
		msg[5] = IntUtils::BytesToLe64(Input, InOffset + 40);
		msg[6] = IntUtils::BytesToLe64(Input, InOffset + 48);
		msg[7] = IntUtils::BytesToLe64(Input, InOffset + 56);
		msg[8] = IntUtils::BytesToLe64(Input, InOffset + 64);
		msg[9] = IntUtils::BytesToLe64(Input, InOffset + 72);
		msg[10] = IntUtils::BytesToLe64(Input, InOffset + 80);
		msg[11] = IntUtils::BytesToLe64(Input, InOffset + 88);
		msg[12] = IntUtils::BytesToLe64(Input, InOffset + 96);
		msg[13] = IntUtils::BytesToLe64(Input, InOffset + 104);
		msg[14] = IntUtils::BytesToLe64(Input, InOffset + 112);
		msg[15] = IntUtils::BytesToLe64(Input, InOffset + 120);

		uint64_t v0 = State.H[0];
		uint64_t v1 = State.H[1];
		uint64_t v2 = State.H[2];
		uint64_t v3 = State.H[3];
		uint64_t v4 = State.H[4];
		uint64_t v5 = State.H[5];
		uint64_t v6 = State.H[6];
		uint64_t v7 = State.H[7];
		uint64_t v8 = IV[0];
		uint64_t v9 = IV[1];
		uint64_t v10 = IV[2];
		uint64_t v11 = IV[3];
		uint64_t v12 = IV[4] ^ State.T[0];
		uint64_t v13 = IV[5] ^ State.T[1];
		uint64_t v14 = IV[6] ^ State.F[0];
		uint64_t v15 = IV[7] ^ State.F[1];

		// round 0
		v0 += v4 + msg[0];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[1];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[2];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[3];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[4];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[5];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[7];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[8];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[9];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[10];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[11];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[12];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[13];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[14];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[15];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 1
		v0 += v4 + msg[14];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[10];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[4];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[8];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[9];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[15];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[13];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[1];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[12];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[0];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[2];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[11];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[7];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[5];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[3];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 2
		v0 += v4 + msg[11];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[8];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[12];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[0];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[5];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[2];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[15];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[13];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[10];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[14];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[3];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[6];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[7];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[1];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[9];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[4];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 3
		v0 += v4 + msg[7];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[9];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[3];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[1];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[13];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[12];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[11];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[14];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[2];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[6];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[5];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[10];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[4];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[0];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[15];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[8];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 4
		v0 += v4 + msg[9];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[0];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[5];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[7];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[2];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[4];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[10];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[15];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[14];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[1];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[11];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[12];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[6];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[8];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[3];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[13];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 5
		v0 += v4 + msg[2];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[12];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[6];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[10];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[0];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[11];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[8];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[3];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[4];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[13];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[7];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[5];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[15];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[14];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[1];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[9];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 6
		v0 += v4 + msg[12];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[5];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[1];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[15];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[14];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[13];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[4];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[10];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[0];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[7];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[6];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[3];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[9];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[2];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[8];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[11];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 7
		v0 += v4 + msg[13];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[11];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[7];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[14];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[12];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[1];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[3];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[9];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[5];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[0];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[15];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[4];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[8];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[6];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[2];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[10];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 8
		v0 += v4 + msg[6];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[15];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[14];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[9];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[11];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[3];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[0];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[8];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[12];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[2];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[13];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[7];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[1];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[4];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[10];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[5];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 9
		v0 += v4 + msg[10];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[2];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[8];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[4];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[7];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[6];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[1];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[5];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[15];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[11];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[9];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[14];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[3];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[12];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[13];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[0];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 10
		v0 += v4 + msg[0];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[1];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[2];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[3];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[4];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[5];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[7];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[8];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[9];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[10];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[11];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[12];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[13];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[14];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[15];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		// round 11
		v0 += v4 + msg[14];
		v12 ^= v0;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v0 += v4 + msg[10];
		v12 ^= v0;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v8 += v12;
		v4 ^= v8;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		v1 += v5 + msg[4];
		v13 ^= v1;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v1 += v5 + msg[8];
		v13 ^= v1;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v9 += v13;
		v5 ^= v9;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v2 += v6 + msg[9];
		v14 ^= v2;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v2 += v6 + msg[15];
		v14 ^= v2;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v10 += v14;
		v6 ^= v10;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v3 += v7 + msg[13];
		v15 ^= v3;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v3 += v7 + msg[6];
		v15 ^= v3;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v11 += v15;
		v7 ^= v11;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v0 += v5 + msg[1];
		v15 ^= v0;
		v15 = ((v15 >> 32) | (v15 << (64 - 32)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 24) | (v5 << (64 - 24)));
		v0 += v5 + msg[12];
		v15 ^= v0;
		v15 = ((v15 >> 16) | (v15 << (64 - 16)));
		v10 += v15;
		v5 ^= v10;
		v5 = ((v5 >> 63) | (v5 << (64 - 63)));

		v1 += v6 + msg[0];
		v12 ^= v1;
		v12 = ((v12 >> 32) | (v12 << (64 - 32)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 24) | (v6 << (64 - 24)));
		v1 += v6 + msg[2];
		v12 ^= v1;
		v12 = ((v12 >> 16) | (v12 << (64 - 16)));
		v11 += v12;
		v6 ^= v11;
		v6 = ((v6 >> 63) | (v6 << (64 - 63)));

		v2 += v7 + msg[11];
		v13 ^= v2;
		v13 = ((v13 >> 32) | (v13 << (64 - 32)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 24) | (v7 << (64 - 24)));
		v2 += v7 + msg[7];
		v13 ^= v2;
		v13 = ((v13 >> 16) | (v13 << (64 - 16)));
		v8 += v13;
		v7 ^= v8;
		v7 = ((v7 >> 63) | (v7 << (64 - 63)));

		v3 += v4 + msg[5];
		v14 ^= v3;
		v14 = ((v14 >> 32) | (v14 << (64 - 32)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 24) | (v4 << (64 - 24)));
		v3 += v4 + msg[3];
		v14 ^= v3;
		v14 = ((v14 >> 16) | (v14 << (64 - 16)));
		v9 += v14;
		v4 ^= v9;
		v4 = ((v4 >> 63) | (v4 << (64 - 63)));

		State.H[0] ^= v0 ^ v8;
		State.H[1] ^= v1 ^ v9;
		State.H[2] ^= v2 ^ v10;
		State.H[3] ^= v3 ^ v11;
		State.H[4] ^= v4 ^ v12;
		State.H[5] ^= v5 ^ v13;
		State.H[6] ^= v6 ^ v14;
		State.H[7] ^= v7 ^ v15;
	}
#endif
};

NAMESPACE_DIGESTEND
#endif