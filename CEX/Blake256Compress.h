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

#ifndef _CEX_BLAKE2SCOMPRESS_H
#define _CEX_BLAKE2SCOMPRESS_H

#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class Blake256Compress
{
private:

#if defined(__AVX__)
#	define TOF(reg) _mm_castsi128_ps((reg))
#	define TOI(reg) _mm_castps_si128((reg))
#	define _mm_roti_epi32(r, c) ( \
        (8==-(c)) ? _mm_shuffle_epi8(r,R8) \
        : (16==-(c)) ? _mm_shuffle_epi8(r,R16) \
        : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )
#endif

public:

#if defined(__AVX__)
	template <typename T>
	static void Compress64(const std::vector<byte> &Input, size_t InOffset, T &State, const std::vector<uint> &IV)
	{
		__m128i R1, R2, R3, R4;
		__m128i B1, B2, B3, B4;
		__m128i FF0, FF1;
		__m128i T0, T1, T2;

		const __m128i R8 = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1);
		const __m128i R16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
		const __m128i M0 = _mm_loadu_si128((const __m128i*)&Input[InOffset]);
		const __m128i M1 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 16]);
		const __m128i M2 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 32]);
		const __m128i M3 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 48]);

		R1 = FF0 = _mm_loadu_si128((const __m128i*)&State.H[0]);
		R2 = FF1 = _mm_loadu_si128((const __m128i*)&State.H[4]);
		R3 = _mm_loadu_si128((const __m128i*)&IV[0]);
		std::vector<byte> taf(16);
		memcpy(&taf[0], &State.T[0], 8);
		memcpy(&taf[8], &State.F[0], 8);
		R4 = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[4]), _mm_loadu_si128((const __m128i*)&taf[0]));

		// round 0
		// lm 0.1
		B1 = TOI(_mm_shuffle_ps(TOF(M0), TOF(M1), _MM_SHUFFLE(2, 0, 2, 0)));
		// g1
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B1), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 0.2
		B2 = TOI(_mm_shuffle_ps(TOF(M0), TOF(M1), _MM_SHUFFLE(3, 1, 3, 1)));
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
		B3 = TOI(_mm_shuffle_ps(TOF(M2), TOF(M3), _MM_SHUFFLE(2, 0, 2, 0)));
		// g1
		R1 = _mm_add_epi32(_mm_add_epi32(R1, B3), R2);
		R4 = _mm_xor_si128(R4, R1);
		R4 = _mm_roti_epi32(R4, -16);
		R3 = _mm_add_epi32(R3, R4);
		R2 = _mm_xor_si128(R2, R3);
		R2 = _mm_roti_epi32(R2, -12);

		// lm 0.4
		B4 = TOI(_mm_shuffle_ps(TOF(M2), TOF(M3), _MM_SHUFFLE(3, 1, 3, 1)));
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

		_mm_storeu_si128((__m128i*)&State.H[0], _mm_xor_si128(FF0, _mm_xor_si128(R1, R3)));
		_mm_storeu_si128((__m128i*)&State.H[4], _mm_xor_si128(FF1, _mm_xor_si128(R2, R4)));
	}

#else

	template <typename T>
	static void Compress64(const std::vector<byte> &Input, size_t InOffset, T &State, const std::vector<uint> &IV)
	{
		std::vector<uint> M(16);
		Utility::IntUtils::LeBytesToUL512(Input, InOffset, M, 0);

		uint R0 = State.H[0];
		uint R1 = State.H[1];
		uint R2 = State.H[2];
		uint R3 = State.H[3];
		uint R4 = State.H[4];
		uint R5 = State.H[5];
		uint R6 = State.H[6];
		uint R7 = State.H[7];
		uint R8 = IV[0];
		uint R9 = IV[1];
		uint R10 = IV[2];
		uint R11 = IV[3];
		uint R12 = IV[4] ^ State.T[0];
		uint R13 = IV[5] ^ State.T[1];
		uint R14 = IV[6] ^ State.F[0];
		uint R15 = IV[7] ^ State.F[1];

		// round 0
		R0 += R4 + M[0];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[1];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[2];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[3];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[4];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[5];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[7];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[8];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[9];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[10];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[11];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[12];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[13];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[14];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[15];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 1
		R0 += R4 + M[14];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[10];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[4];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[8];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[9];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[15];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[13];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[1];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[12];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[0];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[2];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[11];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[7];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[5];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[3];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 2
		R0 += R4 + M[11];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[8];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[12];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[0];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[5];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[2];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[15];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[13];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[10];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[14];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[3];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[6];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[7];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[1];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[9];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[4];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 3
		R0 += R4 + M[7];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[9];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[3];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[1];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[13];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[12];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[11];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[14];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[2];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[6];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[5];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[10];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[4];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[0];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[15];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[8];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 4
		R0 += R4 + M[9];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[0];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[5];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[7];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[2];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[4];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[10];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[15];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[14];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[1];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[11];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[12];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[6];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[8];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[3];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[13];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 5
		R0 += R4 + M[2];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[12];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[6];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[10];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[0];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[11];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[8];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[3];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[4];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[13];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[7];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[5];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[15];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[14];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[1];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[9];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 6
		R0 += R4 + M[12];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[5];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[1];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[15];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[14];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[13];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[4];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[10];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[0];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[7];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[6];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[3];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[9];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[2];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[8];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[11];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 7
		R0 += R4 + M[13];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[11];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[7];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[14];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[12];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[1];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[3];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[9];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[5];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[0];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[15];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[4];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[8];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[6];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[2];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[10];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 8
		R0 += R4 + M[6];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[15];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[14];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[9];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[11];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[3];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[0];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[8];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[12];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[2];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[13];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[7];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[1];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[4];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[10];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[5];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		// round 9
		R0 += R4 + M[10];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R0 += R4 + M[2];
		R12 ^= R0;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		R1 += R5 + M[8];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R1 += R5 + M[4];
		R13 ^= R1;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R2 += R6 + M[7];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R2 += R6 + M[6];
		R14 ^= R2;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R3 += R7 + M[1];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R3 += R7 + M[5];
		R15 ^= R3;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R0 += R5 + M[15];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (32 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 12) | (R5 << (32 - 12)));
		R0 += R5 + M[11];
		R15 ^= R0;
		R15 = ((R15 >> 8) | (R15 << (32 - 8)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 7) | (R5 << (32 - 7)));

		R1 += R6 + M[9];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (32 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 12) | (R6 << (32 - 12)));
		R1 += R6 + M[14];
		R12 ^= R1;
		R12 = ((R12 >> 8) | (R12 << (32 - 8)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 7) | (R6 << (32 - 7)));

		R2 += R7 + M[3];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (32 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 12) | (R7 << (32 - 12)));
		R2 += R7 + M[12];
		R13 ^= R2;
		R13 = ((R13 >> 8) | (R13 << (32 - 8)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 7) | (R7 << (32 - 7)));

		R3 += R4 + M[13];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (32 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 12) | (R4 << (32 - 12)));
		R3 += R4 + M[0];
		R14 ^= R3;
		R14 = ((R14 >> 8) | (R14 << (32 - 8)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 7) | (R4 << (32 - 7)));

		State.H[0] ^= R0 ^ R8;
		State.H[1] ^= R1 ^ R9;
		State.H[2] ^= R2 ^ R10;
		State.H[3] ^= R3 ^ R11;
		State.H[4] ^= R4 ^ R12;
		State.H[5] ^= R5 ^ R13;
		State.H[6] ^= R6 ^ R14;
		State.H[7] ^= R7 ^ R15;
	}
#endif
};

NAMESPACE_DIGESTEND
#endif