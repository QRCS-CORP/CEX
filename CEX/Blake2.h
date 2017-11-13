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

#ifndef CEX_BLAKE2_H
#define CEX_BLAKE2_H

#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class Blake2
{

private:

	//~~~Inline Functions~~~//

#if defined(__AVX__)

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
	inline static void Diagonalize(T &RL1, T &RL2, T &RL3, T &RL4, T &RH1, T &RH2, T &RH3, T &RH4)
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
	inline static void UnDiagonalize(T &RL1, T &RL2, T &RL3, T &RL4, T &RH1, T &RH2, T &RH3, T &RH4)
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

	//~~~Public Functions~~~//

#if defined(__AVX__)

	template <typename State>
	inline static void Compress512(const std::vector<byte> &Input, size_t InOffset, State &Output, const std::vector<uint> &IV)
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

		R1 = FF0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[0]));
		R2 = FF1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[4]));
		R3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[0]));
		std::vector<byte> taf(16);
		std::memcpy(&taf[0], &Output.T[0], 8);
		std::memcpy(&taf[8], &Output.F[0], 8);
		R4 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[4])), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&taf[0])));

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

		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[0]), _mm_xor_si128(FF0, _mm_xor_si128(R1, R3)));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[4]), _mm_xor_si128(FF1, _mm_xor_si128(R2, R4)));
	}

	template <typename State>
	inline static void Compress1024(const std::vector<byte> &Input, size_t InOffset, State &Output, const std::vector<ulong> &IV)
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

		__m128i RL1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[0]));
		__m128i RH1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[2]));
		__m128i RL2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[4]));
		__m128i RH2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[6]));
		__m128i RL3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[0]));
		__m128i RH3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[2]));
		__m128i RL4 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[4])), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.T[0])));
		__m128i RH4 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&IV[6])), _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.F[0])));
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
		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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
		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		Diagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UnDiagonalize(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

		RL1 = _mm_xor_si128(RL3, RL1);
		RH1 = _mm_xor_si128(RH3, RH1);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[0]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[0])), RL1));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[2]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[2])), RH1));
		RL2 = _mm_xor_si128(RL4, RL2);
		RH2 = _mm_xor_si128(RH4, RH2);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[4]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[4])), RL2));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[6]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Output.H[6])), RH2));
	}

#else

	template <typename State>
	inline static void Compress512(const std::vector<byte> &Input, size_t InOffset, State &Output, const std::vector<uint> &IV)
	{
		std::array<uint, 16> M;
		Utility::IntUtils::LeBytesToUL512(Input, InOffset, M, 0);

		uint R0 = Output.H[0];
		uint R1 = Output.H[1];
		uint R2 = Output.H[2];
		uint R3 = Output.H[3];
		uint R4 = Output.H[4];
		uint R5 = Output.H[5];
		uint R6 = Output.H[6];
		uint R7 = Output.H[7];
		uint R8 = IV[0];
		uint R9 = IV[1];
		uint R10 = IV[2];
		uint R11 = IV[3];
		uint R12 = IV[4] ^ Output.T[0];
		uint R13 = IV[5] ^ Output.T[1];
		uint R14 = IV[6] ^ Output.F[0];
		uint R15 = IV[7] ^ Output.F[1];

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

		Output.H[0] ^= R0 ^ R8;
		Output.H[1] ^= R1 ^ R9;
		Output.H[2] ^= R2 ^ R10;
		Output.H[3] ^= R3 ^ R11;
		Output.H[4] ^= R4 ^ R12;
		Output.H[5] ^= R5 ^ R13;
		Output.H[6] ^= R6 ^ R14;
		Output.H[7] ^= R7 ^ R15;
	}

	template <typename State>
	inline static void Compress1024(const std::vector<byte> &Input, size_t InOffset, State &Output, const std::vector<ulong> &IV)
	{
		std::array<ulong, 16> M;
		Utility::IntUtils::LeBytesToULL1024(Input, InOffset, M, 0);

		ulong R0 = Output.H[0];
		ulong R1 = Output.H[1];
		ulong R2 = Output.H[2];
		ulong R3 = Output.H[3];
		ulong R4 = Output.H[4];
		ulong R5 = Output.H[5];
		ulong R6 = Output.H[6];
		ulong R7 = Output.H[7];
		ulong R8 = IV[0];
		ulong R9 = IV[1];
		ulong R10 = IV[2];
		ulong R11 = IV[3];
		ulong R12 = IV[4] ^ Output.T[0];
		ulong R13 = IV[5] ^ Output.T[1];
		ulong R14 = IV[6] ^ Output.F[0];
		ulong R15 = IV[7] ^ Output.F[1];

		// round 0
		R0 += R4 + M[0];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[1];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[2];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[3];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[4];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[5];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[7];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[8];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[9];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[10];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[11];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[12];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[13];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[14];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[15];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 1
		R0 += R4 + M[14];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[10];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[4];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[8];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[9];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[15];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[13];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[1];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[12];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[0];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[2];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[11];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[7];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[5];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[3];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 2
		R0 += R4 + M[11];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[8];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[12];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[0];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[5];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[2];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[15];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[13];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[10];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[14];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[3];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[6];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[7];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[1];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[9];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[4];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 3
		R0 += R4 + M[7];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[9];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[3];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[1];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[13];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[12];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[11];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[14];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[2];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[6];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[5];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[10];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[4];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[0];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[15];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[8];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 4
		R0 += R4 + M[9];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[0];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[5];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[7];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[2];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[4];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[10];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[15];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[14];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[1];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[11];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[12];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[6];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[8];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[3];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[13];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 5
		R0 += R4 + M[2];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[12];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[6];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[10];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[0];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[11];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[8];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[3];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[4];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[13];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[7];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[5];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[15];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[14];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[1];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[9];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 6
		R0 += R4 + M[12];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[5];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[1];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[15];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[14];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[13];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[4];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[10];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[0];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[7];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[6];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[3];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[9];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[2];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[8];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[11];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 7
		R0 += R4 + M[13];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[11];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[7];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[14];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[12];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[1];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[3];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[9];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[5];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[0];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[15];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[4];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[8];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[6];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[2];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[10];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 8
		R0 += R4 + M[6];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[15];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[14];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[9];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[11];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[3];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[0];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[8];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[12];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[2];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[13];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[7];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[1];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[4];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[10];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[5];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 9
		R0 += R4 + M[10];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[2];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[8];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[4];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[7];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[6];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[1];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[5];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[15];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[11];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[9];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[14];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[3];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[12];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[13];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[0];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 10
		R0 += R4 + M[0];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[1];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[2];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[3];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[4];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[5];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[7];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[8];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[9];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[10];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[11];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[12];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[13];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[14];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[15];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		// round 11
		R0 += R4 + M[14];
		R12 ^= R0;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R0 += R4 + M[10];
		R12 ^= R0;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R8 += R12;
		R4 ^= R8;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		R1 += R5 + M[4];
		R13 ^= R1;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R1 += R5 + M[8];
		R13 ^= R1;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R9 += R13;
		R5 ^= R9;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R2 += R6 + M[9];
		R14 ^= R2;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R2 += R6 + M[15];
		R14 ^= R2;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R10 += R14;
		R6 ^= R10;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R3 += R7 + M[13];
		R15 ^= R3;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R3 += R7 + M[6];
		R15 ^= R3;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R11 += R15;
		R7 ^= R11;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R0 += R5 + M[1];
		R15 ^= R0;
		R15 = ((R15 >> 32) | (R15 << (64 - 32)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 24) | (R5 << (64 - 24)));
		R0 += R5 + M[12];
		R15 ^= R0;
		R15 = ((R15 >> 16) | (R15 << (64 - 16)));
		R10 += R15;
		R5 ^= R10;
		R5 = ((R5 >> 63) | (R5 << (64 - 63)));

		R1 += R6 + M[0];
		R12 ^= R1;
		R12 = ((R12 >> 32) | (R12 << (64 - 32)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 24) | (R6 << (64 - 24)));
		R1 += R6 + M[2];
		R12 ^= R1;
		R12 = ((R12 >> 16) | (R12 << (64 - 16)));
		R11 += R12;
		R6 ^= R11;
		R6 = ((R6 >> 63) | (R6 << (64 - 63)));

		R2 += R7 + M[11];
		R13 ^= R2;
		R13 = ((R13 >> 32) | (R13 << (64 - 32)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 24) | (R7 << (64 - 24)));
		R2 += R7 + M[7];
		R13 ^= R2;
		R13 = ((R13 >> 16) | (R13 << (64 - 16)));
		R8 += R13;
		R7 ^= R8;
		R7 = ((R7 >> 63) | (R7 << (64 - 63)));

		R3 += R4 + M[5];
		R14 ^= R3;
		R14 = ((R14 >> 32) | (R14 << (64 - 32)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 24) | (R4 << (64 - 24)));
		R3 += R4 + M[3];
		R14 ^= R3;
		R14 = ((R14 >> 16) | (R14 << (64 - 16)));
		R9 += R14;
		R4 ^= R9;
		R4 = ((R4 >> 63) | (R4 << (64 - 63)));

		Output.H[0] ^= R0 ^ R8;
		Output.H[1] ^= R1 ^ R9;
		Output.H[2] ^= R2 ^ R10;
		Output.H[3] ^= R3 ^ R11;
		Output.H[4] ^= R4 ^ R12;
		Output.H[5] ^= R5 ^ R13;
		Output.H[6] ^= R6 ^ R14;
		Output.H[7] ^= R7 ^ R15;
	}

#endif
};

NAMESPACE_DIGESTEND
#endif