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
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_BLAKE2BCOMPRESS_H
#define _CEX_BLAKE2BCOMPRESS_H

#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class Blake512Compress
{
private:

#if defined(__AVX__)
#	define _mm_roti_epi64(x, c) \
		(-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
		: (-(c) == 24) ? _mm_shuffle_epi8((x), R24) \
		: (-(c) == 16) ? _mm_shuffle_epi8((x), R16) \
		: (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
		: _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))

#	define DIAGONALIZE(RL1,RL2,RL3,RL4,RH1,RH2,RH3,RH4) \
		T0 = _mm_alignr_epi8(RH2, RL2, 8); \
		T1 = _mm_alignr_epi8(RL2, RH2, 8); \
		RL2 = T0; \
		RH2 = T1; \
		\
		T0 = RL3; \
		RL3 = RH3; \
		RH3 = T0;    \
		\
		T0 = _mm_alignr_epi8(RH4, RL4, 8); \
		T1 = _mm_alignr_epi8(RL4, RH4, 8); \
		RL4 = T1; \
		RH4 = T0;

#	define UNDIAGONALIZE(RL1,RL2,RL3,RL4,RH1,RH2,RH3,RH4) \
		T0 = _mm_alignr_epi8(RL2, RH2, 8); \
		T1 = _mm_alignr_epi8(RH2, RL2, 8); \
		RL2 = T0; \
		RH2 = T1; \
		\
		T0 = RL3; \
		RL3 = RH3; \
		RH3 = T0; \
		\
		T0 = _mm_alignr_epi8(RL4, RH4, 8); \
		T1 = _mm_alignr_epi8(RH4, RL4, 8); \
		RL4 = T1; \
		RH4 = T0;
#endif

public:

#if defined(__AVX__)
	template <typename T>
	static void Compress128(const std::vector<byte> &Input, size_t InOffset, T &State, const std::vector<ulong> &IV)
	{
		const __m128i M0 = _mm_loadu_si128((const __m128i*)&Input[InOffset]);
		const __m128i M1 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 16]);
		const __m128i M2 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 32]);
		const __m128i M3 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 48]);
		const __m128i M4 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 64]);
		const __m128i M5 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 80]);
		const __m128i M6 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 96]);
		const __m128i M7 = _mm_loadu_si128((const __m128i*)&Input[InOffset + 112]);
		const __m128i R16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
		const __m128i R24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

		__m128i RL1 = _mm_loadu_si128((const __m128i*)&State.H[0]);
		__m128i RH1 = _mm_loadu_si128((const __m128i*)&State.H[2]);
		__m128i RL2 = _mm_loadu_si128((const __m128i*)&State.H[4]);
		__m128i RH2 = _mm_loadu_si128((const __m128i*)&State.H[6]);
		__m128i RL3 = _mm_loadu_si128((const __m128i*)&IV[0]);
		__m128i RH3 = _mm_loadu_si128((const __m128i*)&IV[2]);
		__m128i RL4 = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[4]), _mm_loadu_si128((const __m128i*)&State.T[0]));
		__m128i RH4 = _mm_xor_si128(_mm_loadu_si128((const __m128i*)&IV[6]), _mm_loadu_si128((const __m128i*)&State.F[0]));
		__m128i B0, B1, T0, T1;

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
		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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
		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		DIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

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

		UNDIAGONALIZE(RL1, RL2, RL3, RL4, RH1, RH2, RH3, RH4);

		RL1 = _mm_xor_si128(RL3, RL1);
		RH1 = _mm_xor_si128(RH3, RH1);
		_mm_storeu_si128((__m128i*)&State.H[0], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[0]), RL1));
		_mm_storeu_si128((__m128i*)&State.H[2], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[2]), RH1));
		RL2 = _mm_xor_si128(RL4, RL2);
		RH2 = _mm_xor_si128(RH4, RH2);
		_mm_storeu_si128((__m128i*)&State.H[4], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[4]), RL2));
		_mm_storeu_si128((__m128i*)&State.H[6], _mm_xor_si128(_mm_loadu_si128((const __m128i*)&State.H[6]), RH2));
	}

#else

	template <typename T>
	static void Compress128(const std::vector<byte> &Input, size_t InOffset, T &State, const std::vector<ulong> &IV)
	{
		std::vector<ulong> M(16);
		Utility::IntUtils::LeBytesToULL1024(Input, InOffset, M, 0);

		ulong R0 = State.H[0];
		ulong R1 = State.H[1];
		ulong R2 = State.H[2];
		ulong R3 = State.H[3];
		ulong R4 = State.H[4];
		ulong R5 = State.H[5];
		ulong R6 = State.H[6];
		ulong R7 = State.H[7];
		ulong R8 = IV[0];
		ulong R9 = IV[1];
		ulong R10 = IV[2];
		ulong R11 = IV[3];
		ulong R12 = IV[4] ^ State.T[0];
		ulong R13 = IV[5] ^ State.T[1];
		ulong R14 = IV[6] ^ State.F[0];
		ulong R15 = IV[7] ^ State.F[1];

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