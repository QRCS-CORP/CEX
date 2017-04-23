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

#include "CexDomain.h"
#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

/**
* \internal
*/
class SHA256Compress
{
private:
	static const size_t BLOCK_SIZE = 64;

	inline static uint BigSigma0(uint W)
	{
		return ((W >> 2) | (W << 30)) ^ ((W >> 13) | (W << 19)) ^ ((W >> 22) | (W << 10));
	}

	inline static uint BigSigma1(uint W)
	{
		return ((W >> 6) | (W << 26)) ^ ((W >> 11) | (W << 21)) ^ ((W >> 25) | (W << 7));
	}

	inline static uint Ch(uint B, uint C, uint D)
	{
		return (B & C) ^ (~B & D);
	}

	inline static uint Maj(uint B, uint C, uint D)
	{
		return (B & C) ^ (B & D) ^ (C & D);
	}

	inline static uint Sigma0(uint W)
	{
		return ((W >> 7) | (W << 25)) ^ ((W >> 18) | (W << 14)) ^ (W >> 3);
	}

	inline static uint Sigma1(uint W)
	{
		return ((W >> 17) | (W << 15)) ^ ((W >> 19) | (W << 13)) ^ (W >> 10);
	}

	#define SHA256ROUND(A, B, C, D, E, F, G, H, M, P)			\
	do {														\
		uint R0(H + BigSigma1(E) + Ch(E, F, G) + P + M);		\
		D += R0;												\
		uint R1(BigSigma0(A) + Maj(A, B, C));					\
		H = R0 + R1;											\
	} while (0)													\


public:

	template <typename T>
	inline static void Compress64W(const std::vector<byte> &Input, size_t InOffset, T &Output)
	{
#if defined(__AVX__)
		__m128i S0, S1, T0, T1;
		__m128i MSG, TMP, MASK;
		__m128i M0, M1, M2, M3;

		// Load initial values
		TMP = _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output.H));
		S1 = _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output.H[4]));
		MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
		TMP = _mm_shuffle_epi32(TMP, 0xB1);  // CDAB
		S1 = _mm_shuffle_epi32(S1, 0x1B);    // EFGH
		S0 = _mm_alignr_epi8(TMP, S1, 8);    // ABEF
		S1 = _mm_blend_epi16(S1, TMP, 0xF0); // CDGH

		// Save current state
		T0 = S0;
		T1 = S1;

		// Rounds 0-3
		MSG = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset]));
		M0 = _mm_shuffle_epi8(MSG, MASK);
		MSG = _mm_add_epi32(M0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

		// Rounds 4-7
		M1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16]));
		M1 = _mm_shuffle_epi8(M1, MASK);
		MSG = _mm_add_epi32(M1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M0 = _mm_sha256msg1_epu32(M0, M1);

		// Rounds 8-11
		M2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 32]));
		M2 = _mm_shuffle_epi8(M2, MASK);
		MSG = _mm_add_epi32(M2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M1 = _mm_sha256msg1_epu32(M1, M2);

		// Rounds 12-15
		M3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 48]));
		M3 = _mm_shuffle_epi8(M3, MASK);
		MSG = _mm_add_epi32(M3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M3, M2, 4);
		M0 = _mm_add_epi32(M0, TMP);
		M0 = _mm_sha256msg2_epu32(M0, M3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M2 = _mm_sha256msg1_epu32(M2, M3);

		// Rounds 16-19
		MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M0, M3, 4);
		M1 = _mm_add_epi32(M1, TMP);
		M1 = _mm_sha256msg2_epu32(M1, M0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M3 = _mm_sha256msg1_epu32(M3, M0);

		// Rounds 20-23
		MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M1, M0, 4);
		M2 = _mm_add_epi32(M2, TMP);
		M2 = _mm_sha256msg2_epu32(M2, M1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M0 = _mm_sha256msg1_epu32(M0, M1);

		// Rounds 24-27
		MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M2, M1, 4);
		M3 = _mm_add_epi32(M3, TMP);
		M3 = _mm_sha256msg2_epu32(M3, M2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M1 = _mm_sha256msg1_epu32(M1, M2);

		// Rounds 28-31
		MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M3, M2, 4);
		M0 = _mm_add_epi32(M0, TMP);
		M0 = _mm_sha256msg2_epu32(M0, M3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M2 = _mm_sha256msg1_epu32(M2, M3);

		// Rounds 32-35
		MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M0, M3, 4);
		M1 = _mm_add_epi32(M1, TMP);
		M1 = _mm_sha256msg2_epu32(M1, M0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M3 = _mm_sha256msg1_epu32(M3, M0);

		// Rounds 36-39
		MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M1, M0, 4);
		M2 = _mm_add_epi32(M2, TMP);
		M2 = _mm_sha256msg2_epu32(M2, M1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M0 = _mm_sha256msg1_epu32(M0, M1);

		// Rounds 40-43
		MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M2, M1, 4);
		M3 = _mm_add_epi32(M3, TMP);
		M3 = _mm_sha256msg2_epu32(M3, M2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M1 = _mm_sha256msg1_epu32(M1, M2);

		// Rounds 44-47
		MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M3, M2, 4);
		M0 = _mm_add_epi32(M0, TMP);
		M0 = _mm_sha256msg2_epu32(M0, M3);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M2 = _mm_sha256msg1_epu32(M2, M3);

		// Rounds 48-51
		MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M0, M3, 4);
		M1 = _mm_add_epi32(M1, TMP);
		M1 = _mm_sha256msg2_epu32(M1, M0);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
		M3 = _mm_sha256msg1_epu32(M3, M0);

		// Rounds 52-55
		MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M1, M0, 4);
		M2 = _mm_add_epi32(M2, TMP);
		M2 = _mm_sha256msg2_epu32(M2, M1);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

		// Rounds 56-59
		MSG = _mm_add_epi32(M2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		TMP = _mm_alignr_epi8(M2, M1, 4);
		M3 = _mm_add_epi32(M3, TMP);
		M3 = _mm_sha256msg2_epu32(M3, M2);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

		// Rounds 60-63
		MSG = _mm_add_epi32(M3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
		S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
		MSG = _mm_shuffle_epi32(MSG, 0x0E);
		S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);

		// Combine state 
		S0 = _mm_add_epi32(S0, T0);
		S1 = _mm_add_epi32(S1, T1);
		TMP = _mm_shuffle_epi32(S0, 0x1B);   // FEBA
		S1 = _mm_shuffle_epi32(S1, 0xB1);    // DCHG
		S0 = _mm_blend_epi16(TMP, S1, 0xF0); // DCBA
		S1 = _mm_alignr_epi8(S1, TMP, 8);    // ABEF

		// Save state
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[0]), S0);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output.H[4]), S1);
#else
		Compress64(Input, InOffset, Output);
#endif
	}

	template <typename T>
	inline static void Compress64(const std::vector<byte> &Input, size_t InOffset, T &Output)
	{
		uint A = Output.H[0];
		uint B = Output.H[1];
		uint C = Output.H[2];
		uint D = Output.H[3];
		uint E = Output.H[4];
		uint F = Output.H[5];
		uint G = Output.H[6];
		uint H = Output.H[7];
		uint W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

		W0 = IntUtils::BeBytesTo32(Input, InOffset);
		SHA256ROUND(A, B, C, D, E, F, G, H, W0, 0x428a2f98);
		W1 = IntUtils::BeBytesTo32(Input, InOffset + 4);
		SHA256ROUND(H, A, B, C, D, E, F, G, W1, 0x71374491);
		W2 = IntUtils::BeBytesTo32(Input, InOffset + 8);
		SHA256ROUND(G, H, A, B, C, D, E, F, W2, 0xb5c0fbcf);
		W3 = IntUtils::BeBytesTo32(Input, InOffset + 12);
		SHA256ROUND(F, G, H, A, B, C, D, E, W3, 0xe9b5dba5);
		W4 = IntUtils::BeBytesTo32(Input, InOffset + 16);
		SHA256ROUND(E, F, G, H, A, B, C, D, W4, 0x3956c25b);
		W5 = IntUtils::BeBytesTo32(Input, InOffset + 20);
		SHA256ROUND(D, E, F, G, H, A, B, C, W5, 0x59f111f1);
		W6 = IntUtils::BeBytesTo32(Input, InOffset + 24);
		SHA256ROUND(C, D, E, F, G, H, A, B, W6, 0x923f82a4);
		W7 = IntUtils::BeBytesTo32(Input, InOffset + 28);
		SHA256ROUND(B, C, D, E, F, G, H, A, W7, 0xab1c5ed5);
		W8 = IntUtils::BeBytesTo32(Input, InOffset + 32);
		SHA256ROUND(A, B, C, D, E, F, G, H, W8, 0xd807aa98);
		W9 = IntUtils::BeBytesTo32(Input, InOffset + 36);
		SHA256ROUND(H, A, B, C, D, E, F, G, W9, 0x12835b01);
		W10 = IntUtils::BeBytesTo32(Input, InOffset + 40);
		SHA256ROUND(G, H, A, B, C, D, E, F, W10, 0x243185be);
		W11 = IntUtils::BeBytesTo32(Input, InOffset + 44);
		SHA256ROUND(F, G, H, A, B, C, D, E, W11, 0x550c7dc3);
		W12 = IntUtils::BeBytesTo32(Input, InOffset + 48);
		SHA256ROUND(E, F, G, H, A, B, C, D, W12, 0x72be5d74);
		W13 = IntUtils::BeBytesTo32(Input, InOffset + 52);
		SHA256ROUND(D, E, F, G, H, A, B, C, W13, 0x80deb1fe);
		W14 = IntUtils::BeBytesTo32(Input, InOffset + 56);
		SHA256ROUND(C, D, E, F, G, H, A, B, W14, 0x9bdc06a7);
		W15 = IntUtils::BeBytesTo32(Input, InOffset + 60);
		SHA256ROUND(B, C, D, E, F, G, H, A, W15, 0xc19bf174);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256ROUND(A, B, C, D, E, F, G, H, W0, 0xe49b69c1);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256ROUND(H, A, B, C, D, E, F, G, W1, 0xefbe4786);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256ROUND(G, H, A, B, C, D, E, F, W2, 0x0fc19dc6);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256ROUND(F, G, H, A, B, C, D, E, W3, 0x240ca1cc);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256ROUND(E, F, G, H, A, B, C, D, W4, 0x2de92c6f);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256ROUND(D, E, F, G, H, A, B, C, W5, 0x4a7484aa);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256ROUND(C, D, E, F, G, H, A, B, W6, 0x5cb0a9dc);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256ROUND(B, C, D, E, F, G, H, A, W7, 0x76f988da);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256ROUND(A, B, C, D, E, F, G, H, W8, 0x983e5152);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256ROUND(H, A, B, C, D, E, F, G, W9, 0xa831c66d);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256ROUND(G, H, A, B, C, D, E, F, W10, 0xb00327c8);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256ROUND(F, G, H, A, B, C, D, E, W11, 0xbf597fc7);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256ROUND(E, F, G, H, A, B, C, D, W12, 0xc6e00bf3);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256ROUND(D, E, F, G, H, A, B, C, W13, 0xd5a79147);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256ROUND(C, D, E, F, G, H, A, B, W14, 0x06ca6351);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256ROUND(B, C, D, E, F, G, H, A, W15, 0x14292967);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256ROUND(A, B, C, D, E, F, G, H, W0, 0x27b70a85);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256ROUND(H, A, B, C, D, E, F, G, W1, 0x2e1b2138);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256ROUND(G, H, A, B, C, D, E, F, W2, 0x4d2c6dfc);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256ROUND(F, G, H, A, B, C, D, E, W3, 0x53380d13);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256ROUND(E, F, G, H, A, B, C, D, W4, 0x650a7354);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256ROUND(D, E, F, G, H, A, B, C, W5, 0x766a0abb);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256ROUND(C, D, E, F, G, H, A, B, W6, 0x81c2c92e);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256ROUND(B, C, D, E, F, G, H, A, W7, 0x92722c85);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256ROUND(A, B, C, D, E, F, G, H, W8, 0xa2bfe8a1);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256ROUND(H, A, B, C, D, E, F, G, W9, 0xa81a664b);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256ROUND(G, H, A, B, C, D, E, F, W10, 0xc24b8b70);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256ROUND(F, G, H, A, B, C, D, E, W11, 0xc76c51a3);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256ROUND(E, F, G, H, A, B, C, D, W12, 0xd192e819);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256ROUND(D, E, F, G, H, A, B, C, W13, 0xd6990624);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256ROUND(C, D, E, F, G, H, A, B, W14, 0xf40e3585);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256ROUND(B, C, D, E, F, G, H, A, W15, 0x106aa070);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256ROUND(A, B, C, D, E, F, G, H, W0, 0x19a4c116);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256ROUND(H, A, B, C, D, E, F, G, W1, 0x1e376c08);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256ROUND(G, H, A, B, C, D, E, F, W2, 0x2748774c);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256ROUND(F, G, H, A, B, C, D, E, W3, 0x34b0bcb5);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256ROUND(E, F, G, H, A, B, C, D, W4, 0x391c0cb3);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256ROUND(D, E, F, G, H, A, B, C, W5, 0x4ed8aa4a);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256ROUND(C, D, E, F, G, H, A, B, W6, 0x5b9cca4f);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256ROUND(B, C, D, E, F, G, H, A, W7, 0x682e6ff3);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256ROUND(A, B, C, D, E, F, G, H, W8, 0x748f82ee);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256ROUND(H, A, B, C, D, E, F, G, W9, 0x78a5636f);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256ROUND(G, H, A, B, C, D, E, F, W10, 0x84c87814);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256ROUND(F, G, H, A, B, C, D, E, W11, 0x8cc70208);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256ROUND(E, F, G, H, A, B, C, D, W12, 0x90befffa);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256ROUND(D, E, F, G, H, A, B, C, W13, 0xa4506ceb);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256ROUND(C, D, E, F, G, H, A, B, W14, 0xbef9a3f7);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256ROUND(B, C, D, E, F, G, H, A, W15, 0xc67178f2);

		Output.H[0] += A;
		Output.H[1] += B;
		Output.H[2] += C;
		Output.H[3] += D;
		Output.H[4] += E;
		Output.H[5] += F;
		Output.H[6] += G;
		Output.H[7] += H;

		Output.T += BLOCK_SIZE;
	}
};

NAMESPACE_DIGESTEND