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

#ifndef CEX_SHA2_H
#define CEX_SHA2_H

#include "CexDomain.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class SHA2
{
private:

	template<typename T>
	inline static T Ch(T B, T C, T D)
	{
		return (B & C) ^ (~B & D);
	}

	template<typename T>
	inline static T Maj(T B, T C, T D)
	{
		return (B & C) ^ (B & D) ^ (C & D);
	}

	inline static uint UlBigSigma0(uint W)
	{
		return ((W >> 2) | (W << 30)) ^ ((W >> 13) | (W << 19)) ^ ((W >> 22) | (W << 10));
	}

	inline static uint UlBigSigma1(uint W)
	{
		return ((W >> 6) | (W << 26)) ^ ((W >> 11) | (W << 21)) ^ ((W >> 25) | (W << 7));
	}

	inline static void Round256(uint A, uint B, uint C, uint &D, uint E, uint F, uint G, uint &H, uint M, uint P)
	{
		uint R0(H + UlBigSigma1(E) + Ch(E, F, G) + P + M);
		D += R0;
		H = R0 + (UlBigSigma0(A) + Maj(A, B, C));
	}

	inline static uint UlSigma0(uint W)
	{
		return ((W >> 7) | (W << 25)) ^ ((W >> 18) | (W << 14)) ^ (W >> 3);
	}

	inline static uint UlSigma1(uint W)
	{
		return ((W >> 17) | (W << 15)) ^ ((W >> 19) | (W << 13)) ^ (W >> 10);
	}

	inline static ulong UllBigSigma0(ulong W)
	{
		return ((W << 36) | (W >> 28)) ^ ((W << 30) | (W >> 34)) ^ ((W << 25) | (W >> 39));
	}

	inline static ulong UllBigSigma1(ulong W)
	{
		return ((W << 50) | (W >> 14)) ^ ((W << 46) | (W >> 18)) ^ ((W << 23) | (W >> 41));
	}

	inline static void Round512(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P)
	{
		ulong R0 = H + UllBigSigma1(E) + Ch(E, F, G) + P + M;
		D += R0;
		H = R0 + UllBigSigma0(A) + Maj(A, B, C);
	}

	inline static ulong UllSigma0(ulong W)
	{
		return ((W << 63) | (W >> 1)) ^ ((W << 56) | (W >> 8)) ^ (W >> 7);
	}

	inline static ulong UllSigma1(ulong W)
	{
		return ((W << 45) | (W >> 19)) ^ ((W << 3) | (W >> 61)) ^ (W >> 6);
	}

public:

	template<typename State>
	inline static void Compress64(const std::vector<byte> &Input, size_t InOffset, State &Output)
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
		Round256(A, B, C, D, E, F, G, H, W0, 0x428A2F98UL);
		W1 = IntUtils::BeBytesTo32(Input, InOffset + 4);
		Round256(H, A, B, C, D, E, F, G, W1, 0x71374491UL);
		W2 = IntUtils::BeBytesTo32(Input, InOffset + 8);
		Round256(G, H, A, B, C, D, E, F, W2, 0xB5C0FBCFUL);
		W3 = IntUtils::BeBytesTo32(Input, InOffset + 12);
		Round256(F, G, H, A, B, C, D, E, W3, 0xE9B5DBA5UL);
		W4 = IntUtils::BeBytesTo32(Input, InOffset + 16);
		Round256(E, F, G, H, A, B, C, D, W4, 0x3956C25BUL);
		W5 = IntUtils::BeBytesTo32(Input, InOffset + 20);
		Round256(D, E, F, G, H, A, B, C, W5, 0x59F111F1UL);
		W6 = IntUtils::BeBytesTo32(Input, InOffset + 24);
		Round256(C, D, E, F, G, H, A, B, W6, 0x923F82A4UL);
		W7 = IntUtils::BeBytesTo32(Input, InOffset + 28);
		Round256(B, C, D, E, F, G, H, A, W7, 0xAB1C5ED5UL);
		W8 = IntUtils::BeBytesTo32(Input, InOffset + 32);
		Round256(A, B, C, D, E, F, G, H, W8, 0xD807AA98UL);
		W9 = IntUtils::BeBytesTo32(Input, InOffset + 36);
		Round256(H, A, B, C, D, E, F, G, W9, 0x12835B01UL);
		W10 = IntUtils::BeBytesTo32(Input, InOffset + 40);
		Round256(G, H, A, B, C, D, E, F, W10, 0x243185BEUL);
		W11 = IntUtils::BeBytesTo32(Input, InOffset + 44);
		Round256(F, G, H, A, B, C, D, E, W11, 0x550C7DC3UL);
		W12 = IntUtils::BeBytesTo32(Input, InOffset + 48);
		Round256(E, F, G, H, A, B, C, D, W12, 0x72BE5D74UL);
		W13 = IntUtils::BeBytesTo32(Input, InOffset + 52);
		Round256(D, E, F, G, H, A, B, C, W13, 0x80DEB1FEUL);
		W14 = IntUtils::BeBytesTo32(Input, InOffset + 56);
		Round256(C, D, E, F, G, H, A, B, W14, 0x9BDC06A7UL);
		W15 = IntUtils::BeBytesTo32(Input, InOffset + 60);
		Round256(B, C, D, E, F, G, H, A, W15, 0xC19BF174UL);

		W0 += UlSigma1(W14) + W9 + UlSigma0(W1);
		Round256(A, B, C, D, E, F, G, H, W0, 0xE49B69C1UL);
		W1 += UlSigma1(W15) + W10 + UlSigma0(W2);
		Round256(H, A, B, C, D, E, F, G, W1, 0xEFBE4786UL);
		W2 += UlSigma1(W0) + W11 + UlSigma0(W3);
		Round256(G, H, A, B, C, D, E, F, W2, 0x0FC19DC6UL);
		W3 += UlSigma1(W1) + W12 + UlSigma0(W4);
		Round256(F, G, H, A, B, C, D, E, W3, 0x240CA1CCUL);
		W4 += UlSigma1(W2) + W13 + UlSigma0(W5);
		Round256(E, F, G, H, A, B, C, D, W4, 0x2DE92C6FUL);
		W5 += UlSigma1(W3) + W14 + UlSigma0(W6);
		Round256(D, E, F, G, H, A, B, C, W5, 0x4A7484AAUL);
		W6 += UlSigma1(W4) + W15 + UlSigma0(W7);
		Round256(C, D, E, F, G, H, A, B, W6, 0x5CB0A9DCUL);
		W7 += UlSigma1(W5) + W0 + UlSigma0(W8);
		Round256(B, C, D, E, F, G, H, A, W7, 0x76F988DAUL);
		W8 += UlSigma1(W6) + W1 + UlSigma0(W9);
		Round256(A, B, C, D, E, F, G, H, W8, 0x983E5152UL);
		W9 += UlSigma1(W7) + W2 + UlSigma0(W10);
		Round256(H, A, B, C, D, E, F, G, W9, 0xA831C66DUL);
		W10 += UlSigma1(W8) + W3 + UlSigma0(W11);
		Round256(G, H, A, B, C, D, E, F, W10, 0xB00327C8UL);
		W11 += UlSigma1(W9) + W4 + UlSigma0(W12);
		Round256(F, G, H, A, B, C, D, E, W11, 0xBF597FC7UL);
		W12 += UlSigma1(W10) + W5 + UlSigma0(W13);
		Round256(E, F, G, H, A, B, C, D, W12, 0xC6E00BF3UL);
		W13 += UlSigma1(W11) + W6 + UlSigma0(W14);
		Round256(D, E, F, G, H, A, B, C, W13, 0xD5A79147UL);
		W14 += UlSigma1(W12) + W7 + UlSigma0(W15);
		Round256(C, D, E, F, G, H, A, B, W14, 0x06CA6351UL);
		W15 += UlSigma1(W13) + W8 + UlSigma0(W0);
		Round256(B, C, D, E, F, G, H, A, W15, 0x14292967UL);

		W0 += UlSigma1(W14) + W9 + UlSigma0(W1);
		Round256(A, B, C, D, E, F, G, H, W0, 0x27B70A85UL);
		W1 += UlSigma1(W15) + W10 + UlSigma0(W2);
		Round256(H, A, B, C, D, E, F, G, W1, 0x2E1B2138UL);
		W2 += UlSigma1(W0) + W11 + UlSigma0(W3);
		Round256(G, H, A, B, C, D, E, F, W2, 0x4D2C6DFCUL);
		W3 += UlSigma1(W1) + W12 + UlSigma0(W4);
		Round256(F, G, H, A, B, C, D, E, W3, 0x53380D13UL);
		W4 += UlSigma1(W2) + W13 + UlSigma0(W5);
		Round256(E, F, G, H, A, B, C, D, W4, 0x650A7354UL);
		W5 += UlSigma1(W3) + W14 + UlSigma0(W6);
		Round256(D, E, F, G, H, A, B, C, W5, 0x766A0ABBUL);
		W6 += UlSigma1(W4) + W15 + UlSigma0(W7);
		Round256(C, D, E, F, G, H, A, B, W6, 0x81C2C92EUL);
		W7 += UlSigma1(W5) + W0 + UlSigma0(W8);
		Round256(B, C, D, E, F, G, H, A, W7, 0x92722C85UL);
		W8 += UlSigma1(W6) + W1 + UlSigma0(W9);
		Round256(A, B, C, D, E, F, G, H, W8, 0xA2BFE8A1UL);
		W9 += UlSigma1(W7) + W2 + UlSigma0(W10);
		Round256(H, A, B, C, D, E, F, G, W9, 0xA81A664BUL);
		W10 += UlSigma1(W8) + W3 + UlSigma0(W11);
		Round256(G, H, A, B, C, D, E, F, W10, 0xC24B8B70UL);
		W11 += UlSigma1(W9) + W4 + UlSigma0(W12);
		Round256(F, G, H, A, B, C, D, E, W11, 0xC76C51A3UL);
		W12 += UlSigma1(W10) + W5 + UlSigma0(W13);
		Round256(E, F, G, H, A, B, C, D, W12, 0xD192E819UL);
		W13 += UlSigma1(W11) + W6 + UlSigma0(W14);
		Round256(D, E, F, G, H, A, B, C, W13, 0xD6990624UL);
		W14 += UlSigma1(W12) + W7 + UlSigma0(W15);
		Round256(C, D, E, F, G, H, A, B, W14, 0xF40E3585UL);
		W15 += UlSigma1(W13) + W8 + UlSigma0(W0);
		Round256(B, C, D, E, F, G, H, A, W15, 0x106AA070UL);

		W0 += UlSigma1(W14) + W9 + UlSigma0(W1);
		Round256(A, B, C, D, E, F, G, H, W0, 0x19A4C116UL);
		W1 += UlSigma1(W15) + W10 + UlSigma0(W2);
		Round256(H, A, B, C, D, E, F, G, W1, 0x1E376C08UL);
		W2 += UlSigma1(W0) + W11 + UlSigma0(W3);
		Round256(G, H, A, B, C, D, E, F, W2, 0x2748774CUL);
		W3 += UlSigma1(W1) + W12 + UlSigma0(W4);
		Round256(F, G, H, A, B, C, D, E, W3, 0x34B0BCB5UL);
		W4 += UlSigma1(W2) + W13 + UlSigma0(W5);
		Round256(E, F, G, H, A, B, C, D, W4, 0x391C0CB3UL);
		W5 += UlSigma1(W3) + W14 + UlSigma0(W6);
		Round256(D, E, F, G, H, A, B, C, W5, 0x4ED8AA4AUL);
		W6 += UlSigma1(W4) + W15 + UlSigma0(W7);
		Round256(C, D, E, F, G, H, A, B, W6, 0x5B9CCA4FUL);
		W7 += UlSigma1(W5) + W0 + UlSigma0(W8);
		Round256(B, C, D, E, F, G, H, A, W7, 0x682E6FF3UL);
		W8 += UlSigma1(W6) + W1 + UlSigma0(W9);
		Round256(A, B, C, D, E, F, G, H, W8, 0x748F82EEUL);
		W9 += UlSigma1(W7) + W2 + UlSigma0(W10);
		Round256(H, A, B, C, D, E, F, G, W9, 0x78A5636FUL);
		W10 += UlSigma1(W8) + W3 + UlSigma0(W11);
		Round256(G, H, A, B, C, D, E, F, W10, 0x84C87814UL);
		W11 += UlSigma1(W9) + W4 + UlSigma0(W12);
		Round256(F, G, H, A, B, C, D, E, W11, 0x8CC70208UL);
		W12 += UlSigma1(W10) + W5 + UlSigma0(W13);
		Round256(E, F, G, H, A, B, C, D, W12, 0x90BEFFFAUL);
		W13 += UlSigma1(W11) + W6 + UlSigma0(W14);
		Round256(D, E, F, G, H, A, B, C, W13, 0xA4506CEBUL);
		W14 += UlSigma1(W12) + W7 + UlSigma0(W15);
		Round256(C, D, E, F, G, H, A, B, W14, 0xBEF9A3F7UL);
		W15 += UlSigma1(W13) + W8 + UlSigma0(W0);
		Round256(B, C, D, E, F, G, H, A, W15, 0xC67178F2UL);

		Output.H[0] += A;
		Output.H[1] += B;
		Output.H[2] += C;
		Output.H[3] += D;
		Output.H[4] += E;
		Output.H[5] += F;
		Output.H[6] += G;
		Output.H[7] += H;

		Output.Increase(64);
	}

	template<typename State>
	inline static void Compress64W(const std::vector<byte> &Input, size_t InOffset, State &Output)
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

		T0 = S0; // Save current state
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

		Output.Increase(128);
#else
		Compress64(Input, InOffset, Output);
#endif
	}

	template<typename State>
	inline static void Compress128(const std::vector<byte> &Input, size_t InOffset, State &Output)
	{
		ulong A = Output.H[0];
		ulong B = Output.H[1];
		ulong C = Output.H[2];
		ulong D = Output.H[3];
		ulong E = Output.H[4];
		ulong F = Output.H[5];
		ulong G = Output.H[6];
		ulong H = Output.H[7];
		ulong W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

		W0 = IntUtils::BeBytesTo64(Input, InOffset);
		Round512(A, B, C, D, E, F, G, H, W0, 0x428A2F98D728AE22ULL);
		W1 = IntUtils::BeBytesTo64(Input, InOffset + 8);
		Round512(H, A, B, C, D, E, F, G, W1, 0x7137449123EF65CDULL);
		W2 = IntUtils::BeBytesTo64(Input, InOffset + 16);
		Round512(G, H, A, B, C, D, E, F, W2, 0xB5C0FBCFEC4D3B2FULL);
		W3 = IntUtils::BeBytesTo64(Input, InOffset + 24);
		Round512(F, G, H, A, B, C, D, E, W3, 0xE9B5DBA58189DBBCULL);
		W4 = IntUtils::BeBytesTo64(Input, InOffset + 32);
		Round512(E, F, G, H, A, B, C, D, W4, 0x3956C25BF348B538ULL);
		W5 = IntUtils::BeBytesTo64(Input, InOffset + 40);
		Round512(D, E, F, G, H, A, B, C, W5, 0x59F111F1B605D019ULL);
		W6 = IntUtils::BeBytesTo64(Input, InOffset + 48);
		Round512(C, D, E, F, G, H, A, B, W6, 0x923F82A4AF194F9BULL);
		W7 = IntUtils::BeBytesTo64(Input, InOffset + 56);
		Round512(B, C, D, E, F, G, H, A, W7, 0xAB1C5ED5DA6D8118ULL);
		W8 = IntUtils::BeBytesTo64(Input, InOffset + 64);
		Round512(A, B, C, D, E, F, G, H, W8, 0xD807AA98A3030242ULL);
		W9 = IntUtils::BeBytesTo64(Input, InOffset + 72);
		Round512(H, A, B, C, D, E, F, G, W9, 0x12835B0145706FBEULL);
		W10 = IntUtils::BeBytesTo64(Input, InOffset + 80);
		Round512(G, H, A, B, C, D, E, F, W10, 0x243185BE4EE4B28CULL);
		W11 = IntUtils::BeBytesTo64(Input, InOffset + 88);
		Round512(F, G, H, A, B, C, D, E, W11, 0x550C7DC3D5FFB4E2ULL);
		W12 = IntUtils::BeBytesTo64(Input, InOffset + 96);
		Round512(E, F, G, H, A, B, C, D, W12, 0x72BE5D74F27B896FULL);
		W13 = IntUtils::BeBytesTo64(Input, InOffset + 104);
		Round512(D, E, F, G, H, A, B, C, W13, 0x80DEB1FE3B1696B1ULL);
		W14 = IntUtils::BeBytesTo64(Input, InOffset + 112);
		Round512(C, D, E, F, G, H, A, B, W14, 0x9BDC06A725C71235ULL);
		W15 = IntUtils::BeBytesTo64(Input, InOffset + 120);
		Round512(B, C, D, E, F, G, H, A, W15, 0xC19BF174CF692694ULL);

		W0 += UllSigma1(W14) + W9 + UllSigma0(W1);
		Round512(A, B, C, D, E, F, G, H, W0, 0xE49B69C19EF14AD2ULL);
		W1 += UllSigma1(W15) + W10 + UllSigma0(W2);
		Round512(H, A, B, C, D, E, F, G, W1, 0xEFBE4786384F25E3ULL);
		W2 += UllSigma1(W0) + W11 + UllSigma0(W3);
		Round512(G, H, A, B, C, D, E, F, W2, 0x0FC19DC68B8CD5B5ULL);
		W3 += UllSigma1(W1) + W12 + UllSigma0(W4);
		Round512(F, G, H, A, B, C, D, E, W3, 0x240CA1CC77AC9C65ULL);
		W4 += UllSigma1(W2) + W13 + UllSigma0(W5);
		Round512(E, F, G, H, A, B, C, D, W4, 0x2DE92C6F592B0275ULL);
		W5 += UllSigma1(W3) + W14 + UllSigma0(W6);
		Round512(D, E, F, G, H, A, B, C, W5, 0x4A7484AA6EA6E483ULL);
		W6 += UllSigma1(W4) + W15 + UllSigma0(W7);
		Round512(C, D, E, F, G, H, A, B, W6, 0x5CB0A9DCBD41FBD4ULL);
		W7 += UllSigma1(W5) + W0 + UllSigma0(W8);
		Round512(B, C, D, E, F, G, H, A, W7, 0x76F988DA831153B5ULL);
		W8 += UllSigma1(W6) + W1 + UllSigma0(W9);
		Round512(A, B, C, D, E, F, G, H, W8, 0x983E5152EE66DFABULL);
		W9 += UllSigma1(W7) + W2 + UllSigma0(W10);
		Round512(H, A, B, C, D, E, F, G, W9, 0xA831C66D2DB43210ULL);
		W10 += UllSigma1(W8) + W3 + UllSigma0(W11);
		Round512(G, H, A, B, C, D, E, F, W10, 0xB00327C898FB213FULL);
		W11 += UllSigma1(W9) + W4 + UllSigma0(W12);
		Round512(F, G, H, A, B, C, D, E, W11, 0xBF597FC7BEEF0EE4ULL);
		W12 += UllSigma1(W10) + W5 + UllSigma0(W13);
		Round512(E, F, G, H, A, B, C, D, W12, 0xC6E00BF33DA88FC2ULL);
		W13 += UllSigma1(W11) + W6 + UllSigma0(W14);
		Round512(D, E, F, G, H, A, B, C, W13, 0xD5A79147930AA725ULL);
		W14 += UllSigma1(W12) + W7 + UllSigma0(W15);
		Round512(C, D, E, F, G, H, A, B, W14, 0x06CA6351E003826FULL);
		W15 += UllSigma1(W13) + W8 + UllSigma0(W0);
		Round512(B, C, D, E, F, G, H, A, W15, 0x142929670A0E6E70ULL);

		W0 += UllSigma1(W14) + W9 + UllSigma0(W1);
		Round512(A, B, C, D, E, F, G, H, W0, 0x27B70A8546D22FFCULL);
		W1 += UllSigma1(W15) + W10 + UllSigma0(W2);
		Round512(H, A, B, C, D, E, F, G, W1, 0x2E1B21385C26C926ULL);
		W2 += UllSigma1(W0) + W11 + UllSigma0(W3);
		Round512(G, H, A, B, C, D, E, F, W2, 0x4D2C6DFC5AC42AEDULL);
		W3 += UllSigma1(W1) + W12 + UllSigma0(W4);
		Round512(F, G, H, A, B, C, D, E, W3, 0x53380D139D95B3DFULL);
		W4 += UllSigma1(W2) + W13 + UllSigma0(W5);
		Round512(E, F, G, H, A, B, C, D, W4, 0x650A73548BAF63DEULL);
		W5 += UllSigma1(W3) + W14 + UllSigma0(W6);
		Round512(D, E, F, G, H, A, B, C, W5, 0x766A0ABB3C77B2A8ULL);
		W6 += UllSigma1(W4) + W15 + UllSigma0(W7);
		Round512(C, D, E, F, G, H, A, B, W6, 0x81C2C92E47EDAEE6ULL);
		W7 += UllSigma1(W5) + W0 + UllSigma0(W8);
		Round512(B, C, D, E, F, G, H, A, W7, 0x92722C851482353BULL);
		W8 += UllSigma1(W6) + W1 + UllSigma0(W9);
		Round512(A, B, C, D, E, F, G, H, W8, 0xA2BFE8A14CF10364ULL);
		W9 += UllSigma1(W7) + W2 + UllSigma0(W10);
		Round512(H, A, B, C, D, E, F, G, W9, 0xA81A664BBC423001ULL);
		W10 += UllSigma1(W8) + W3 + UllSigma0(W11);
		Round512(G, H, A, B, C, D, E, F, W10, 0xC24B8B70D0F89791ULL);
		W11 += UllSigma1(W9) + W4 + UllSigma0(W12);
		Round512(F, G, H, A, B, C, D, E, W11, 0xC76C51A30654BE30ULL);
		W12 += UllSigma1(W10) + W5 + UllSigma0(W13);
		Round512(E, F, G, H, A, B, C, D, W12, 0xD192E819D6EF5218ULL);
		W13 += UllSigma1(W11) + W6 + UllSigma0(W14);
		Round512(D, E, F, G, H, A, B, C, W13, 0xD69906245565A910ULL);
		W14 += UllSigma1(W12) + W7 + UllSigma0(W15);
		Round512(C, D, E, F, G, H, A, B, W14, 0xF40E35855771202AULL);
		W15 += UllSigma1(W13) + W8 + UllSigma0(W0);
		Round512(B, C, D, E, F, G, H, A, W15, 0x106AA07032BBD1B8ULL);

		W0 += UllSigma1(W14) + W9 + UllSigma0(W1);
		Round512(A, B, C, D, E, F, G, H, W0, 0x19A4C116B8D2D0C8ULL);
		W1 += UllSigma1(W15) + W10 + UllSigma0(W2);
		Round512(H, A, B, C, D, E, F, G, W1, 0x1E376C085141AB53ULL);
		W2 += UllSigma1(W0) + W11 + UllSigma0(W3);
		Round512(G, H, A, B, C, D, E, F, W2, 0x2748774CDF8EEB99ULL);
		W3 += UllSigma1(W1) + W12 + UllSigma0(W4);
		Round512(F, G, H, A, B, C, D, E, W3, 0x34B0BCB5E19B48A8ULL);
		W4 += UllSigma1(W2) + W13 + UllSigma0(W5);
		Round512(E, F, G, H, A, B, C, D, W4, 0x391C0CB3C5C95A63ULL);
		W5 += UllSigma1(W3) + W14 + UllSigma0(W6);
		Round512(D, E, F, G, H, A, B, C, W5, 0x4ED8AA4AE3418ACBULL);
		W6 += UllSigma1(W4) + W15 + UllSigma0(W7);
		Round512(C, D, E, F, G, H, A, B, W6, 0x5B9CCA4F7763E373ULL);
		W7 += UllSigma1(W5) + W0 + UllSigma0(W8);
		Round512(B, C, D, E, F, G, H, A, W7, 0x682E6FF3D6B2B8A3ULL);
		W8 += UllSigma1(W6) + W1 + UllSigma0(W9);
		Round512(A, B, C, D, E, F, G, H, W8, 0x748F82EE5DEFB2FCULL);
		W9 += UllSigma1(W7) + W2 + UllSigma0(W10);
		Round512(H, A, B, C, D, E, F, G, W9, 0x78A5636F43172F60ULL);
		W10 += UllSigma1(W8) + W3 + UllSigma0(W11);
		Round512(G, H, A, B, C, D, E, F, W10, 0x84C87814A1F0AB72ULL);
		W11 += UllSigma1(W9) + W4 + UllSigma0(W12);
		Round512(F, G, H, A, B, C, D, E, W11, 0x8CC702081A6439ECULL);
		W12 += UllSigma1(W10) + W5 + UllSigma0(W13);
		Round512(E, F, G, H, A, B, C, D, W12, 0x90BEFFFA23631E28ULL);
		W13 += UllSigma1(W11) + W6 + UllSigma0(W14);
		Round512(D, E, F, G, H, A, B, C, W13, 0xA4506CEBDE82BDE9ULL);
		W14 += UllSigma1(W12) + W7 + UllSigma0(W15);
		Round512(C, D, E, F, G, H, A, B, W14, 0xBEF9A3F7B2C67915ULL);
		W15 += UllSigma1(W13) + W8 + UllSigma0(W0);
		Round512(B, C, D, E, F, G, H, A, W15, 0xC67178F2E372532BULL);

		W0 += UllSigma1(W14) + W9 + UllSigma0(W1);
		Round512(A, B, C, D, E, F, G, H, W0, 0xCA273ECEEA26619CULL);
		W1 += UllSigma1(W15) + W10 + UllSigma0(W2);
		Round512(H, A, B, C, D, E, F, G, W1, 0xD186B8C721C0C207ULL);
		W2 += UllSigma1(W0) + W11 + UllSigma0(W3);
		Round512(G, H, A, B, C, D, E, F, W2, 0xEADA7DD6CDE0EB1EULL);
		W3 += UllSigma1(W1) + W12 + UllSigma0(W4);
		Round512(F, G, H, A, B, C, D, E, W3, 0xF57D4F7FEE6ED178ULL);
		W4 += UllSigma1(W2) + W13 + UllSigma0(W5);
		Round512(E, F, G, H, A, B, C, D, W4, 0x06F067AA72176FBAULL);
		W5 += UllSigma1(W3) + W14 + UllSigma0(W6);
		Round512(D, E, F, G, H, A, B, C, W5, 0x0A637DC5A2C898A6ULL);
		W6 += UllSigma1(W4) + W15 + UllSigma0(W7);
		Round512(C, D, E, F, G, H, A, B, W6, 0x113F9804BEF90DAEULL);
		W7 += UllSigma1(W5) + W0 + UllSigma0(W8);
		Round512(B, C, D, E, F, G, H, A, W7, 0x1B710B35131C471BULL);
		W8 += UllSigma1(W6) + W1 + UllSigma0(W9);
		Round512(A, B, C, D, E, F, G, H, W8, 0x28DB77F523047D84ULL);
		W9 += UllSigma1(W7) + W2 + UllSigma0(W10);
		Round512(H, A, B, C, D, E, F, G, W9, 0x32CAAB7B40C72493ULL);
		W10 += UllSigma1(W8) + W3 + UllSigma0(W11);
		Round512(G, H, A, B, C, D, E, F, W10, 0x3C9EBE0A15C9BEBCULL);
		W11 += UllSigma1(W9) + W4 + UllSigma0(W12);
		Round512(F, G, H, A, B, C, D, E, W11, 0x431D67C49C100D4CULL);
		W12 += UllSigma1(W10) + W5 + UllSigma0(W13);
		Round512(E, F, G, H, A, B, C, D, W12, 0x4CC5D4BECB3E42B6ULL);
		W13 += UllSigma1(W11) + W6 + UllSigma0(W14);
		Round512(D, E, F, G, H, A, B, C, W13, 0x597F299CFC657E2AULL);
		W14 += UllSigma1(W12) + W7 + UllSigma0(W15);
		Round512(C, D, E, F, G, H, A, B, W14, 0x5FCB6FAB3AD6FAECULL);
		W15 += UllSigma1(W13) + W8 + UllSigma0(W0);
		Round512(B, C, D, E, F, G, H, A, W15, 0x6C44198C4A475817ULL);

		Output.H[0] += A;
		Output.H[1] += B;
		Output.H[2] += C;
		Output.H[3] += D;
		Output.H[4] += E;
		Output.H[5] += F;
		Output.H[6] += G;
		Output.H[7] += H;

		Output.Increase(128);
	}
};

NAMESPACE_DIGESTEND
#endif
