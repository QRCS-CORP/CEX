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
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

/**
* \internal
*/
class SHA512Compress
{
private:
	static const size_t BLOCK_SIZE = 128;

	inline static ulong BigSigma0(ulong W)
	{
		return ((W << 36) | (W >> 28)) ^ ((W << 30) | (W >> 34)) ^ ((W << 25) | (W >> 39));
	}

	inline static ulong BigSigma1(ulong W)
	{
		return ((W << 50) | (W >> 14)) ^ ((W << 46) | (W >> 18)) ^ ((W << 23) | (W >> 41));
	}

	inline static ulong Ch(ulong B, ulong C, ulong D)
	{
		return (B & C) ^ (~B & D);
	}

	inline static ulong Maj(ulong B, ulong C, ulong D)
	{
		return (B & C) ^ (B & D) ^ (C & D);
	}

	inline static ulong Sigma0(ulong W)
	{
		return ((W << 63) | (W >> 1)) ^ ((W << 56) | (W >> 8)) ^ (W >> 7);
	}

	inline static ulong Sigma1(ulong W)
	{
		return ((W << 45) | (W >> 19)) ^ ((W << 3) | (W >> 61)) ^ (W >> 6);
	}

	#define SHA512ROUND(A, B, C, D, E, F, G, H, M, P)			\
	do {														\
		ulong R0 = H + BigSigma1(E) + Ch(E, F, G) + P + M;		\
		D += R0;												\
		ulong R1 = BigSigma0(A) + Maj(A, B, C);					\
		H = R0 + R1;											\
	} while (0)													\

public:

	template <typename T>
	inline static void Compress128(const std::vector<byte> &Input, size_t InOffset, T &Output)
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
		SHA512ROUND(A, B, C, D, E, F, G, H, W0, 0x428a2f98d728ae22);
		W1 = IntUtils::BeBytesTo64(Input, InOffset + 8);
		SHA512ROUND(H, A, B, C, D, E, F, G, W1, 0x7137449123ef65cd);
		W2 = IntUtils::BeBytesTo64(Input, InOffset + 16);
		SHA512ROUND(G, H, A, B, C, D, E, F, W2, 0xb5c0fbcfec4d3b2f);
		W3 = IntUtils::BeBytesTo64(Input, InOffset + 24);
		SHA512ROUND(F, G, H, A, B, C, D, E, W3, 0xe9b5dba58189dbbc);
		W4 = IntUtils::BeBytesTo64(Input, InOffset + 32);
		SHA512ROUND(E, F, G, H, A, B, C, D, W4, 0x3956c25bf348b538);
		W5 = IntUtils::BeBytesTo64(Input, InOffset + 40);
		SHA512ROUND(D, E, F, G, H, A, B, C, W5, 0x59f111f1b605d019);
		W6 = IntUtils::BeBytesTo64(Input, InOffset + 48);
		SHA512ROUND(C, D, E, F, G, H, A, B, W6, 0x923f82a4af194f9b);
		W7 = IntUtils::BeBytesTo64(Input, InOffset + 56);
		SHA512ROUND(B, C, D, E, F, G, H, A, W7, 0xab1c5ed5da6d8118);
		W8 = IntUtils::BeBytesTo64(Input, InOffset + 64);
		SHA512ROUND(A, B, C, D, E, F, G, H, W8, 0xd807aa98a3030242);
		W9 = IntUtils::BeBytesTo64(Input, InOffset + 72);
		SHA512ROUND(H, A, B, C, D, E, F, G, W9, 0x12835b0145706fbe);
		W10 = IntUtils::BeBytesTo64(Input, InOffset + 80);
		SHA512ROUND(G, H, A, B, C, D, E, F, W10, 0x243185be4ee4b28c);
		W11 = IntUtils::BeBytesTo64(Input, InOffset + 88);
		SHA512ROUND(F, G, H, A, B, C, D, E, W11, 0x550c7dc3d5ffb4e2);
		W12 = IntUtils::BeBytesTo64(Input, InOffset + 96);
		SHA512ROUND(E, F, G, H, A, B, C, D, W12, 0x72be5d74f27b896f);
		W13 = IntUtils::BeBytesTo64(Input, InOffset + 104);
		SHA512ROUND(D, E, F, G, H, A, B, C, W13, 0x80deb1fe3b1696b1);
		W14 = IntUtils::BeBytesTo64(Input, InOffset + 112);
		SHA512ROUND(C, D, E, F, G, H, A, B, W14, 0x9bdc06a725c71235);
		W15 = IntUtils::BeBytesTo64(Input, InOffset + 120);
		SHA512ROUND(B, C, D, E, F, G, H, A, W15, 0xc19bf174cf692694);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA512ROUND(A, B, C, D, E, F, G, H, W0, 0xe49b69c19ef14ad2);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA512ROUND(H, A, B, C, D, E, F, G, W1, 0xefbe4786384f25e3);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA512ROUND(G, H, A, B, C, D, E, F, W2, 0x0fc19dc68b8cd5b5);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA512ROUND(F, G, H, A, B, C, D, E, W3, 0x240ca1cc77ac9c65);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA512ROUND(E, F, G, H, A, B, C, D, W4, 0x2de92c6f592b0275);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA512ROUND(D, E, F, G, H, A, B, C, W5, 0x4a7484aa6ea6e483);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA512ROUND(C, D, E, F, G, H, A, B, W6, 0x5cb0a9dcbd41fbd4);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA512ROUND(B, C, D, E, F, G, H, A, W7, 0x76f988da831153b5);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA512ROUND(A, B, C, D, E, F, G, H, W8, 0x983e5152ee66dfab);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA512ROUND(H, A, B, C, D, E, F, G, W9, 0xa831c66d2db43210);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA512ROUND(G, H, A, B, C, D, E, F, W10, 0xb00327c898fb213f);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA512ROUND(F, G, H, A, B, C, D, E, W11, 0xbf597fc7beef0ee4);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA512ROUND(E, F, G, H, A, B, C, D, W12, 0xc6e00bf33da88fc2);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA512ROUND(D, E, F, G, H, A, B, C, W13, 0xd5a79147930aa725);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA512ROUND(C, D, E, F, G, H, A, B, W14, 0x06ca6351e003826f);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA512ROUND(B, C, D, E, F, G, H, A, W15, 0x142929670a0e6e70);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA512ROUND(A, B, C, D, E, F, G, H, W0, 0x27b70a8546d22ffc);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA512ROUND(H, A, B, C, D, E, F, G, W1, 0x2e1b21385c26c926);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA512ROUND(G, H, A, B, C, D, E, F, W2, 0x4d2c6dfc5ac42aed);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA512ROUND(F, G, H, A, B, C, D, E, W3, 0x53380d139d95b3df);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA512ROUND(E, F, G, H, A, B, C, D, W4, 0x650a73548baf63de);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA512ROUND(D, E, F, G, H, A, B, C, W5, 0x766a0abb3c77b2a8);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA512ROUND(C, D, E, F, G, H, A, B, W6, 0x81c2c92e47edaee6);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA512ROUND(B, C, D, E, F, G, H, A, W7, 0x92722c851482353b);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA512ROUND(A, B, C, D, E, F, G, H, W8, 0xa2bfe8a14cf10364);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA512ROUND(H, A, B, C, D, E, F, G, W9, 0xa81a664bbc423001);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA512ROUND(G, H, A, B, C, D, E, F, W10, 0xc24b8b70d0f89791);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA512ROUND(F, G, H, A, B, C, D, E, W11, 0xc76c51a30654be30);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA512ROUND(E, F, G, H, A, B, C, D, W12, 0xd192e819d6ef5218);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA512ROUND(D, E, F, G, H, A, B, C, W13, 0xd69906245565a910);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA512ROUND(C, D, E, F, G, H, A, B, W14, 0xf40e35855771202a);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA512ROUND(B, C, D, E, F, G, H, A, W15, 0x106aa07032bbd1b8);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA512ROUND(A, B, C, D, E, F, G, H, W0, 0x19a4c116b8d2d0c8);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA512ROUND(H, A, B, C, D, E, F, G, W1, 0x1e376c085141ab53);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA512ROUND(G, H, A, B, C, D, E, F, W2, 0x2748774cdf8eeb99);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA512ROUND(F, G, H, A, B, C, D, E, W3, 0x34b0bcb5e19b48a8);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA512ROUND(E, F, G, H, A, B, C, D, W4, 0x391c0cb3c5c95a63);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA512ROUND(D, E, F, G, H, A, B, C, W5, 0x4ed8aa4ae3418acb);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA512ROUND(C, D, E, F, G, H, A, B, W6, 0x5b9cca4f7763e373);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA512ROUND(B, C, D, E, F, G, H, A, W7, 0x682e6ff3d6b2b8a3);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA512ROUND(A, B, C, D, E, F, G, H, W8, 0x748f82ee5defb2fc);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA512ROUND(H, A, B, C, D, E, F, G, W9, 0x78a5636f43172f60);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA512ROUND(G, H, A, B, C, D, E, F, W10, 0x84c87814a1f0ab72);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA512ROUND(F, G, H, A, B, C, D, E, W11, 0x8cc702081a6439ec);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA512ROUND(E, F, G, H, A, B, C, D, W12, 0x90befffa23631e28);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA512ROUND(D, E, F, G, H, A, B, C, W13, 0xa4506cebde82bde9);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA512ROUND(C, D, E, F, G, H, A, B, W14, 0xbef9a3f7b2c67915);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA512ROUND(B, C, D, E, F, G, H, A, W15, 0xc67178f2e372532b);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA512ROUND(A, B, C, D, E, F, G, H, W0, 0xca273eceea26619c);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA512ROUND(H, A, B, C, D, E, F, G, W1, 0xd186b8c721c0c207);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA512ROUND(G, H, A, B, C, D, E, F, W2, 0xeada7dd6cde0eb1e);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA512ROUND(F, G, H, A, B, C, D, E, W3, 0xf57d4f7fee6ed178);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA512ROUND(E, F, G, H, A, B, C, D, W4, 0x06f067aa72176fba);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA512ROUND(D, E, F, G, H, A, B, C, W5, 0x0a637dc5a2c898a6);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA512ROUND(C, D, E, F, G, H, A, B, W6, 0x113f9804bef90dae);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA512ROUND(B, C, D, E, F, G, H, A, W7, 0x1b710b35131c471b);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA512ROUND(A, B, C, D, E, F, G, H, W8, 0x28db77f523047d84);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA512ROUND(H, A, B, C, D, E, F, G, W9, 0x32caab7b40c72493);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA512ROUND(G, H, A, B, C, D, E, F, W10, 0x3c9ebe0a15c9bebc);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA512ROUND(F, G, H, A, B, C, D, E, W11, 0x431d67c49c100d4c);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA512ROUND(E, F, G, H, A, B, C, D, W12, 0x4cc5d4becb3e42b6);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA512ROUND(D, E, F, G, H, A, B, C, W13, 0x597f299cfc657e2a);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA512ROUND(C, D, E, F, G, H, A, B, W14, 0x5fcb6fab3ad6faec);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA512ROUND(B, C, D, E, F, G, H, A, W15, 0x6c44198c4a475817);

		Output.H[0] += A;
		Output.H[1] += B;
		Output.H[2] += C;
		Output.H[3] += D;
		Output.H[4] += E;
		Output.H[5] += F;
		Output.H[6] += G;
		Output.H[7] += H;

		Output.Increase(BLOCK_SIZE); 
	}
};

NAMESPACE_DIGESTEND