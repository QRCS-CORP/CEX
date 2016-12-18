// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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

#include "CexDomain.h"
#include "IntUtils.h"
#if defined(CEX_HAS_AVX)
#	include "UInt256.h"
#endif

NAMESPACE_DIGEST

using Utility::IntUtils;
#if defined(CEX_HAS_AVX)
	using Numeric::UInt256;
#endif

/// <summary>
/// The SHA256 compression class
/// </summary> 
class SHA256Compress
{
private:
	static const size_t BLOCK_SIZE = 64;

	template <typename T>
	static inline T BigSigma0(T &W)
	{
		return ((W >> 2) | (W << 30)) ^ ((W >> 13) | (W << 19)) ^ ((W >> 22) | (W << 10));
	}

	template <typename T>
	static inline T BigSigma1(T &W)
	{
		return ((W >> 6) | (W << 26)) ^ ((W >> 11) | (W << 21)) ^ ((W >> 25) | (W << 7));
	}

	template <typename T>
	static inline T Ch(T &B, T &C, T &D)
	{
		return (B & C) ^ (~B & D);
	}

	template <typename T>
	static inline T Maj(T &B, T &C, T &D)
	{
		return (B & C) ^ (B & D) ^ (C & D);
	}

	template <typename T>
	static inline T Sigma0(T &W)
	{
		return ((W >> 7) | (W << 25)) ^ ((W >> 18) | (W << 14)) ^ (W >> 3);
	}

	template <typename T>
	static inline T Sigma1(T &W)
	{
		return ((W >> 17) | (W << 15)) ^ ((W >> 19) | (W << 13)) ^ (W >> 10);
	}

	template <typename T>
	static inline void SHA256Round(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, uint P)
	{
		T R0(H + BigSigma1(E) + Ch(E, F, G) + T(P) + M);
		D += R0;
		T R1(BigSigma0(A) + Maj(A, B, C));
		H = R0 + R1;
	}

	template <typename T, typename R>
	static inline void ShuffleLoad32(std::vector<T> &Input, size_t InOffset, size_t Index, R &W)
	{
		W.LoadLE(
			Input[InOffset].H[Index], 
			Input[InOffset + 1].H[Index], 
			Input[InOffset + 2].H[Index], 
			Input[InOffset + 3].H[Index],
			Input[InOffset + 4].H[Index],
			Input[InOffset + 5].H[Index],
			Input[InOffset + 6].H[Index],
			Input[InOffset + 7].H[Index]
		);
	}

	template <typename T, typename R>
	static inline void ShuffleStore32(R &W, std::vector<T> &Output, size_t OutOffset, size_t Index)
	{
		std::vector<uint> tmp(8);
		W.StoreLE(tmp, 0);

		Output[OutOffset].H[Index] = tmp[0];
		Output[OutOffset + 1].H[Index] = tmp[1];
		Output[OutOffset + 2].H[Index] = tmp[2];
		Output[OutOffset + 3].H[Index] = tmp[3];
		Output[OutOffset + 4].H[Index] = tmp[4];
		Output[OutOffset + 5].H[Index] = tmp[5];
		Output[OutOffset + 6].H[Index] = tmp[6];
		Output[OutOffset + 7].H[Index] = tmp[7];
	}

public:

	template <typename T>
	static inline void Compress64(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
		uint A = Output[OutOffset].H[0];
		uint B = Output[OutOffset].H[1];
		uint C = Output[OutOffset].H[2];
		uint D = Output[OutOffset].H[3];
		uint E = Output[OutOffset].H[4];
		uint F = Output[OutOffset].H[5];
		uint G = Output[OutOffset].H[6];
		uint H = Output[OutOffset].H[7];
		uint W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

		W0 = IntUtils::BytesToBe32(Input, InOffset);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x428a2f98);
		W1 = IntUtils::BytesToBe32(Input, InOffset + 4);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x71374491);
		W2 = IntUtils::BytesToBe32(Input, InOffset + 8);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0xb5c0fbcf);
		W3 = IntUtils::BytesToBe32(Input, InOffset + 12);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0xe9b5dba5);
		W4 = IntUtils::BytesToBe32(Input, InOffset + 16);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x3956c25b);
		W5 = IntUtils::BytesToBe32(Input, InOffset + 20);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x59f111f1);
		W6 = IntUtils::BytesToBe32(Input, InOffset + 24);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x923f82a4);
		W7 = IntUtils::BytesToBe32(Input, InOffset + 28);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0xab1c5ed5);
		W8 = IntUtils::BytesToBe32(Input, InOffset + 32);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0xd807aa98);
		W9 = IntUtils::BytesToBe32(Input, InOffset + 36);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0x12835b01);
		W10 = IntUtils::BytesToBe32(Input, InOffset + 40);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0x243185be);
		W11 = IntUtils::BytesToBe32(Input, InOffset + 44);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0x550c7dc3);
		W12 = IntUtils::BytesToBe32(Input, InOffset + 48);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0x72be5d74);
		W13 = IntUtils::BytesToBe32(Input, InOffset + 52);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0x80deb1fe);
		W14 = IntUtils::BytesToBe32(Input, InOffset + 56);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0x9bdc06a7);
		W15 = IntUtils::BytesToBe32(Input, InOffset + 60);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0xc19bf174);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0xe49b69c1);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0xefbe4786);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x0fc19dc6);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x240ca1cc);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x2de92c6f);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x4a7484aa);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x5cb0a9dc);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x76f988da);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0x983e5152);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0xa831c66d);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0xb00327c8);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0xbf597fc7);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0xc6e00bf3);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xd5a79147);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0x06ca6351);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0x14292967);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x27b70a85);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x2e1b2138);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x4d2c6dfc);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x53380d13);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x650a7354);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x766a0abb);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x81c2c92e);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x92722c85);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0xa2bfe8a1);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0xa81a664b);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0xc24b8b70);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0xc76c51a3);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0xd192e819);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xd6990624);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0xf40e3585);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0x106aa070);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x19a4c116);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x1e376c08);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x2748774c);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x34b0bcb5);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x391c0cb3);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x4ed8aa4a);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x5b9cca4f);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x682e6ff3);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0x748f82ee);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0x78a5636f);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0x84c87814);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0x8cc70208);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0x90befffa);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xa4506ceb);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0xbef9a3f7);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0xc67178f2);

		Output[OutOffset].H[0] += A;
		Output[OutOffset].H[1] += B;
		Output[OutOffset].H[2] += C;
		Output[OutOffset].H[3] += D;
		Output[OutOffset].H[4] += E;
		Output[OutOffset].H[5] += F;
		Output[OutOffset].H[6] += G;
		Output[OutOffset].H[7] += H;

		Output[OutOffset].T += BLOCK_SIZE;
	}

	template <typename T>
	static inline void Compress512(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
	{
#if defined(CEX_HAS_AVX)

		UInt256 A, B, C, D, E, F, G, H;
		ShuffleLoad32(Output, OutOffset, 0, A);
		ShuffleLoad32(Output, OutOffset, 1, B);
		ShuffleLoad32(Output, OutOffset, 2, C);
		ShuffleLoad32(Output, OutOffset, 3, D);
		ShuffleLoad32(Output, OutOffset, 4, E);
		ShuffleLoad32(Output, OutOffset, 5, F);
		ShuffleLoad32(Output, OutOffset, 6, G);
		ShuffleLoad32(Output, OutOffset, 7, H);

		UInt256 H0 = A, H1 = B, H2 = C, H3 = D, H4 = E, H5 = F, H6 = G, H7 = H;
		UInt256 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
		;
		W0 = UInt256::ShuffleLoadBE(Input, InOffset, 64);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x428a2f98);
		W1 = UInt256::ShuffleLoadBE(Input, InOffset + 4, 64);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x71374491);
		W2 = UInt256::ShuffleLoadBE(Input, InOffset + 8, 64);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0xb5c0fbcf);
		W3 = UInt256::ShuffleLoadBE(Input, InOffset + 12, 64);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0xe9b5dba5);
		W4 = UInt256::ShuffleLoadBE(Input, InOffset + 16, 64);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x3956c25b);
		W5 = UInt256::ShuffleLoadBE(Input, InOffset + 20, 64);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x59f111f1);
		W6 = UInt256::ShuffleLoadBE(Input, InOffset + 24, 64);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x923f82a4);
		W7 = UInt256::ShuffleLoadBE(Input, InOffset + 28, 64);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0xab1c5ed5);
		W8 = UInt256::ShuffleLoadBE(Input, InOffset + 32, 64);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0xd807aa98);
		W9 = UInt256::ShuffleLoadBE(Input, InOffset + 36, 64);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0x12835b01);
		W10 = UInt256::ShuffleLoadBE(Input, InOffset + 40, 64);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0x243185be);
		W11 = UInt256::ShuffleLoadBE(Input, InOffset + 44, 64);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0x550c7dc3);
		W12 = UInt256::ShuffleLoadBE(Input, InOffset + 48, 64);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0x72be5d74);
		W13 = UInt256::ShuffleLoadBE(Input, InOffset + 52, 64);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0x80deb1fe);
		W14 = UInt256::ShuffleLoadBE(Input, InOffset + 56, 64);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0x9bdc06a7);
		W15 = UInt256::ShuffleLoadBE(Input, InOffset + 60, 64);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0xc19bf174);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0xe49b69c1);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0xefbe4786);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x0fc19dc6);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x240ca1cc);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x2de92c6f);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x4a7484aa);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x5cb0a9dc);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x76f988da);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0x983e5152);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0xa831c66d);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0xb00327c8);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0xbf597fc7);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0xc6e00bf3);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xd5a79147);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0x06ca6351);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0x14292967);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x27b70a85);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x2e1b2138);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x4d2c6dfc);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x53380d13);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x650a7354);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x766a0abb);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x81c2c92e);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x92722c85);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0xa2bfe8a1);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0xa81a664b);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0xc24b8b70);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0xc76c51a3);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0xd192e819);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xd6990624);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0xf40e3585);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0x106aa070);

		W0 += Sigma1(W14) + W9 + Sigma0(W1);
		SHA256Round(A, B, C, D, E, F, G, H, W0, 0x19a4c116);
		W1 += Sigma1(W15) + W10 + Sigma0(W2);
		SHA256Round(H, A, B, C, D, E, F, G, W1, 0x1e376c08);
		W2 += Sigma1(W0) + W11 + Sigma0(W3);
		SHA256Round(G, H, A, B, C, D, E, F, W2, 0x2748774c);
		W3 += Sigma1(W1) + W12 + Sigma0(W4);
		SHA256Round(F, G, H, A, B, C, D, E, W3, 0x34b0bcb5);
		W4 += Sigma1(W2) + W13 + Sigma0(W5);
		SHA256Round(E, F, G, H, A, B, C, D, W4, 0x391c0cb3);
		W5 += Sigma1(W3) + W14 + Sigma0(W6);
		SHA256Round(D, E, F, G, H, A, B, C, W5, 0x4ed8aa4a);
		W6 += Sigma1(W4) + W15 + Sigma0(W7);
		SHA256Round(C, D, E, F, G, H, A, B, W6, 0x5b9cca4f);
		W7 += Sigma1(W5) + W0 + Sigma0(W8);
		SHA256Round(B, C, D, E, F, G, H, A, W7, 0x682e6ff3);
		W8 += Sigma1(W6) + W1 + Sigma0(W9);
		SHA256Round(A, B, C, D, E, F, G, H, W8, 0x748f82ee);
		W9 += Sigma1(W7) + W2 + Sigma0(W10);
		SHA256Round(H, A, B, C, D, E, F, G, W9, 0x78a5636f);
		W10 += Sigma1(W8) + W3 + Sigma0(W11);
		SHA256Round(G, H, A, B, C, D, E, F, W10, 0x84c87814);
		W11 += Sigma1(W9) + W4 + Sigma0(W12);
		SHA256Round(F, G, H, A, B, C, D, E, W11, 0x8cc70208);
		W12 += Sigma1(W10) + W5 + Sigma0(W13);
		SHA256Round(E, F, G, H, A, B, C, D, W12, 0x90befffa);
		W13 += Sigma1(W11) + W6 + Sigma0(W14);
		SHA256Round(D, E, F, G, H, A, B, C, W13, 0xa4506ceb);
		W14 += Sigma1(W12) + W7 + Sigma0(W15);
		SHA256Round(C, D, E, F, G, H, A, B, W14, 0xbef9a3f7);
		W15 += Sigma1(W13) + W8 + Sigma0(W0);
		SHA256Round(B, C, D, E, F, G, H, A, W15, 0xc67178f2);

		A += H0;
		B += H1;
		C += H2;
		D += H3;
		E += H4;
		F += H5;
		G += H6;
		H += H7;

		ShuffleStore32(A, Output, OutOffset, 0);
		ShuffleStore32(B, Output, OutOffset, 1);
		ShuffleStore32(C, Output, OutOffset, 2);
		ShuffleStore32(D, Output, OutOffset, 3);
		ShuffleStore32(E, Output, OutOffset, 4);
		ShuffleStore32(F, Output, OutOffset, 5);
		ShuffleStore32(G, Output, OutOffset, 6);
		ShuffleStore32(H, Output, OutOffset, 7);

		Output[OutOffset].T += BLOCK_SIZE;
		Output[OutOffset + 1].T += BLOCK_SIZE;
		Output[OutOffset + 2].T += BLOCK_SIZE;
		Output[OutOffset + 3].T += BLOCK_SIZE;
		Output[OutOffset + 4].T += BLOCK_SIZE;
		Output[OutOffset + 5].T += BLOCK_SIZE;
		Output[OutOffset + 6].T += BLOCK_SIZE;
		Output[OutOffset + 7].T += BLOCK_SIZE;

#else

		Compress64(Input, InOffset, Output, OutOffset);
		Compress64(Input, InOffset + 64, Output, OutOffset + 1);
		Compress64(Input, InOffset + 128, Output, OutOffset + 2);
		Compress64(Input, InOffset + 192, Output, OutOffset + 3);
		Compress64(Input, InOffset + 256, Output, OutOffset + 4);
		Compress64(Input, InOffset + 320, Output, OutOffset + 5);
		Compress64(Input, InOffset + 384, Output, OutOffset + 6);
		Compress64(Input, InOffset + 448, Output, OutOffset + 7);

#endif
	}
};

NAMESPACE_DIGESTEND