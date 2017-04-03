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

#ifndef _CEX_THREEFISH512_H
#define _CEX_THREEFISH512_H

#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/**
* \internal
*/
class Threefish512
{
private:

	static const size_t BLOCK_SIZE = 64;

	static ulong GetParity(const std::vector<ulong> &Key)
	{
		ulong parity = 0x1BD11BDAA9FC1A22;

		for (size_t i = 0; i < Key.size(); i++)
			parity ^= Key[i];

		return parity;
	}

	static inline void Inject(ulong &A, ulong &B, uint R, ulong K0, ulong K1)
	{
		B += K1;
		A += B + K0;
		B = Utility::IntUtils::RotL64(B, R) ^ A;
	}

	static inline void Mix(ulong &A, ulong &B, uint R)
	{
		A += B;
		B = Utility::IntUtils::RotL64(B, R) ^ A;
	}

	static inline void Interleave64(__m256i &X0, __m256i &X1)
	{
		const __m256i T0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3, 1, 2, 0));
		const __m256i T1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3, 1, 2, 0));

		X0 = _mm256_unpacklo_epi64(T0, T1);
		X1 = _mm256_unpackhi_epi64(T0, T1);
	}

#define TF512ROUND(X0, X1, SHL)														\
   do {                                                                             \
      const __m256i SHR = _mm256_sub_epi64(_mm256_set1_epi64x(64), SHL);            \
      X0 = _mm256_add_epi64(X0, X1);                                                \
      X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, SHL), _mm256_srlv_epi64(X1, SHR)); \
      X1 = _mm256_xor_si256(X1, X0);                                                \
      X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(0, 3, 2, 1));                   \
      X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));                   \
   } while(0)

#define TF512INJECTKEY(X0, X1, R0, K0, K1, I0, I1)									\
   do {																				\
      const __m256i T0 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(I0, 0, 0, 0));		\
      const __m256i T1 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, I1, 0, 0));		\
      X0 = _mm256_add_epi64(X0, K0);												\
      X1 = _mm256_add_epi64(X1, K1);												\
      X1 = _mm256_add_epi64(X1, R0);												\
      X0 = _mm256_add_epi64(X0, T0);												\
      X1 = _mm256_add_epi64(X1, T1);												\
      R0 = _mm256_add_epi64(R0, RFN);												\
   } while(0)

#define TF512ENC8ROUNDS(X0, X1, R0, K1, K2, K3, T0, T1, T2)			\
   do {																\
      TF512ROUND(X0, X1, R1);										\
      TF512ROUND(X0, X1, R2);										\
      TF512ROUND(X0, X1, R3);										\
      TF512ROUND(X0, X1, R4);										\
      TF512INJECTKEY(X0, X1, R0, K1, K2, T0, T1);					\
      TF512ROUND(X0, X1, R5);										\
      TF512ROUND(X0, X1, R6);										\
      TF512ROUND(X0, X1, R7);										\
      TF512ROUND(X0, X1, R8);										\
      TF512INJECTKEY(X0, X1, R0, K2, K3, T2, T0);					\
   } while(0)

public:

	template <typename T>
	static void Transfrom64W(std::vector<ulong> &Input, size_t InOffset, T &Output)
	{
		__m256i R0 = _mm256_set_epi64x(0, 0, 0, 0);
		const __m256i R1 = _mm256_set_epi64x(37, 19, 36, 46);
		const __m256i R2 = _mm256_set_epi64x(42, 14, 27, 33);
		const __m256i R3 = _mm256_set_epi64x(39, 36, 49, 17);
		const __m256i R4 = _mm256_set_epi64x(56, 54, 9, 44);
		const __m256i R5 = _mm256_set_epi64x(24, 34, 30, 39);
		const __m256i R6 = _mm256_set_epi64x(17, 10, 50, 13);
		const __m256i R7 = _mm256_set_epi64x(43, 39, 29, 25);
		const __m256i R8 = _mm256_set_epi64x(22, 56, 35, 8);
		const __m256i RFN = _mm256_set_epi64x(1, 0, 0, 0);

		const ulong KS = GetParity(Output.S);
		const __m256i K0 = _mm256_set_epi64x(Output.S[6], Output.S[4], Output.S[2], Output.S[0]);
		const __m256i K1 = _mm256_set_epi64x(Output.S[7], Output.S[5], Output.S[3], Output.S[1]);
		const __m256i K2 = _mm256_set_epi64x(KS, Output.S[6], Output.S[4], Output.S[2]);
		const __m256i K3 = _mm256_set_epi64x(Output.S[0], Output.S[7], Output.S[5], Output.S[3]);
		const __m256i K4 = _mm256_set_epi64x(Output.S[1], KS, Output.S[6], Output.S[4]);
		const __m256i K5 = _mm256_set_epi64x(Output.S[2], Output.S[0], Output.S[7], Output.S[5]);
		const __m256i K6 = _mm256_set_epi64x(Output.S[3], Output.S[1], KS, Output.S[6]);
		const __m256i K7 = _mm256_set_epi64x(Output.S[4], Output.S[2], Output.S[0], Output.S[7]);
		const __m256i K8 = _mm256_set_epi64x(Output.S[5], Output.S[3], Output.S[1], KS);
		const __m256i T = _mm256_set_epi64x(Output.T[0], Output.T[1], Output.T[0] ^ Output.T[1], 0);

		__m256i* regOutput = reinterpret_cast<__m256i*>(Output.S.data());
		__m256i X0 = _mm256_set_epi64x(Input[InOffset + 6], Input[InOffset + 4], Input[InOffset + 2], Input[InOffset]);
		__m256i X1 = _mm256_set_epi64x(Input[InOffset+ 7], Input[InOffset + 5], Input[InOffset + 3], Input[InOffset + 1]);

		TF512INJECTKEY(X0, X1, R0, K0, K1, 2, 3);
		TF512ENC8ROUNDS(X0, X1, R0, K1, K2, K3, 1, 2, 3);
		TF512ENC8ROUNDS(X0, X1, R0, K3, K4, K5, 2, 3, 1);
		TF512ENC8ROUNDS(X0, X1, R0, K5, K6, K7, 3, 1, 2);
		TF512ENC8ROUNDS(X0, X1, R0, K7, K8, K0, 1, 2, 3);
		TF512ENC8ROUNDS(X0, X1, R0, K0, K1, K2, 2, 3, 1);
		TF512ENC8ROUNDS(X0, X1, R0, K2, K3, K4, 3, 1, 2);
		TF512ENC8ROUNDS(X0, X1, R0, K4, K5, K6, 1, 2, 3);
		TF512ENC8ROUNDS(X0, X1, R0, K6, K7, K8, 2, 3, 1);
		TF512ENC8ROUNDS(X0, X1, R0, K8, K0, K1, 3, 1, 2);

		Interleave64(X0, X1);

		_mm256_storeu_si256(regOutput++, X0);
		_mm256_storeu_si256(regOutput, X1);
	}

	template <typename T>
	static void Transfrom64(std::vector<ulong> &Input, size_t InOffset, T &Output)
	{
		// cache the block, key, and tweak
		ulong B0 = Input[0];
		ulong B1 = Input[1];
		ulong B2 = Input[2];
		ulong B3 = Input[3];
		ulong B4 = Input[4];
		ulong B5 = Input[5];
		ulong B6 = Input[6];
		ulong B7 = Input[7];
		ulong K0 = Output.S[0];
		ulong K1 = Output.S[1];
		ulong K2 = Output.S[2];
		ulong K3 = Output.S[3];
		ulong K4 = Output.S[4];
		ulong K5 = Output.S[5];
		ulong K6 = Output.S[6];
		ulong K7 = Output.S[7];
		ulong K8 = GetParity(Output.S);
		ulong T0 = Output.T[0];
		ulong T1 = Output.T[1];
		ulong T2 = Output.T[0] ^ Output.T[1];

		// 72 rounds
		Inject(B0, B1, 46, K0, K1);
		Inject(B2, B3, 36, K2, K3);
		Inject(B4, B5, 19, K4, K5 + T0);
		Inject(B6, B7, 37, K6 + T1, K7);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K1, K2);
		Inject(B2, B3, 30, K3, K4);
		Inject(B4, B5, 34, K5, K6 + T1);
		Inject(B6, B7, 24, K7 + T2, K8 + 1);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K2, K3);
		Inject(B2, B3, 36, K4, K5);
		Inject(B4, B5, 19, K6, K7 + T2);
		Inject(B6, B7, 37, K8 + T0, K0 + 2);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K3, K4);
		Inject(B2, B3, 30, K5, K6);
		Inject(B4, B5, 34, K7, K8 + T0);
		Inject(B6, B7, 24, K0 + T1, K1 + 3);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K4, K5);
		Inject(B2, B3, 36, K6, K7);
		Inject(B4, B5, 19, K8, K0 + T1);
		Inject(B6, B7, 37, K1 + T2, K2 + 4);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K5, K6);
		Inject(B2, B3, 30, K7, K8);
		Inject(B4, B5, 34, K0, K1 + T2);
		Inject(B6, B7, 24, K2 + T0, K3 + 5);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K6, K7);
		Inject(B2, B3, 36, K8, K0);
		Inject(B4, B5, 19, K1, K2 + T0);
		Inject(B6, B7, 37, K3 + T1, K4 + 6);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K7, K8);
		Inject(B2, B3, 30, K0, K1);
		Inject(B4, B5, 34, K2, K3 + T1);
		Inject(B6, B7, 24, K4 + T2, K5 + 7);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K8, K0);
		Inject(B2, B3, 36, K1, K2);
		Inject(B4, B5, 19, K3, K4 + T2);
		Inject(B6, B7, 37, K5 + T0, K6 + 8);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K0, K1);
		Inject(B2, B3, 30, K2, K3);
		Inject(B4, B5, 34, K4, K5 + T0);
		Inject(B6, B7, 24, K6 + T1, K7 + 9);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K1, K2);
		Inject(B2, B3, 36, K3, K4);
		Inject(B4, B5, 19, K5, K6 + T1);
		Inject(B6, B7, 37, K7 + T2, K8 + 10);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K2, K3);
		Inject(B2, B3, 30, K4, K5);
		Inject(B4, B5, 34, K6, K7 + T2);
		Inject(B6, B7, 24, K8 + T0, K0 + 11);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K3, K4);
		Inject(B2, B3, 36, K5, K6);
		Inject(B4, B5, 19, K7, K8 + T0);
		Inject(B6, B7, 37, K0 + T1, K1 + 12);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K4, K5);
		Inject(B2, B3, 30, K6, K7);
		Inject(B4, B5, 34, K8, K0 + T1);
		Inject(B6, B7, 24, K1 + T2, K2 + 13);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K5, K6);
		Inject(B2, B3, 36, K7, K8);
		Inject(B4, B5, 19, K0, K1 + T2);
		Inject(B6, B7, 37, K2 + T0, K3 + 14);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K6, K7);
		Inject(B2, B3, 30, K8, K0);
		Inject(B4, B5, 34, K1, K2 + T0);
		Inject(B6, B7, 24, K3 + T1, K4 + 15);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);
		Inject(B0, B1, 46, K7, K8);
		Inject(B2, B3, 36, K0, K1);
		Inject(B4, B5, 19, K2, K3 + T1);
		Inject(B6, B7, 37, K4 + T2, K5 + 16);
		Mix(B2, B1, 33);
		Mix(B4, B7, 27);
		Mix(B6, B5, 14);
		Mix(B0, B3, 42);
		Mix(B4, B1, 17);
		Mix(B6, B3, 49);
		Mix(B0, B5, 36);
		Mix(B2, B7, 39);
		Mix(B6, B1, 44);
		Mix(B0, B7, 9);
		Mix(B2, B5, 54);
		Mix(B4, B3, 56);
		Inject(B0, B1, 39, K8, K0);
		Inject(B2, B3, 30, K1, K2);
		Inject(B4, B5, 34, K3, K4 + T2);
		Inject(B6, B7, 24, K5 + T0, K6 + 17);
		Mix(B2, B1, 13);
		Mix(B4, B7, 50);
		Mix(B6, B5, 10);
		Mix(B0, B3, 17);
		Mix(B4, B1, 25);
		Mix(B6, B3, 29);
		Mix(B0, B5, 39);
		Mix(B2, B7, 43);
		Mix(B6, B1, 8);
		Mix(B0, B7, 35);
		Mix(B2, B5, 56);
		Mix(B4, B3, 22);

		Output.S[0] = B0 + K0;
		Output.S[1] = B1 + K1;
		Output.S[2] = B2 + K2;
		Output.S[3] = B3 + K3;
		Output.S[4] = B4 + K4;
		Output.S[5] = B5 + K5 + T0;
		Output.S[6] = B6 + K6 + T1;
		Output.S[7] = B7 + K7 + 18;
	}
};

NAMESPACE_DIGESTEND
#endif
