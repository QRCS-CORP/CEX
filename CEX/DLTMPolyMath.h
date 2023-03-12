// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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

#ifndef CEX_DLTMPOLYMATH_H
#define CEX_DLTMPOLYMATH_H

#include "CexDomain.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using Digest::Keccak;
using Tools::MemoryTools;

/// 
/// internal
/// 

/// <summary>
/// The Dilithium math functions
/// </summary>
class DLTMPolyMath
{
private:

	static const size_t DILITHIUM_CRH_SIZE = 48;
	static const uint32_t DILITHIUM_N = 256;
	static const int32_t DILITHIUM_Q = 8380417;
	static const int32_t DILITHIUM_QBITS = 23;
	static const uint32_t DILITHIUM_SEED_SIZE = 32;
	static const int32_t DILITHIUM_UNITYROOT = 1753;
	static const int32_t DILITHIUM_D = 13;
	// 2^32 % Q 
	static const int32_t DILITHIUM_MONT = 4193792U;
	// -q^(-1) mod 2^32 
	static const int32_t DILITHIUM_QINV = 58728449;
	static const size_t DILITHIUM_POLW1_SIZE_PACKED = ((DILITHIUM_N * 4) / 8);
	// roots of unity in order needed by forward ntt
	static const uint32_t Zetas[DILITHIUM_N];
	static const int32_t Avx2Q[8];
	static const int32_t Avx2QINV[8];

public:

	// ntt.c //
	static void InvNttToMont(std::array<int32_t, 256>& A);
	static void Ntt(std::array<int32_t, 256>& A);
	// packing.c //
	static void PackPk(std::vector<uint8_t> &Pk, const std::vector<uint8_t> &Rho, const std::vector<std::array<int32_t, 256>> &T1, uint32_t PolT1Packed);
	static void UnpackPk(std::vector<uint8_t> &Rho, std::vector<std::array<int32_t, 256>> &T1, const std::vector<uint8_t> &Pk, uint32_t PolT1Packed);
	static void PackSk(std::vector<uint8_t> &Sk, const std::vector<uint8_t> &Rho, const std::vector<uint8_t> &Key, const std::vector<uint8_t> &Tr, const std::vector<std::array<int32_t, 256>> &S1, const std::vector<std::array<int32_t, 256>> &S2, const std::vector<std::array<int32_t, 256>> &T0, uint32_t Eta, uint32_t PolTAPacked, uint32_t PolT0Packed);
	static void UnpackSk(std::vector<uint8_t> &Rho, std::vector<uint8_t> &Tr, std::vector<uint8_t> &Key, std::vector<std::array<int32_t, 256>> &T0, 
	std::vector<std::array<int32_t, 256>> &S1, std::vector<std::array<int32_t, 256>> &S2, const std::vector<uint8_t> &Sk, uint32_t Eta, uint32_t PolyEtaPacked, uint32_t PolyT0Packed);
	static void PackSig(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &C, const std::vector<std::array<uint32_t, 256>> &Z, const std::vector<std::array<uint32_t, 256>> &H);
	static int32_t UnpackSig(std::vector<uint8_t> &C, std::vector<std::array<int32_t, 256>> &Z, std::vector<std::array<int32_t, 256>> &H, const std::vector<uint8_t> &Signature, uint32_t PolZPacked, uint32_t Gamma1, uint32_t Omega);
	// poly.c //
	static void PolyAdd(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B);
	static void PolyCaddQ(std::array<int32_t, 256> &A);
	static void PolyChallenge(std::array<int32_t, 256> &C, const std::vector<uint8_t> &Seed, uint32_t Tau);
	static int32_t PolyChkNorm(const std::array<int32_t, 256> &A, uint32_t B);
	static void PolyDecompose(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A, uint32_t Gamma2);
	static void PolyEtaPack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Eta);
	static void PolyEtaUnpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset, uint32_t Eta);
	static void PolyInvNttMont(std::array<int32_t, 256> &A);
	static uint32_t PolyMakeHint(std::array<int32_t, 256> &H, const std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A1, uint32_t Gamma2);
	static void PolyNtt(std::array<int32_t, 256> &A);
	static void PolyPointwiseInvMont(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256>& B);
	static void PolyPointwiseMont(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B);
	static void PolyPower2Round(std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A0, const std::array<int32_t, 256> &A);
	static void PolyReduce(std::array<int32_t, 256> &A);
	static void PolyShiftL(std::array<int32_t, 256> &A);
	static void PackSig(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &C, const std::vector<std::array<int32_t, 256>> &Z,const std::vector<std::array<int32_t, 256>> &H, uint32_t K, uint32_t Omega, uint32_t PolyzPacked, uint32_t Gamma1);
	static void PolySub(std::array<int32_t, 256> &C, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &B);
	static void PolyT0Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A);
	static void PolyT0Unpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyT1Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A);
	static void PolyT1Unpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyUniform(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce);
	static void PolyUniformEta(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce, uint32_t Eta, uint32_t Blocks);
	static void PolyZUnpack(std::array<int32_t, 256> &R, const std::vector<uint8_t> &A, size_t AOffset, uint32_t Gamma1);
	static void PolyUniformGamma1M1(std::array<int32_t, 256> &A, const std::vector<uint8_t> &Seed, uint16_t Nonce, uint32_t Gamma1);
	static void PolyUseHint(std::array<int32_t, 256> &B, const std::array<int32_t, 256> &A, const std::array<int32_t, 256> &H, uint32_t Gamma2);
	static void PolyW1Pack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Gamma2);
	static void PolyZPack(std::vector<uint8_t> &R, size_t ROffset, const std::array<int32_t, 256> &A, uint32_t Gamma1);
	static size_t RejEta(std::array<int32_t, 256> &A, size_t AOffset, size_t ALength, const std::vector<uint8_t> &Buffer, size_t BufLength, uint32_t Eta);
	static size_t RejUniform(std::array<int32_t, 256> &A, size_t AOffset, size_t ALength, const std::vector<uint8_t> &Buffer, size_t BufLength);
	// polyvec.c //
	static void PolyVecAdd(std::vector<std::array<int32_t, 256>>& W, const std::vector<std::array<int32_t, 256>>& U, const std::vector<std::array<int32_t, 256>>& V);
	static int32_t PolyVecChkNorm(const std::vector<std::array<int32_t, 256>> &V, uint32_t bound);
	static void PolyVecDecompose(std::vector<std::array<int32_t, 256>> &V1, std::vector<std::array<int32_t, 256>> &V0, const std::vector<std::array<int32_t, 256>> &V, uint32_t Gamma2);
	static void PolyVecCaddQ(std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecInvNttMont(std::vector<std::array<int32_t, 256>> &V);
	static uint32_t PolyVecMakeHint(std::vector<std::array<int32_t, 256>> &H, const std::vector<std::array<int32_t, 256>> &A0, const std::vector<std::array<int32_t, 256>> &A1, uint32_t Gamma2);
	static void PolyVecMatrixPointwiseMont(std::array<int32_t, 256> &W, const std::vector<std::array<int32_t, 256>> &U, const std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecNtt(std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecPackW1(std::vector<uint8_t> &R, const std::vector<std::array<int32_t, 256>> &W1, size_t W1PackedSize, uint32_t Gamma2);
	static void PolyVecPointwiseInvMont(std::vector<std::array<int32_t, 256>> &C, const std::array<int32_t, 256> &A, const std::vector<std::array<int32_t, 256>> &B);
	static void PolyVecPointwiseMont(std::vector<std::array<int32_t, 256>> &C, const std::array<int32_t, 256> &A, const std::vector<std::array<int32_t, 256>> &B);
	static void PolyVecPower2Round(std::vector<std::array<int32_t, 256>> &V1, std::vector<std::array<int32_t, 256>> &V0, const std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecReduce(std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecShiftL(std::vector<std::array<int32_t, 256>> &V);
	static void PolyVecSub(std::vector<std::array<int32_t, 256>> &C, const std::vector<std::array<int32_t, 256>> &A, const std::vector<std::array<int32_t, 256>> &B);
	static void PolyVecUniformGamma1M1(std::vector<std::array<int32_t, 256>> &V, const std::vector<uint8_t> &Seed, uint16_t nonce, uint32_t Gamma1);
	static void PolyVecUseHint(std::vector<std::array<int32_t, 256>> &B, const std::vector<std::array<int32_t, 256>> &A, const std::vector<std::array<int32_t, 256>> &H, uint32_t Gamma2);
	// reduce.c //
	static int32_t CaddQ(int32_t a);
	static int32_t MontReduce(int64_t A);
	static int32_t Reduce32(int32_t A);
	// rounding.c //
	static int32_t Decompose(int32_t &A0, int32_t A, uint32_t Gamma2);
	static int32_t MakeHint(int32_t A0, int32_t A1, int32_t Gamma2);
	static int32_t Power2Round(int32_t A, int32_t &A0);
	static uint32_t UseHint(int32_t A, const int32_t Hint, uint32_t Gamma2);
	// sign.c //
	static void ExpandMat(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho);

#if defined(CEX_HAS_AVX2)
	static size_t RejUniformAvx2(std::array<int32_t, 256> &A, size_t AOffset, size_t ALength, const std::vector<uint8_t> &Buffer, size_t BufLength);
	static void PolyUniform4x(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3, const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3);
	static void PolyUniformEta4x(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3, const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3, size_t Blocks, uint32_t Eta);
	static void PolyUniformGamma1x4(std::array<int32_t, 256> &A0, std::array<int32_t, 256> &A1, std::array<int32_t, 256> &A2, std::array<int32_t, 256> &A3, const std::vector<uint8_t> &Seed, uint16_t Nonce0, uint16_t Nonce1, uint16_t Nonce2, uint16_t Nonce3, uint32_t Gamma1);
	static void PolyVecMatrixExpandAvx2(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho, uint32_t K, uint32_t L);
	static void PolyVecMatrixExpandRow(std::vector<std::vector<std::array<int32_t, 256>>> &Matrix, const std::vector<uint8_t> &Rho, uint32_t K, uint32_t L, size_t Index);
#endif

};

NAMESPACE_DILITHIUMEND
#endif