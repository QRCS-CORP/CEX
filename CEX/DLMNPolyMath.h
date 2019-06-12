// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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

#ifndef CEX_DLTMPOLYMATH_H
#define CEX_DLTMPOLYMATH_H

#include "CexDomain.h"
#include "Keccak.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using Digest::Keccak;
using Utility::MemoryTools;

/// 
/// internal
/// 

/// <summary>
/// The Dilithium math functions
/// </summary>
class DLMNPolyMath
{
private:

	static const uint DILITHIUM_N = 256;
	static const int32_t DILITHIUM_Q = 8380417;
	static const int32_t DILITHIUM_QBITS = 23;
	static const int32_t DILITHIUM_UNITYROOT = 1753;
	static const int32_t DILITHIUM_D = 14;
	static const int32_t DILITHIUM_GAMMA1 = ((DILITHIUM_Q - 1) / 16);
	static const int32_t DILITHIUM_GAMMA2 = (DILITHIUM_GAMMA1 / 2);
	static const int32_t DILITHIUM_ALPHA = (2 * DILITHIUM_GAMMA2);
	// 2^32 % Q 
	static const int32_t DILITHIUM_MONT = 4193792U;
	// -q^(-1) mod 2^32 
	static const int32_t DILITHIUM_QINV = 4236238847U;
	static const size_t DILITHIUM_POLW1_SIZE_PACKED = ((DILITHIUM_N * 4) / 8);

	// roots of unity in order needed by forward ntt
	static const uint Zetas[DILITHIUM_N];
	// roots of unity in order needed by inverse ntt
	static const uint ZetasInv[DILITHIUM_N];

public:

	// ntt.c //

	static void InvNttFromInvMont(std::array<uint, 256> &P);

	static void Ntt(std::array<uint, 256> &P);

	// packing.c //

	static void PackPk(std::vector<byte> &Pk, const std::vector<byte> &Rho, const std::vector<std::array<uint, 256>> &T1, uint PolT1Packed);

	static void UnpackPk(std::vector<byte> &Rho, std::vector<std::array<uint, 256>> &T1, const std::vector<byte> &Pk, uint PolT1Packed);

	static void PackSk(std::vector<byte> &Sk, const std::vector<byte> &Rho, const std::vector<byte> &Key, const std::vector<byte> &Tr, const std::vector<std::array<uint, 256>> &S1,
		const std::vector<std::array<uint, 256>> &S2, const std::vector<std::array<uint, 256>> &T0, uint Eta, uint PolTAPacked, uint PolT0Packed);

	static void UnpackSk(std::vector<byte> &Rho, std::vector<byte> &Key, std::vector<byte> &Tr, std::vector<std::array<uint, 256>> &S1, std::vector<std::array<uint, 256>> &S2,
		std::vector<std::array<uint, 256>> &T0, const std::vector<byte> &Sk, uint Eta, uint PolTAPacked, uint PolT0Packed);

	static void PackSig(std::vector<byte> &Sig, const std::vector<std::array<uint, 256>> &Z, const std::vector<std::array<uint, 256>> &H, const std::array<uint, 256> &C, uint Omega, uint PolZPacked);

	static int32_t UnpackSig(std::vector<std::array<uint, 256>> &Z, std::vector<std::array<uint, 256>> &H, std::array<uint, 256> &C, const std::vector<byte> &Sig, uint Omega, uint PolZPacked);

	// poly.c //

	static void PolyAdd(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B);

	static int32_t PolyChkNorm(const std::array<uint, 256> &A, uint B);

	static void PolyCSubQ(std::array<uint, 256> &A);

	static void PolyDecompose(std::array<uint, 256> &A1, std::array<uint, 256> &A0, const std::array<uint, 256> &A);

	static void PolyEtaPack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A, uint Eta);

	static void PolyEtaUnpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset, uint Eta);

	static void PolyFreeze(std::array<uint, 256> &A);

	static void PolyInvNttMontgomery(std::array<uint, 256> &A);

	static uint PolyMakeHint(std::array<uint, 256> &H, const std::array<uint, 256> &A0, const std::array<uint, 256> &A1);

	static void PolyNtt(std::array<uint, 256> &A);

	static void PolyPointwiseInvMontgomery(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B);

	static void PolyPower2Round(std::array<uint, 256> &A1, std::array<uint, 256> &A0, const std::array<uint, 256> &A);

	static void PolyReduce(std::array<uint, 256> &A);

	static void PolyShiftL(std::array<uint, 256> &A);

	static void PolySub(std::array<uint, 256> &C, const std::array<uint, 256> &A, const std::array<uint, 256> &B);

	static void PolyT0Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A);

	static void PolyT0Unpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset);

	static void PolyT1Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A);

	static void PolyT1Unpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset);

	static void PolyUniform(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort Nonce);

	static void PolyUniformEta(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort nonce, uint Eta, uint Seta);

	static void PolyUniformGamma1M1(std::array<uint, 256> &A, const std::vector<byte> &Seed, ushort Nonce);

	static void PolyUseHint(std::array<uint, 256> &A, const std::array<uint, 256> &B, const std::array<uint, 256> &H);

	static void PolyW1Pack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A);

	static void PolyZPack(std::vector<byte> &R, size_t ROffset, const std::array<uint, 256> &A);

	static void PolyZUnpack(std::array<uint, 256> &R, const std::vector<byte> &A, size_t AOffset);

	static size_t RejEta(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength, uint Eta);

	static size_t RejGamma1M1(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength);

	static size_t RejUniform(std::array<uint, 256> &A, size_t AOffset, size_t ALength, const std::vector<byte> &Buffer, size_t BufLength);

	// polyvec.c //

	static void PolyVecAdd(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V);

	static int32_t PolyVecChkNorm(const std::vector<std::array<uint, 256>> &V, uint bound);

	static void PolyVecCSubQ(std::vector<std::array<uint, 256>> &V);

	static void PolyVecDecompose(std::vector<std::array<uint, 256>> &V1, std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V);

	static void PolyVecFreeze(std::vector<std::array<uint, 256>> &V);

	static void PolyVecInvNttMontgomery(std::vector<std::array<uint, 256>> &V);

	static uint PolyVecMakeHint(std::vector<std::array<uint, 256>> &H, const std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V1);

	static void PolyVecNtt(std::vector<std::array<uint, 256>> &V);

	static void PolyVecPointwiseAccInvMontgomery(std::array<uint, 256> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V);

	static void PolyVecPower2Round(std::vector<std::array<uint, 256>> &V1, std::vector<std::array<uint, 256>> &V0, const std::vector<std::array<uint, 256>> &V);

	static void PolyVecReduce(std::vector<std::array<uint, 256>> &V);

	static void PolyVecShiftL(std::vector<std::array<uint, 256>> &V);

	static void PolyVecSub(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &V);

	static void PolyVecUseHint(std::vector<std::array<uint, 256>> &W, const std::vector<std::array<uint, 256>> &U, const std::vector<std::array<uint, 256>> &H);

	// reduce.c //

	static uint CSubQ(uint A);

	static uint Freeze(uint A);

	static uint MontgomeryReduce(ulong A);

	static uint Reduce32(uint A);

	// rounding.c //

	static uint Decompose(uint A, uint&A0);

	static uint MakeHint(const uint A0, const uint A1);

	static uint Power2Round(uint A, uint&A0);

	static uint UseHint(const uint A, const uint Hint);

	// sign.c //

	static void Challenge(std::array<uint, 256> &C, const std::vector<byte> &Mu, const std::vector<std::array<uint, 256>> &W1);

	static void ExpandMat(std::vector<std::vector<std::array<uint, 256>>> &Matrix, const std::vector<byte> &Rho);
};

NAMESPACE_DILITHIUMEND
#endif