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

#ifndef CEX_MLWEQ3329N256_H
#define CEX_MLWEQ3329N256_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MODULELWE

/// 
/// internal
/// 

/// <summary>
/// The ModuleLWE FFT
/// </summary>
class MLWEQ3329N256
{
private:

	// 2^16 % Q
	static const int MONT = 2285;
	static const int MLWE_ETA = 2;
	static const size_t MLWE_POLY_SIZE = 384;
	// q^(-1) mod 2^16
	static const int MLWE_QINV = 62209;
	static const std::vector<int16_t> Zetas;
	static const std::vector<int16_t> ZetasInv;

public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The byte size of the MLWE seed
	/// </summary>
	static const size_t MLWE_SEED_SIZE = 32;

	/// <summary>
	/// The byte size of the MLWE-K2 cipher-text
	/// </summary>
	static const size_t CIPHERTEXTK2_SIZE = 736;

	/// <summary>
	/// The byte size of the MLWE-K3 cipher-text
	/// </summary>
	static const size_t CIPHERTEXTK3_SIZE = 1088;

	/// <summary>
	/// The byte size of the MLWE-K4 cipher-text
	/// </summary>
	static const size_t CIPHERTEXTK4_SIZE = 1568;

	/// <summary>
	/// The number of coefficients
	/// </summary>
	static const uint MLWE_N = 256;

	/// <summary>
	/// The Q modulus
	/// </summary>
	static const uint MLWE_Q = 3329;

	/// <summary>
	/// The byte size of the MLWE-K2 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEYK2_SIZE = 1632;

	/// <summary>
	/// The byte size of the MLWE-K3 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEYK3_SIZE = 2400;

	/// <summary>
	/// The byte size of the MLWE-K4 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEYK4_SIZE = 3168;

	/// <summary>
	/// The byte size of the MLWE-K2 public key polynomial
	/// </summary>
	static const size_t PUBLICKEYK2_SIZE = 800;

	/// <summary>
	/// The byte size of the MLWE-K3 public key polynomial
	/// </summary>
	static const size_t PUBLICKEYK3_SIZE = 1184;

	/// <summary>
	/// The byte size of the MLWE-K4 public key polynomial
	/// </summary>
	static const size_t PUBLICKEYK4_SIZE = 1568;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decapsulate a cipher-text and return the shared-secret
	/// </summary>
	/// 
	/// <param name="Secret">The shared-secret key</param>
	/// <param name="CipherText">The encapsulated keys ciphertext</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	static bool Decapsulate(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);

	/// <summary>
	/// Encapsulate a secret key and output the cipher-text and the shared-secret
	/// </summary>
	/// 
	/// <param name="Secret">The shared-secret message</param>
	/// <param name="CipherText">The encapsulated keys ciphertext</param>
	/// <param name="PublicKey">The asymmetric public key</param>
	/// <param name="Rng">The random generator instance</param>
	static void Encapsulate(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng);

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random generator instance</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

private:

	// indcpa.c //

	static void PackPk(std::vector<byte> &R, std::vector<std::array<ushort, MLWE_N>> &Pk, const std::vector<byte> &Seed);
	static void UnpackPk(std::vector<std::array<ushort, MLWE_N>> &Pk, std::vector<byte> &Seed, const std::vector<byte> &PackedPk, uint Dimension);
	static void PackSk(std::vector<byte> &R, std::vector<std::array<ushort, MLWE_N>> &Sk);
	static void UnpackSk(std::vector<std::array<ushort, MLWE_N>> &Sk, const std::vector<byte> &PackedSk);
	static void PackCiphertext(std::vector<byte> &R, std::vector<std::array<ushort, MLWE_N>> &B, std::array<ushort, MLWE_N> &V);
	static void UnpackCiphertext(std::vector<std::array<ushort, MLWE_N>> &B, std::array<ushort, MLWE_N> &V, const std::vector<byte> &C);
	static uint RejUniform(std::array<ushort, MLWE_N> &R, uint ROffset, uint RLength, const std::vector<byte> &Buffer, size_t BufLength);
	static void GenMatrix(std::vector<std::vector<std::array<ushort, MLWE_N>>> &A, const std::vector<byte> &Seed, bool Transposed);
	static void CpaGenerate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::vector<byte> &Seed, uint K);
	static void CpaEncrypt(std::vector<byte> &CipherText, const std::vector<byte> &Message, const std::vector<byte> &Pk, const std::vector<byte> &Coins, uint K);
	static void CpaDecrypt(std::vector<byte> &Message, const std::vector<byte> &CipherText, const std::vector<byte> &Sk, uint K);

	// ntt.c //

	static ushort FqMul(int16_t A, int16_t B);
	static void Ntt(std::array<ushort, MLWE_N> &R);
	static void InvNtt(std::array<ushort, MLWE_N> &R);
	static void BaseMul(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B, size_t Offset, int16_t Zeta);

	// poly.c //

	static void Cbd(std::array<ushort, MLWE_N> &R, const std::vector<byte> &Buffer);
	static void PolyCompress(std::vector<byte> &R, std::array<ushort, MLWE_N> &A, uint K);
	static void PolyDecompress(std::array<ushort, MLWE_N> &R, const std::vector<byte> &A, uint K);
	static void PolyToBytes(std::vector<byte> &R, size_t ROffset, std::array<ushort, MLWE_N> &A);
	static void PolyFromBytes(std::array<ushort, MLWE_N> &R, const std::vector<byte> &A, size_t AOffset);
	static void PolyGetNoise(std::array<ushort, MLWE_N> &R, const std::vector<byte> &Seed, byte Nonce);
	static void PolyNtt(std::array<ushort, MLWE_N> &R);
	static void PolyInvNtt(std::array<ushort, MLWE_N> &R);
	static void PolyBaseMul(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B);
	static void PolyFromMont(std::array<ushort, MLWE_N> &R);
	static void PolyReduce(std::array<ushort, MLWE_N> &R);
	static void PolyCSubQ(std::array<ushort, MLWE_N> &R);
	static void PolyAdd(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B);
	static void PolySub(std::array<ushort, MLWE_N> &R, const std::array<ushort, MLWE_N> &A, const std::array<ushort, MLWE_N> &B);
	static void PolyFromMsg(std::array<ushort, MLWE_N> &R, const std::vector<byte> &Msg);
	static void PolyToMsg(std::vector<byte> &Msg, std::array<ushort, MLWE_N> &A);

	// polyvec.c //

	static void PolyVecCompress(std::vector<byte> &R, std::vector<std::array<ushort, MLWE_N>> &A);
	static void PolyVecDecompress(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<byte> &A);
	static void PolyVecToBytes(std::vector<byte> &R, std::vector<std::array<ushort, MLWE_N>> &A);
	static void PolyVecFromBytes(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<byte> &A);
	static void PolyVecNtt(std::vector<std::array<ushort, MLWE_N>> &R);
	static void PolyVecInvNtt(std::vector<std::array<ushort, MLWE_N>> &R);
	static void PolyVecPointwiseAcc(std::array<ushort, MLWE_N> &R, const std::vector<std::array<ushort, MLWE_N>> &A, const std::vector<std::array<ushort, MLWE_N>> &B);
	static void PolyVecReduce(std::vector<std::array<ushort, MLWE_N>> &R);
	static void PolyVecCSubQ(std::vector<std::array<ushort, MLWE_N>> &R);
	static void PolyVecAdd(std::vector<std::array<ushort, MLWE_N>> &R, const std::vector<std::array<ushort, MLWE_N>> &A, const std::vector<std::array<ushort, MLWE_N>> &B);

	// reduce.c //

	static ushort MontgomeryReduce(int32_t A);
	static ushort BarrettReduce(int16_t A);
	static ushort CSubQ(int16_t A);
	static void Compute(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
};

NAMESPACE_MODULELWEEND
#endif
