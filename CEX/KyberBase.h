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

#ifndef CEX_KYBERBASE_H
#define CEX_KYBERBASE_H

#include "CexDomain.h"
#include "IPrng.h"
#if defined(CEX_HAS_AVX)
#	include "Intrinsics.h"
#endif

NAMESPACE_KYBER

using Prng::IPrng;

/// 
/// internal
/// 

/// <summary>
// An internal Kyber utilities class
/// </summary>
class KyberBase
{
private:

	typedef struct
	{
		CEX_ALIGN(32) std::array<int16_t, 256> coeffs;
	} Poly;

	typedef struct
	{
		std::vector<Poly> vec;
	} PolyVec;

	static const std::vector<uint16_t> Zetas;

public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The uint8_t size of the K2400 cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE_K2400 = 1088;

	/// <summary>
	/// The uint8_t size of the K3168 cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE_K3168 = 1568;

	/// <summary>
	/// The uint8_t size of the K3936 cipher-text
	/// </summary>
	static const size_t CIPHERTEXT_SIZE_K3936 = 1920;

	/// <summary>
	/// The uint8_t size of the K2400 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE_K2400 = 2400;

	/// <summary>
	/// The uint8_t size of the K3168 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE_K3168 = 3168;

	/// <summary>
	/// The uint8_t size of the K3936 private key polynomial
	/// </summary>
	static const size_t PRIVATEKEY_SIZE_K3936 = 3936;

	/// <summary>
	/// The uint8_t size of the K2400 public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE_K2400 = 1184;

	/// <summary>
	/// The uint8_t size of the K3168 public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE_K3168 = 1568;

	/// <summary>
	/// The uint8_t size of the K3936 public key polynomial
	/// </summary>
	static const size_t PUBLICKEY_SIZE_K3936 = 1952;

	/**
	* \brief Generates shared secret for given cipher text and private key
	*
	* \param ss: Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
	* \param ct: [const] Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
	* \param sk: [const] Pointer to input private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
	* \return Returns true for success
	*/
	static bool Decapsulate(const std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret, uint32_t K);

	/**
	* \brief Generates cipher text and shared secret for given public key
	*
	* \param ct: Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
	* \param ss: Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
	* \param pk: [const] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
	* \param rng_generate: Pointer to the random generator function
	*/
	static void Encapsulate(const std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret, std::unique_ptr<IPrng> &Rng, uint32_t K);

	/**
	* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
	*
	* \param pk: Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
	* \param sk: Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
	* \param rng_generate: Pointer to the random generator function
	*/
	static void Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng, uint32_t K);

private:

	static int16_t BarrettReduce(int16_t A);
	static void BaseMul(int16_t R[2], const int16_t A[2], const int16_t B[2], int16_t Zeta);
	static int16_t FqMul(int16_t A, int16_t B);
	static void GenMatrix(std::vector<PolyVec>& A, const std::vector<uint8_t>& Seed, size_t SOffset, int32_t Transposed, uint32_t K);
	static void IndCpaDec(std::vector<uint8_t>& M, const std::vector<uint8_t>& C, const std::vector<uint8_t>& Sk, uint32_t K);
	static void IndCpaEnc(std::vector<uint8_t>& C, const std::vector<uint8_t>& M, const std::vector<uint8_t>& Pk, const std::vector<uint8_t>& Coins, size_t COffset, uint32_t K);
	static void IndCpaKeyPair(std::vector<uint8_t>& Pk, std::vector<uint8_t>& Sk, std::unique_ptr<IPrng>& Rng, uint32_t K);
	static void InvNtt(Poly &R);
	static int16_t MontgomeryReduce(int32_t A);
	static void Ntt(Poly &R);
	static void PackCiphertext(std::vector<uint8_t>& R, const PolyVec& B, const Poly& V, uint32_t K);
	static void PackPk(std::vector<uint8_t> &R, const PolyVec &Pk, const std::vector<uint8_t> &Seed);
	static void PackSk(std::vector<uint8_t>& R, const PolyVec& Sk);
	static void PolyBaseMulMontgomery(Poly &R, const Poly &A, const Poly &B);
	static void PolyCbdEta1(Poly &R, const std::vector<uint8_t> &Buf);
	static void PolyCbdEta2(Poly &R, const std::vector<uint8_t> &Buf);
	static void PolyFromBytes(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyGetNoiseEta1(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce);
	static void PolyGetNoiseEta2(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce);
	static void PolyInvNttToMontgomery(Poly &R);
	static void PolyNttv2(Poly &R);
	static void PolyReduce(Poly &R);
	static void PolyToBytes(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyToMont(Poly &R);
	static void PolyToMsg(std::vector<uint8_t> &Msg, const Poly &A);
	static void PolyVecAdd(PolyVec &R, const PolyVec &A, const PolyVec &B);
	static void PolyVecBaseMulAccMontgomery(Poly &R, const PolyVec &A, const PolyVec &B);
	static void PolyVecCompress(std::vector<uint8_t>& R, const PolyVec& A);
	static void PolyVecFromBytes(PolyVec &R, const std::vector<uint8_t> &A);
	static void PolyVecInvNttToMont(PolyVec &R);
	static void PolyVecNtt(PolyVec &R);
	static void PolyVecReduce(PolyVec &R);
	static void PolyVecToBytes(std::vector<uint8_t> &R, const PolyVec &A);
	static uint32_t RejUniform(Poly &R, uint32_t ROffset, uint32_t Rlen, const std::vector<uint8_t> &Buf, uint32_t BufLen);
	static void UnPackCiphertext(PolyVec &B, Poly &V, const std::vector<uint8_t> &C);
	static void UnPackPk(PolyVec &Pk, std::vector<uint8_t> &Seed, const std::vector<uint8_t> &PackedPk);
	static void UnPackSk(PolyVec &Sk, const std::vector<uint8_t> &PackedSk);

#if defined(CEX_HAS_AVX2)
	static void Cbd2Avx2(Poly &R, const std::vector<uint8_t> &Buf);
	static void CmovAvx2(std::vector<uint8_t> &R, const std::vector<uint8_t> &X, size_t XOffset, size_t Length, uint8_t B);
	static void GenMatrixAvx2(std::vector<PolyVec> &A, const std::vector<uint8_t> &Seed, int32_t transposed, uint32_t K);
	static void PolyAddAvx2(Poly &R, const Poly &A, const Poly &B);
	static void PolyCompressAvx2P128(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyCompressAvx2P160(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyFromMsgAvx2(Poly &R, const std::vector<uint8_t> &Msg);
	static void PolyVecDecompressAvx2(PolyVec &R, const std::vector<uint8_t> &A);
	static void PolyDecompressAvx2P128(Poly &R, const std::vector<uint8_t> & A, size_t AOffset);
	static void PolyDecompressAvx2P160(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyDecompress10Avx2P320(Poly& R, const std::vector<uint8_t>& A, size_t AOffset);
	static void PolyDecompress11Avx2P352(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolySubAvx2(Poly &R, const Poly &A, const Poly &B);
	static uint32_t RejUniformAvx2(Poly &R, const std::vector<uint8_t> &Buf);
	static int32_t VerifyAvx2(const std::vector<uint8_t>& A, const std::vector<uint8_t>& B, size_t Length);
#else
	static void Cbd2(Poly& R, const std::vector<uint8_t>& Buf);
	static void PolyAdd(Poly& R, const Poly& A, const Poly& B);
	static void PolyCompress(std::vector<uint8_t>& R, size_t ROffset, const Poly& A, uint32_t K);
	static void PolyDecompress(Poly& R, const std::vector<uint8_t>& A, size_t AOffset, uint32_t K);
	static void PolyFromMsg(Poly& R, const std::vector<uint8_t>& Msg);
	static void PolySub(Poly& R, const Poly& A, const Poly& B);
	static void PolyVecDecompress(PolyVec& R, const std::vector<uint8_t>& A);

#endif
};
NAMESPACE_KYBEREND
#endif
