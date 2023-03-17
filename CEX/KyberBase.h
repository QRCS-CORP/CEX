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
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#if defined(CEX_HAS_AVX)
#	include "Intrinsics.h"
#endif

NAMESPACE_KYBER

using Tools::IntegerTools;
using Prng::IPrng;
using Digest::Keccak;
using Tools::MemoryTools;

/// 
/// internal
/// 

/// <summary>
// An internal Kyber utilities class
/// </summary>
class KyberBase
{
private:
	
	static const int32_t KYBER_N = 256;
	static const int32_t KYBER_Q = 3329;
	static const int32_t KYBER_ETA2 = 2;
	static const int32_t KYBER_MSGBYTES = 32;
	static const int32_t KYBER_SYMBYTES = 32;
	static const int32_t KYBER_POLYBYTES = 384;
	static const int32_t KYBER_ZETA_SIZE = 128;
	static const int32_t KYBER_MONT = 2285;     // 2^16 mod q
	static const int32_t KYBER_QINV = 62209;    // q^-1 mod 2^16
	static const uint32_t GEN_MATRIX_NBLOCKS = ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + Keccak::KECCAK128_RATE_SIZE) / Keccak::KECCAK128_RATE_SIZE);

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
	
	//~~~Parameter Sets~~~//

	/// <summary>
	/// The Kyber S1 1632 parameter set
	/// </summary>
	class Params1632
	{
	public:

		static const size_t KYBER_PUBLICKEY_SIZE = 800;
		static const size_t KYBER_PRIVATEKEY_SIZE = 1632;
		static const size_t KYBER_CIPHERTEXT_SIZE = 768;
		static const uint32_t KYBER_K = 2;
		static const uint32_t KYBER_ETA1 = 3;
		static const uint32_t KYBER_POLYCOMPRESSED_BYTES = 128;
		static const uint32_t KYBER_POLYVECBASE_BYTES = 320;
	};
	
	/// <summary>
	/// The Kyber S3 2400 parameter set
	/// </summary>
	class Params2400
	{
	public:

		static const size_t KYBER_PUBLICKEY_SIZE = 1184;
		static const size_t KYBER_PRIVATEKEY_SIZE = 2400;
		static const size_t KYBER_CIPHERTEXT_SIZE = 1088;
		static const uint32_t KYBER_K = 3;
		static const uint32_t KYBER_ETA1 = 2;
		static const uint32_t KYBER_POLYCOMPRESSED_BYTES = 128;
		static const uint32_t KYBER_POLYVECBASE_BYTES = 320;
	};
				
	/// <summary>
	/// The Kyber S5 3168 parameter set
	/// </summary>
	class Params3168
	{
	public:

		static const size_t KYBER_PUBLICKEY_SIZE = 1568;
		static const size_t KYBER_PRIVATEKEY_SIZE = 3168;
		static const size_t KYBER_CIPHERTEXT_SIZE = 1568;
		static const uint32_t KYBER_K = 4;
		static const uint32_t KYBER_ETA1 = 2;
		static const uint32_t KYBER_POLYCOMPRESSED_BYTES = 160;
		static const uint32_t KYBER_POLYVECBASE_BYTES = 352;
	};
					
	/// <summary>
	/// The Kyber S6 3936 parameter set
	/// </summary>
	class Params3936
	{
	public:

		static const size_t KYBER_PUBLICKEY_SIZE = 1952;
		static const size_t KYBER_PRIVATEKEY_SIZE = 3936;
		static const size_t KYBER_CIPHERTEXT_SIZE = 1920;
		static const uint32_t KYBER_K = 5;
		static const uint32_t KYBER_ETA1 = 2;
		static const uint32_t KYBER_POLYCOMPRESSED_BYTES = 160;
		static const uint32_t KYBER_POLYVECBASE_BYTES = 352;
	};
	
	template<typename T>
	static void IndCpaKeyPair(T &Params, std::vector<uint8_t> &Pk, std::vector<uint8_t> &Sk, std::unique_ptr<IPrng> &Rng)
	{
		std::vector<PolyVec> A(Params.KYBER_K);
		PolyVec e;
		PolyVec pkpv;
		PolyVec skpv;
		std::vector<uint8_t> buf(2 * KYBER_SYMBYTES);
		size_t i;
		uint8_t nonce;

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			A[i].vec.resize(Params.KYBER_K);
		}

		e.vec.resize(Params.KYBER_K);
		pkpv.vec.resize(Params.KYBER_K);
		skpv.vec.resize(Params.KYBER_K);

		nonce = 0;
		Rng->Generate(buf, 0, KYBER_SYMBYTES);
		Keccak::Compute(buf, 0, KYBER_SYMBYTES, buf, 0, Keccak::KECCAK512_RATE_SIZE);
		GenMatrix(A, buf, 0, Params.KYBER_K);

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyGetNoiseEta1(skpv.vec[i], buf, KYBER_SYMBYTES, nonce, Params.KYBER_ETA1);
			++nonce;
		}

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyGetNoiseEta1(e.vec[i], buf, KYBER_SYMBYTES, nonce, Params.KYBER_ETA1);
			++nonce;
		}

		PolyVecNtt(skpv);
		PolyVecNtt(e);

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyVecBaseMulAccMontgomery(pkpv.vec[i], A[i], skpv);
			PolyToMont(pkpv.vec[i]);
		}

		PolyVecAdd(pkpv, pkpv, e);
		PolyVecReduce(pkpv);
		PackSk(Sk, skpv);
		PackPk(Pk, pkpv, buf);
	}

	template<typename T>
	static void IndCpaEnc(T &Params, std::vector<uint8_t> &C, const std::vector<uint8_t> &M, const std::vector<uint8_t> &Pk, const std::vector<uint8_t> &Coins, size_t COffset)
	{
		PolyVec sp;
		PolyVec pkpv;
		PolyVec ep;
		std::vector<PolyVec> at(Params.KYBER_K);
		PolyVec b;
		Poly v;
		Poly k;
		Poly epp;
		std::vector<uint8_t> seed(KYBER_SYMBYTES);
		size_t i;
		uint8_t nonce;

		sp.vec.resize(Params.KYBER_K);
		pkpv.vec.resize(Params.KYBER_K);
		ep.vec.resize(Params.KYBER_K);
		b.vec.resize(Params.KYBER_K);

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			at[i].vec.resize(Params.KYBER_K);
		}

		nonce = 0;
		UnPackPk(pkpv, seed, Pk);
		PolyFromMsg(k, M);
		GenMatrix(at, seed, 1, Params.KYBER_K);

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyGetNoiseEta1(sp.vec[i], Coins, COffset, nonce, Params.KYBER_ETA1);
			++nonce;
		}

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyGetNoiseEta2(ep.vec[i], Coins, COffset, nonce);
			++nonce;
		}

		PolyGetNoiseEta2(epp, Coins, COffset, nonce);
		PolyVecNtt(sp);

		for (i = 0; i < Params.KYBER_K; ++i)
		{
			PolyVecBaseMulAccMontgomery(b.vec[i], at[i], sp);
		}

		PolyVecBaseMulAccMontgomery(v, pkpv, sp);
		PolyVecInvNttToMont(b);
		PolyInvNttToMontgomery(v);
		PolyVecAdd(b, b, ep);
		PolyAdd(v, v, epp);
		PolyAdd(v, v, k);

		PolyVecReduce(b);
		PolyReduce(v);
		PackCiphertext(C, b, v, Params.KYBER_K);
	}

	template<typename T>
	static void IndCpaDec(T &Params, std::vector<uint8_t> &M, const std::vector<uint8_t> &C, const std::vector<uint8_t> &Sk)
	{
		PolyVec b;
		PolyVec skpv;
		Poly v;
		Poly mp;

		b.vec.resize(Params.KYBER_K);
		skpv.vec.resize(Params.KYBER_K);

		UnPackCiphertext(b, v, C);
		UnPackSk(skpv, Sk);
		PolyVecNtt(b);
		PolyVecBaseMulAccMontgomery(mp, skpv, b);
		PolyInvNttToMontgomery(mp);
		PolySub(mp, v, mp);

		PolyReduce(mp);
		PolyToMsg(M, mp);
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Extracts the shared secret for a given cipher-text and private-key
	/// </summary>
	/// 
	/// <param name="Params">The cipher parameters</param>
	/// <param name="PrivateKey">The private-key vector</param>
	/// <param name="CipherText">The input cipher-text vector</param>
	/// <param name="SharedSecret">The output shared-secret (a vector of KYBER_SECRET_SIZE bytes)</param>
	/// 
	/// <returns>The message was decrypted succesfully, fails on authentication failure</returns>
	template<typename T>
	static bool Decapsulate(T &Params, const std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret)
	{
		const size_t SKILEN = (Params.KYBER_K * KYBER_POLYBYTES);
		const size_t PKILEN = (Params.KYBER_K * KYBER_POLYBYTES) + KYBER_SYMBYTES;
		const size_t SKPLEN = SKILEN + PKILEN + (2 * KYBER_SYMBYTES);
		std::vector<uint8_t> buf(2 * KYBER_SYMBYTES);
		std::vector<uint8_t> cmp(CipherText.size());
		std::vector<uint8_t> kr(2 * KYBER_SYMBYTES);
		std::vector<uint8_t> pk(PrivateKey.size() - SKILEN);
		int32_t fail;

		MemoryTools::Copy(PrivateKey, SKILEN, pk, 0, pk.size());
		IndCpaDec(Params, buf, CipherText, PrivateKey);

		// multitarget countermeasure for coins + contributory kem
		MemoryTools::Copy(PrivateKey, SKPLEN - (2 * KYBER_SYMBYTES), buf, KYBER_SYMBYTES, KYBER_SYMBYTES);
		Keccak::Compute(buf, 0, 2 * KYBER_SYMBYTES, kr, 0, Keccak::KECCAK512_RATE_SIZE);
		// coins are in kr+KYBER_SYMBYTES
		IndCpaEnc(Params, cmp, buf, pk, kr, KYBER_SYMBYTES);

	#if defined(CEX_HAS_AVX2)
		fail = VerifyAvx2(CipherText, cmp, CipherText.size());
	#else
		fail = IntegerTools::Verify(CipherText, cmp, CipherText.size());
	#endif

		// overwrite coins in kr with H(c)
		Keccak::Compute(CipherText, 0, CipherText.size(), kr, KYBER_SYMBYTES, Keccak::KECCAK256_RATE_SIZE);

		// overwrite pre-k with z on re-encryption failure
	#if defined(CEX_HAS_AVX2)
		CmovAvx2(kr, PrivateKey, SKPLEN - KYBER_SYMBYTES, KYBER_SYMBYTES, static_cast<uint8_t>(fail));
	#else
		IntegerTools::CMov(PrivateKey, SKPLEN - KYBER_SYMBYTES, kr, 0, KYBER_SYMBYTES, static_cast<uint8_t>(fail));
	#endif

		// hash concatenation of pre-k and H(c) to k 
		Keccak::XOFP1600(kr, 0, 2 * KYBER_SYMBYTES, SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);

		return (fail == 0);
	}

	/// <summary>
	/// Generates the cipher-text and shared-secret for a given public key
	/// </summary>
	///
	/// <param name="Params">The cipher parameters</param>
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="CipherText">The output cipher-text vector</param>
	/// <param name="SharedSecret">The output shared-secret (an array of KYBER_SECRET_SIZE bytes)</param>
	/// <param name="Rng">The random generator instance</param>
	template<typename T>
	static void Encapsulate(T &Params, const std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret, std::unique_ptr<IPrng> &Rng)
	{
		std::vector<uint8_t> buf(2 * KYBER_SYMBYTES);
		std::vector<uint8_t> kr(2 * KYBER_SYMBYTES);

		Rng->Generate(buf, 0, KYBER_SYMBYTES);
		// don't release system RNG output
		Keccak::Compute(buf, 0, KYBER_SYMBYTES, buf, 0, Keccak::KECCAK256_RATE_SIZE);

		// multitarget countermeasure for coins + contributory KEM
		Keccak::Compute(PublicKey, 0, PublicKey.size(), buf, KYBER_SYMBYTES, Keccak::KECCAK256_RATE_SIZE);
		Keccak::Compute(buf, 0, 2 * KYBER_SYMBYTES, kr, 0, Keccak::KECCAK512_RATE_SIZE);

		// coins are in kr+KYBER_SYMBYTES
		IndCpaEnc(Params, CipherText, buf, PublicKey, kr, KYBER_SYMBYTES);

		// overwrite coins in kr with H(c)
		Keccak::Compute(CipherText, 0, CipherText.size(), kr, KYBER_SYMBYTES, Keccak::KECCAK256_RATE_SIZE);
		// hash concatenation of pre-k and H(c) to k
		Keccak::XOFP1600(kr, 0, 2 * KYBER_SYMBYTES, SharedSecret, 0, SharedSecret.size(), Keccak::KECCAK256_RATE_SIZE);
	}

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="Params">The cipher parameters</param>
	/// <param name="PublicKey">The public-key vector</param>
	/// <param name="PrivateKey">The private-key vector</param>
	/// <param name="Rng">The random generator instance</param>
	/// 
	/// <returns>The key-pair was generated succesfully, or false for generation failure</returns>
	template<typename T>
	static void Generate(T &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng)
	{
		const size_t SKILEN = (Params.KYBER_K * KYBER_POLYBYTES);
		const size_t PKILEN = (Params.KYBER_K * KYBER_POLYBYTES) + KYBER_SYMBYTES;
		const size_t SKPLEN = SKILEN + PKILEN + (2 * KYBER_SYMBYTES);

		IndCpaKeyPair(Params, PublicKey, PrivateKey, Rng);
		MemoryTools::Copy(PublicKey, 0, PrivateKey, SKILEN, PublicKey.size());
		Keccak::Compute(PublicKey, 0, PublicKey.size(), PrivateKey, PKILEN + SKILEN, Keccak::KECCAK256_RATE_SIZE);
		// value z for pseudo-random output on reject
		Rng->Generate(PrivateKey, SKPLEN - KYBER_SYMBYTES, KYBER_SYMBYTES);
	}

private:

	static int16_t BarrettReduce(int16_t A);
	static void BaseMul(int16_t R[2], const int16_t A[2], const int16_t B[2], int16_t Zeta);
	static void Cbd2(Poly &R, const std::vector<uint8_t> &Buf);
	static void Cbd3(Poly &R, const std::vector<uint8_t> &Buf);
	static int16_t FqMul(int16_t A, int16_t B);
	static void GenMatrix(std::vector<PolyVec> &A, const std::vector<uint8_t> &Seed, int32_t Transposed, uint32_t K);
	static void InvNtt(Poly &R);
	static int16_t MontgomeryReduce(int32_t A);
	static void Ntt(Poly &R);
	static void PackCiphertext(std::vector<uint8_t> &R, const PolyVec &B, const Poly &V, uint32_t K);
	static void PackPk(std::vector<uint8_t> &R, const PolyVec &Pk, const std::vector<uint8_t> &Seed);
	static void PackSk(std::vector<uint8_t> &R, const PolyVec &Sk);
	static void PolyAdd(Poly &R, const Poly &A, const Poly &B);
	static void PolyBaseMulMontgomery(Poly &R, const Poly &A, const Poly &B);
	static void PolyCbdEta1(Poly &R, const std::vector<uint8_t> &Buf, uint32_t Eta1);
	static void PolyCbdEta2(Poly &R, const std::vector<uint8_t> &Buf);
	static void PolyFromBytes(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyFromMsg(Poly &R, const std::vector<uint8_t> &Msg);
	static void PolyGetNoiseEta1(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce, uint32_t Eta1);
	static void PolyGetNoiseEta2(Poly &R, const std::vector<uint8_t> &Seed, size_t SOffset, uint8_t Nonce);
	static void PolyInvNttToMontgomery(Poly &R);
	static void PolyNttv2(Poly &R);
	static void PolyReduce(Poly &R);
	static void PolySub(Poly &R, const Poly &A, const Poly &B);
	static void PolyToBytes(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyToMont(Poly &R);
	static void PolyToMsg(std::vector<uint8_t> &Msg, const Poly &A);
	static void PolyVecAdd(PolyVec &R, const PolyVec &A, const PolyVec &B);
	static void PolyVecBaseMulAccMontgomery(Poly &R, const PolyVec &A, const PolyVec &B);
	static void PolyVecCompress(std::vector<uint8_t> &R, const PolyVec &A);
	static void PolyVecDecompress(PolyVec &R, const std::vector<uint8_t> &A);
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
	static void CmovAvx2(std::vector<uint8_t> &R, const std::vector<uint8_t> &X, size_t XOffset, size_t Length, uint8_t B);
	static void PolyCompressAvx2P128(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyCompressAvx2P160(std::vector<uint8_t> &R, size_t ROffset, const Poly &A);
	static void PolyDecompressAvx2P128(Poly &R, const std::vector<uint8_t>  &A, size_t AOffset);
	static void PolyDecompressAvx2P160(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyDecompress10Avx2P320(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static void PolyDecompress11Avx2P352(Poly &R, const std::vector<uint8_t> &A, size_t AOffset);
	static uint32_t RejUniformAvx2(Poly &R, const std::vector<uint8_t> &Buf);
	static int32_t VerifyAvx2(const std::vector<uint8_t> &A, const std::vector<uint8_t> &B, size_t Length);
#else
	static uint32_t LoadLe24(const std::vector<uint8_t> &X, size_t XOffset);
	static void PolyCompress(std::vector<uint8_t> &R, size_t ROffset, const Poly &A, uint32_t K);
	static void PolyDecompress(Poly &R, const std::vector<uint8_t> &A, size_t AOffset, uint32_t K);
#endif
};
NAMESPACE_KYBEREND
#endif
