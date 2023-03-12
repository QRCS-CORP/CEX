#ifndef CEX_DLTMBASE_H
#define CEX_DLTMBASE_H

#include "CexConfig.h"
#include "DLTMPolyMath.h"
#include "IPrng.h"
#include "Keccak.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

NAMESPACE_DILITHIUM

using DLTM::DLTMPolyMath;
using Digest::Keccak;
using Prng::IPrng;
using Tools::IntegerTools;
using Tools::MemoryTools;

/// <summary>
/// The Dilithium base template class
/// </summary>
class DLTMBase
{
private:

	static const size_t DILITHIUM_SEED_SIZE = 32;
	static const size_t DILITHIUM_CRH_SIZE = 48;
	static const uint32_t DILITHIUM_N = 256;
	static const int32_t DILITHIUM_Q = 8380417;
	static const int32_t DILITHIUM_QBITS = 23;
	static const int32_t DILITHIUM_UNITYROOT = 1753;
	static const int32_t DILITHIUM_D = 13;
	static const int32_t DILITHIUM_MONT = -4186625;	// 2^32 % Q 
	static const int32_t DILITHIUM_QINV = 58728449;	// -q^(-1) mod 2^32 
	static const uint32_t DILITHIUM_SETABITS = 4;
	static const size_t DILITHIUM_POLT0_SIZE_PACKED = 416;
	static const size_t DILITHIUM_POLT1_PACKED_SIZE = 320;

public:
	
	/// <summary>
	/// The Dilithium S1 2544 parameter set
	/// </summary>
	class Params2544
	{
	public:

		static const size_t DILITHIUM_PUBLICKEY_SIZE = 1312;
		static const size_t DILITHIUM_SECRETKEY_SIZE = 2544;
		static const size_t DILITHIUM_SIGNATURE_SIZE = 2420;
		static const uint32_t DILITHIUM_K = 4;
		static const uint32_t DILITHIUM_L = 4;
		static const uint32_t DILITHIUM_ETA = 2;
		static const uint32_t DILITHIUM_TAU = 39;
		static const uint32_t DILITHIUM_BETA = 78;
		static const uint32_t DILITHIUM_GAMMA1 = (1 << 17);
		static const uint32_t DILITHIUM_GAMMA2 = ((DILITHIUM_Q - 1) / 88);
		static const uint32_t DILITHIUM_OMEGA = 80;
		static const uint32_t DILITHIUM_POLYZ_PACKED_SIZE = 576;
		static const uint32_t DILITHIUM_POLW1_PACKED_SIZE = 192;
		static const uint32_t DILITHIUM_POLYETA_PACKED_SIZE = 96;
		static const uint32_t DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS = ((136 + Keccak::KECCAK128_RATE_SIZE - 1) / Keccak::KECCAK128_RATE_SIZE);
		static const uint32_t DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS = ((576 + Keccak::KECCAK256_RATE_SIZE - 1) / Keccak::KECCAK256_RATE_SIZE);
	};

	/// <summary>
	/// The Dilithium S3 4016 parameter set
	/// </summary>
	class Params4016
	{
	public:
		static const size_t DILITHIUM_PUBLICKEY_SIZE = 1952;
		static const size_t DILITHIUM_SECRETKEY_SIZE = 4016;
		static const size_t DILITHIUM_SIGNATURE_SIZE = 3293;
		static const uint32_t DILITHIUM_K = 6;
		static const uint32_t DILITHIUM_L = 5;
		static const uint32_t DILITHIUM_ETA = 4;
		static const uint32_t DILITHIUM_TAU = 49;
		static const uint32_t DILITHIUM_BETA = 196;
		static const uint32_t DILITHIUM_GAMMA1 = (1 << 19);
		static const uint32_t DILITHIUM_GAMMA2 = ((DILITHIUM_Q - 1) / 32);
		static const uint32_t DILITHIUM_OMEGA = 55;
		static const uint32_t DILITHIUM_POLYZ_PACKED_SIZE = 640;
		static const uint32_t DILITHIUM_POLW1_PACKED_SIZE = 128;
		static const uint32_t DILITHIUM_POLYETA_PACKED_SIZE = 128;
		static const uint32_t DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS = ((227 + Keccak::KECCAK128_RATE_SIZE - 1) / Keccak::KECCAK128_RATE_SIZE);
		static const uint32_t DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS = ((640 + Keccak::KECCAK256_RATE_SIZE - 1) / Keccak::KECCAK256_RATE_SIZE);
	};

	/// <summary>
	/// The Dilithium S5 4880 parameter set
	/// </summary>
	class Params4880
	{
	public:

		static const size_t DILITHIUM_PUBLICKEY_SIZE = 2592;
		static const size_t DILITHIUM_SECRETKEY_SIZE = 4880;
		static const size_t DILITHIUM_SIGNATURE_SIZE = 4595;
		static const uint32_t DILITHIUM_K = 8;
		static const uint32_t DILITHIUM_L = 7;
		static const uint32_t DILITHIUM_ETA = 2;
		static const uint32_t DILITHIUM_TAU = 60;
		static const uint32_t DILITHIUM_BETA = 120;
		static const uint32_t DILITHIUM_GAMMA1 = (1 << 19);
		static const uint32_t DILITHIUM_GAMMA2 = ((DILITHIUM_Q - 1) / 32);
		static const uint32_t DILITHIUM_OMEGA = 75;
		static const uint32_t DILITHIUM_POLYZ_PACKED_SIZE = 640;
		static const uint32_t DILITHIUM_POLW1_PACKED_SIZE = 128;
		static const uint32_t DILITHIUM_POLYETA_PACKED_SIZE = 96;
		static const uint32_t DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS = ((136 + Keccak::KECCAK128_RATE_SIZE - 1) / Keccak::KECCAK128_RATE_SIZE);
		static const uint32_t DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS = ((640 + Keccak::KECCAK256_RATE_SIZE - 1) / Keccak::KECCAK256_RATE_SIZE);
	};

	/// <summary>
	/// Generate a public/private key-set
	/// </summary>
	/// 
	/// <param name="Params">The implementation parameter set</param>
	/// <param name="PublicKey">The output public key vector</param>
	/// <param name="PrivateKey">The output private key vector</param>
	/// <param name="Rng">The initialized PRNG used by the function</param>
#if defined(CEX_HAS_AVX2)
	template<typename T>
	static void Generate(T &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> s1(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> s2(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> t(T::DILITHIUM_K);
		std::array<int32_t, DILITHIUM_N> t0;
		std::array<int32_t, DILITHIUM_N> t1;
		std::vector<uint8_t> key(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> rhoprime(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> sbuf(3 * DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> seed(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> tr(DILITHIUM_CRH_SIZE);
		size_t i;
		uint16_t nonce;

		// expand 32 bytes of randomness into rho, rhoprime and key
		Rng->Generate(seed, 0, DILITHIUM_SEED_SIZE);
		Keccak::XOFP1600(seed, 0, DILITHIUM_SEED_SIZE, sbuf, 0, 3 * DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);
		MemoryTools::Copy(sbuf, 0, rho, 0, rho.size());
		MemoryTools::Copy(sbuf, DILITHIUM_SEED_SIZE, rhoprime, 0, rhoprime.size());
		MemoryTools::Copy(sbuf, (2 * DILITHIUM_SEED_SIZE), key, 0, key.size());

		// store rho and key
		MemoryTools::Copy(rho, 0, PublicKey, 0, DILITHIUM_SEED_SIZE);
		MemoryTools::Copy(rho, 0, PrivateKey, 0, DILITHIUM_SEED_SIZE);
		MemoryTools::Copy(key, 0, PrivateKey, DILITHIUM_SEED_SIZE, DILITHIUM_SEED_SIZE);
	
		nonce = 0;

		// expand matrix
		if (T::DILITHIUM_K == 4 && T::DILITHIUM_L == 4)
		{
			DLTMPolyMath::PolyUniformEta4x(s1[0], s1[1], s1[2], s1[3], rhoprime, 0, 1, 2, 3, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s2[0], s2[1], s2[2], s2[3], rhoprime, 4, 5, 6, 7, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
		}
		else if (T::DILITHIUM_K == 6 && T::DILITHIUM_L == 5)
		{
			DLTMPolyMath::PolyUniformEta4x(s1[0], s1[1], s1[2], s1[3], rhoprime, 0, 1, 2, 3, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s1[4], s2[0], s2[1], s2[2], rhoprime, 4, 5, 6, 7, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s2[3], s2[4], s2[5], t0, rhoprime, 8, 9, 10, 11, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
		}
		else if (T::DILITHIUM_K == 8 && T::DILITHIUM_L == 7)
		{
			DLTMPolyMath::PolyUniformEta4x(s1[0], s1[1], s1[2], s1[3], rhoprime, 0, 1, 2, 3, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s1[4], s1[5], s1[6], s2[0], rhoprime, 4, 5, 6, 7, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s2[1], s2[2], s2[3], s2[4], rhoprime, 8, 9, 10, 11, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
			DLTMPolyMath::PolyUniformEta4x(s2[5], s2[6], s2[7], t0, rhoprime, 12, 13, 14, 15, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, T::DILITHIUM_ETA);
		}

		// pack secret vectors
		for (i = 0; i < T::DILITHIUM_L; i++)
		{
			DLTMPolyMath::PolyEtaPack(PrivateKey, 2 * DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE + i * T::DILITHIUM_POLYETA_PACKED_SIZE, s1[i], T::DILITHIUM_ETA);
		}

		for (i = 0; i < T::DILITHIUM_K; i++)
		{
			DLTMPolyMath::PolyEtaPack(PrivateKey, 2 * DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE + (T::DILITHIUM_L + i) * T::DILITHIUM_POLYETA_PACKED_SIZE, s2[i], T::DILITHIUM_ETA);
		}

		// transform s1
		DLTMPolyMath::PolyVecNtt(s1);

		for (i = 0; i < T::DILITHIUM_K; i++)
		{
			// expand matrix row
			DLTMPolyMath::PolyVecMatrixExpandRow(mat, rho, T::DILITHIUM_K, T::DILITHIUM_L, i);
			// compute inner-product
			DLTMPolyMath::PolyVecMatrixPointwiseMont(t1, mat[i], s1);
			DLTMPolyMath::PolyInvNttMont(t1);
			// add error polynomial
			DLTMPolyMath::PolyAdd(t1, t1, s2[i]);
			// round t and pack t1, t0
			DLTMPolyMath::PolyCaddQ(t1);
			DLTMPolyMath::PolyPower2Round(t1, t0, t1);
			DLTMPolyMath::PolyT1Pack(PublicKey, DILITHIUM_SEED_SIZE + i * DILITHIUM_POLT1_PACKED_SIZE, t1);
			DLTMPolyMath::PolyT0Pack(PrivateKey, 2 * DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE + (T::DILITHIUM_L + T::DILITHIUM_K) * T::DILITHIUM_POLYETA_PACKED_SIZE + i * DILITHIUM_POLT0_SIZE_PACKED, t0);
		}

		// compute CRH(rho, t1) and write secret key 
		Keccak::XOFP1600(PublicKey, 0, T::DILITHIUM_PUBLICKEY_SIZE, tr, 0, tr.size(), Keccak::KECCAK256_RATE_SIZE);
		MemoryTools::Copy(tr, 0, PrivateKey, 2 * DILITHIUM_SEED_SIZE, DILITHIUM_CRH_SIZE);
	}
#else
	template<typename T>
	static void Generate(T &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> s1(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> s1hat(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> s2(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> t(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> t0(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> t1(T::DILITHIUM_K);
		std::vector<uint8_t> key(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> rhoprime(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> sbuf(3 * DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> seed(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> tr(DILITHIUM_CRH_SIZE);
		size_t i;
		uint16_t nonce;

		// expand 32 bytes of randomness into rho, rhoprime and key
		Rng->Generate(seed, 0, DILITHIUM_SEED_SIZE);
		Keccak::XOFP1600(seed, 0, DILITHIUM_SEED_SIZE, sbuf, 0, 3 * DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);

		MemoryTools::Copy(sbuf, 0, rho, 0, rho.size());
		MemoryTools::Copy(sbuf, DILITHIUM_SEED_SIZE, rhoprime, 0, rhoprime.size());
		MemoryTools::Copy(sbuf, (2 * DILITHIUM_SEED_SIZE), key, 0, key.size());
	
		// expand matrix
		DLTMPolyMath::ExpandMat(mat, rho);
		nonce = 0;

		// sample int16_t vectors s1 and s2 
		for (i = 0; i < s1.size(); ++i)
		{
			DLTMPolyMath::PolyUniformEta(s1[i], rhoprime, nonce, T::DILITHIUM_ETA, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS);
			++nonce;
		}

		for (i = 0; i < s2.size(); ++i)
		{
			DLTMPolyMath::PolyUniformEta(s2[i], rhoprime, nonce, T::DILITHIUM_ETA, T::DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS);
			++nonce;
		}
		// matrix-vector multiplication 
		s1hat = s1;
		DLTMPolyMath::PolyVecNtt(s1hat);

		for (i = 0; i < t.size(); ++i)
		{
			DLTMPolyMath::PolyVecMatrixPointwiseMont(t[i], mat[i], s1hat);
		}

		DLTMPolyMath::PolyVecReduce(t);
		DLTMPolyMath::PolyVecInvNttMont(t);

		// add error vector s2 
		DLTMPolyMath::PolyVecAdd(t, t, s2);

		// extract t1 and write public key
		DLTMPolyMath::PolyVecCaddQ(t);
		DLTMPolyMath::PolyVecPower2Round(t1, t0, t);
		DLTMPolyMath::PackPk(PublicKey, rho, t1, DILITHIUM_POLT1_PACKED_SIZE);

		// compute CRH(rho, t1) and write secret key 
		Keccak::XOFP1600(PublicKey, 0, T::DILITHIUM_PUBLICKEY_SIZE, tr, 0, tr.size(), Keccak::KECCAK256_RATE_SIZE);
		DLTMPolyMath::PackSk(PrivateKey, rho, key, tr, s1, s2, t0, T::DILITHIUM_ETA, T::DILITHIUM_POLYETA_PACKED_SIZE, DILITHIUM_POLT0_SIZE_PACKED);
	}
#endif
	
	/// <summary>
	/// Sign a message using the private key
	/// </summary>
	/// 
	/// <param name="Params">The implementation parameter set</param>
	/// <param name="Signature">The output signed message</param>
	/// <param name="Message">The message to sign</param>
	/// <param name="PrivateKey">The private key</param>
	/// <param name="Rng">The initialized PRNG used by the function</param>
#if defined(CEX_HAS_AVX2)
	template<typename T>
	static void Sign(T &Params, std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> s1(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> y(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> z(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> t0(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> s2(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w0(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w1(T::DILITHIUM_K);
		std::array<int32_t, DILITHIUM_N> cp = { 0 };
		std::array<int32_t, DILITHIUM_N> h = { 0 };
		std::array<uint64_t, 25> kctx = { 0 };
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> tr(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> key(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> mu(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> rhoprime(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> sbuf(2 * DILITHIUM_SEED_SIZE + 3 * DILITHIUM_CRH_SIZE);
		const size_t HNTPOS = DILITHIUM_SEED_SIZE + T::DILITHIUM_L * T::DILITHIUM_POLYZ_PACKED_SIZE;
		size_t i;
		size_t j;
		size_t pos;
		uint32_t n;
		uint16_t nonce;
		bool res;

		n = 0;
		nonce = 0;
		
		DLTMPolyMath::UnpackSk(rho, tr, key, t0, s1, s2, PrivateKey, T::DILITHIUM_ETA, T::DILITHIUM_POLYETA_PACKED_SIZE, DILITHIUM_POLT0_SIZE_PACKED);

		// compute CRH(tr, msg)
		Keccak::Incremental(tr, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
		Keccak::Incremental(Message, 0, Message.size(), DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
		Keccak::SqueezePartial(kctx, mu, 0, mu.size(), Keccak::KECCAK256_RATE_SIZE);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
		Rng->Generate(rhoprime, 0, DILITHIUM_CRH_SIZE);
#else
		MemoryTools::Copy(key, 0, sbuf, 0, DILITHIUM_SEED_SIZE);
		MemoryTools::Copy(mu, 0, sbuf, DILITHIUM_SEED_SIZE, DILITHIUM_CRH_SIZE);
		Keccak::XOFP1600(sbuf, 0, DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE, rhoprime, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);
#endif
		
		// expand matrix and transform vectors 
		DLTMPolyMath::PolyVecMatrixExpandAvx2(mat, rho, T::DILITHIUM_K, T::DILITHIUM_L);
		DLTMPolyMath::PolyVecNtt(s1);
		DLTMPolyMath::PolyVecNtt(s2);
		DLTMPolyMath::PolyVecNtt(t0);
		
		while (true)
		{
			res = true;

			if (T::DILITHIUM_L == 4)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				nonce += 4;
			}
			else if (T::DILITHIUM_L == 5)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				DLTMPolyMath::PolyUniformGamma1M1(y[4], rhoprime, nonce + 4, T::DILITHIUM_GAMMA1);
				nonce += 5;
			}
			else if (T::DILITHIUM_L == 7)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				DLTMPolyMath::PolyUniformGamma1x4(y[4], y[5], y[6], h, rhoprime, nonce + 4, nonce + 5, nonce + 6, 0, T::DILITHIUM_GAMMA1);
				nonce += 7;
			}

			// save y and transform it
			z = y;
			DLTMPolyMath::PolyVecNtt(y);

			// matrix-vector multiplication 
			for (i = 0; i < w.size(); ++i)
			{
				DLTMPolyMath::PolyVecMatrixPointwiseMont(w1[i], mat[i], y);
				DLTMPolyMath::PolyInvNttMont(w1[i]);
				DLTMPolyMath::PolyCaddQ(w1[i]);
				DLTMPolyMath::PolyDecompose(w1[i], w0[i], w1[i], T::DILITHIUM_GAMMA2);
				DLTMPolyMath::PolyW1Pack(Signature, i * T::DILITHIUM_POLW1_PACKED_SIZE, w1[i], T::DILITHIUM_GAMMA2);
			}
			
			// call the random oracle
			MemoryTools::Clear(kctx, 0, Keccak::KECCAK_STATE_BYTE_SIZE);
			Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
			Keccak::Incremental(Signature, 0, T::DILITHIUM_K * T::DILITHIUM_POLW1_PACKED_SIZE, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
			Keccak::SqueezePartial(kctx, Signature, 0, DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);

			DLTMPolyMath::PolyChallenge(cp, Signature, T::DILITHIUM_TAU);
			DLTMPolyMath::PolyNtt(cp);

			// compute z, reject if it reveals secret
			for (i = 0; i < T::DILITHIUM_L; ++i)
			{
				DLTMPolyMath::PolyPointwiseMont(h, cp, s1[i]);
				DLTMPolyMath::PolyInvNttMont(h);
				DLTMPolyMath::PolyAdd(z[i], z[i], h);
				DLTMPolyMath::PolyReduce(z[i]);

				if (DLTMPolyMath::PolyChkNorm(z[i], T::DILITHIUM_GAMMA1 - T::DILITHIUM_BETA))
				{
					res = false;
					break;
				}
			}

			if (res == true)
			{
				// zero hint in signature
				n = 0;
				pos = 0;
				MemoryTools::Clear(Signature, HNTPOS, T::DILITHIUM_OMEGA + T::DILITHIUM_K);

				for (i = 0; i < T::DILITHIUM_K; ++i)
				{
					// check that subtracting cs2 does not change high bits of w and low bits do not reveal secret information
					DLTMPolyMath::PolyPointwiseMont(h, cp, s2[i]);
					DLTMPolyMath::PolyInvNttMont(h);
					DLTMPolyMath::PolySub(w0[i], w0[i], h);
					DLTMPolyMath::PolyReduce(w0[i]);;

					if (DLTMPolyMath::PolyChkNorm(w0[i], T::DILITHIUM_GAMMA2 - T::DILITHIUM_BETA))
					{
						res = false;
						break;
					}

					// compute hints
					DLTMPolyMath::PolyPointwiseMont(h, cp, t0[i]);
					DLTMPolyMath::PolyInvNttMont(h);
					DLTMPolyMath::PolyReduce(h);

					if (DLTMPolyMath::PolyChkNorm(h, T::DILITHIUM_GAMMA2))
					{
						res = false;
						break;
					}

					DLTMPolyMath::PolyAdd(w0[i], w0[i], h);
					DLTMPolyMath::PolyCaddQ(w0[i]);
					n += DLTMPolyMath::PolyMakeHint(h, w0[i], w1[i], T::DILITHIUM_GAMMA2);

					if (n > T::DILITHIUM_OMEGA)
					{
						res = false;
						break;
					}

					// store hints in signature
					for (j = 0; j < DILITHIUM_N; ++j)
					{
						if (h[j] != 0)
						{
							Signature[HNTPOS + pos] = (uint8_t)j;
							++pos;
						}
					}

					Signature[HNTPOS + T::DILITHIUM_OMEGA + i] = (uint8_t)pos;
				}
			}

			if (res == false)
			{
				continue;
			}

			// pack z into signature
			for (i = 0; i < T::DILITHIUM_L; i++)
			{
				DLTMPolyMath::PolyZPack(Signature, DILITHIUM_SEED_SIZE + i * T::DILITHIUM_POLYZ_PACKED_SIZE, z[i], T::DILITHIUM_GAMMA1);
			}

			break;
		}

		MemoryTools::Copy(Message, 0, Signature, T::DILITHIUM_SIGNATURE_SIZE, Message.size());
	}
#else
	template<typename T>
	static void Sign(T &Params, std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> s1(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> y(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> z(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> t0(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> s2(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w0(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w1(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> h(T::DILITHIUM_K);
		std::array<int32_t, DILITHIUM_N> cp = { 0 };
		std::array<uint64_t, 25> kctx = { 0 };
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> tr(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> key(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> mu(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> rhoprime(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> sbuf(0);
		size_t i;
		uint32_t n;
		uint16_t nonce;

		n = 0;
		nonce = 0;

		DLTMPolyMath::UnpackSk(rho, tr, key, t0, s1, s2, PrivateKey, T::DILITHIUM_ETA, T::DILITHIUM_POLYETA_PACKED_SIZE, DILITHIUM_POLT0_SIZE_PACKED);
		Keccak::Incremental(tr, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
		Keccak::Incremental(Message, 0, Message.size(), DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
		Keccak::SqueezePartial(kctx, mu, 0, mu.size(), Keccak::KECCAK256_RATE_SIZE);

	#ifdef DILITHIUM_RANDOMIZED_SIGNING
		Rng->Generate(rhoprime, 0, DILITHIUM_CRH_SIZE);
	#else
		sbuf.resize(DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE);
		MemoryTools::Copy(key, 0, sbuf, 0, DILITHIUM_SEED_SIZE);
		MemoryTools::Copy(mu, 0, sbuf, DILITHIUM_SEED_SIZE, DILITHIUM_CRH_SIZE);
		Keccak::XOFP1600(sbuf, 0, DILITHIUM_SEED_SIZE + DILITHIUM_CRH_SIZE, rhoprime, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);
	#endif

		// expand matrix and transform vectors 
#if defined(CEX_HAS_AVX2)
		DLTMPolyMath::PolyVecMatrixExpandAvx2(mat, rho, T::DILITHIUM_K, T::DILITHIUM_L);
#else
		DLTMPolyMath::ExpandMat(mat, rho);
#endif
		DLTMPolyMath::PolyVecNtt(s1);
		DLTMPolyMath::PolyVecNtt(s2);
		DLTMPolyMath::PolyVecNtt(t0);

		while (true)
		{
#if defined(CEX_HAS_AVX2)
			if (T::DILITHIUM_L == 4)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				nonce += 4;
			}
			else if (T::DILITHIUM_L == 5)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				DLTMPolyMath::PolyUniformGamma1M1(y[4], rhoprime, nonce + 4, T::DILITHIUM_GAMMA1);
				nonce += 5;
			}
			else if (T::DILITHIUM_L == 7)
			{
				DLTMPolyMath::PolyUniformGamma1x4(y[0], y[1], y[2], y[3], rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3, T::DILITHIUM_GAMMA1);
				DLTMPolyMath::PolyUniformGamma1x4(y[4], y[5], y[6], h[0], rhoprime, nonce + 4, nonce + 5, nonce + 6, 0, T::DILITHIUM_GAMMA1);
				nonce += 7;
			}
#else
			// sample intermediate vector y 
			DLTMPolyMath::PolyVecUniformGamma1M1(y, rhoprime, nonce, T::DILITHIUM_GAMMA1);
			++nonce;
#endif

			// matrix-vector multiplication 
			z = y;
			DLTMPolyMath::PolyVecNtt(z);

			for (i = 0; i < w.size(); ++i)
			{
				DLTMPolyMath::PolyVecMatrixPointwiseMont(w[i], mat[i], z);
			}

			DLTMPolyMath::PolyVecReduce(w);
			DLTMPolyMath::PolyVecInvNttMont(w);

			// decompose w and call the random oracle
			DLTMPolyMath::PolyVecCaddQ(w);
			DLTMPolyMath::PolyVecDecompose(w1, w0, w, T::DILITHIUM_GAMMA2);
			DLTMPolyMath::PolyVecPackW1(Signature, w1, T::DILITHIUM_POLW1_PACKED_SIZE, T::DILITHIUM_GAMMA2);

			MemoryTools::Clear(kctx, 0, Keccak::KECCAK_STATE_BYTE_SIZE);
			Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
			Keccak::Incremental(Signature, 0, T::DILITHIUM_K * T::DILITHIUM_POLW1_PACKED_SIZE, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
			Keccak::SqueezePartial(kctx, Signature, 0, DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);

			DLTMPolyMath::PolyChallenge(cp, Signature, T::DILITHIUM_TAU);
			DLTMPolyMath::PolyNtt(cp);
			DLTMPolyMath::PolyVecPointwiseInvMont(z, cp, s1);
			DLTMPolyMath::PolyVecInvNttMont(z);
			DLTMPolyMath::PolyVecAdd(z, z, y);
			DLTMPolyMath::PolyVecReduce(z);

			if (DLTMPolyMath::PolyVecChkNorm(z, T::DILITHIUM_GAMMA1 - T::DILITHIUM_BETA) != 0)
			{
				continue;
			}

			DLTMPolyMath::PolyVecPointwiseMont(h, cp, s2);
			DLTMPolyMath::PolyVecInvNttMont(h);
			DLTMPolyMath::PolyVecSub(w0, w0, h);
			DLTMPolyMath::PolyVecReduce(w0);

			// Check that subtracting cs2 does not change high bits of w and low bits
			if (DLTMPolyMath::PolyVecChkNorm(w0, T::DILITHIUM_GAMMA2 - T::DILITHIUM_BETA) != 0)
			{
				continue;
			}

			DLTMPolyMath::PolyVecPointwiseMont(h, cp, t0);
			DLTMPolyMath::PolyVecInvNttMont(h);
			DLTMPolyMath::PolyVecReduce(h);

			if (DLTMPolyMath::PolyVecChkNorm(h, T::DILITHIUM_GAMMA2) != 0)
			{
				continue;
			}

			DLTMPolyMath::PolyVecAdd(w0, w0, h);
			DLTMPolyMath::PolyVecCaddQ(w0);
			n = DLTMPolyMath::PolyVecMakeHint(h, w0, w1, T::DILITHIUM_GAMMA2);

			if (n > T::DILITHIUM_OMEGA)
			{
				continue;
			}

			break;
		}

		DLTMPolyMath::PackSig(Signature, Signature, z, h, T::DILITHIUM_K, T::DILITHIUM_OMEGA, T::DILITHIUM_POLYZ_PACKED_SIZE, T::DILITHIUM_GAMMA1);
		MemoryTools::Copy(Message, 0, Signature, T::DILITHIUM_SIGNATURE_SIZE, Message.size());
	}
#endif

	/// <summary>
	/// Verify a signed message
	/// </summary>
	/// 
	/// <param name="Params">The implementation parameter set</param>
	/// <param name="Message">The output message</param>
	/// <param name="Signature">The input signed message</param>
	/// <param name="PublicKey">The public key</param>
	/// 
	/// <returns>Returns true on success</returns>
#if defined(CEX_HAS_AVX2)
	template<typename T>
	static bool Verify(T &Params, std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> z(T::DILITHIUM_L);
		std::vector<uint8_t> buf(T::DILITHIUM_K * T::DILITHIUM_POLW1_PACKED_SIZE);
		std::vector<uint8_t> c(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> mu(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::array<int32_t, DILITHIUM_N> cp = { 0 };
		std::array<int32_t, DILITHIUM_N> h = { 0 };
		std::array<int32_t, DILITHIUM_N> t1;
		std::array<int32_t, DILITHIUM_N> w1;
		std::array<uint64_t, 25> kctx = { 0 };
		const size_t HNTPOS = DILITHIUM_SEED_SIZE + T::DILITHIUM_L * T::DILITHIUM_POLYZ_PACKED_SIZE;
		size_t i;
		size_t j;
		size_t msglen;
		size_t pos;
		bool res;

		res = true;

		if (Signature.size() >= T::DILITHIUM_SIGNATURE_SIZE)
		{
			// compute CRH(CRH(rho, t1), msg)
			Keccak::XOFP1600(PublicKey, 0, T::DILITHIUM_PUBLICKEY_SIZE, mu, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);
			msglen = Signature.size() - T::DILITHIUM_SIGNATURE_SIZE;			
			Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
			Keccak::Incremental(Signature, T::DILITHIUM_SIGNATURE_SIZE, msglen, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
			Keccak::SqueezePartial(kctx, mu, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);

			// expand challenge
			DLTMPolyMath::PolyChallenge(cp, Signature, T::DILITHIUM_TAU);
			DLTMPolyMath::PolyNtt(cp);

			// unpack z; shortness follows from unpacking
			for (i = 0; i < T::DILITHIUM_L; ++i)
			{
				DLTMPolyMath::PolyZUnpack(z[i], Signature, DILITHIUM_SEED_SIZE + i * T::DILITHIUM_POLYZ_PACKED_SIZE, T::DILITHIUM_GAMMA1);
				DLTMPolyMath::PolyNtt(z[i]);
			}
		}
		
        pos = 0;

        for (i = 0; i < T::DILITHIUM_K; ++i)
        {
            // expand matrix row
			DLTMPolyMath::PolyVecMatrixExpandRow(mat, PublicKey, T::DILITHIUM_K, T::DILITHIUM_L, i);

            // compute i-th row of Az - c2^Dt1
			DLTMPolyMath::PolyVecMatrixPointwiseMont(w1, mat[i], z);
			DLTMPolyMath::PolyT1Unpack(t1, PublicKey, DILITHIUM_SEED_SIZE + i * DILITHIUM_POLT1_PACKED_SIZE);
			DLTMPolyMath::PolyShiftL(t1);
			DLTMPolyMath::PolyNtt(t1);
			DLTMPolyMath::PolyPointwiseMont(t1, cp, t1);

			DLTMPolyMath::PolySub(w1, w1, t1);
			DLTMPolyMath::PolyReduce(w1);
			DLTMPolyMath::PolyInvNttMont(w1);

            // get hint polynomial and reconstruct w1
            for (j = 0; j < DILITHIUM_N; ++j)
            {
                h[j] = 0;
            }

            if (Signature[HNTPOS + T::DILITHIUM_OMEGA + i] < pos || Signature[HNTPOS + T::DILITHIUM_OMEGA + i] > T::DILITHIUM_OMEGA)
            {
                res = false;
                break;
            }
			
            for (j = pos; j < Signature[HNTPOS + T::DILITHIUM_OMEGA + i]; ++j)
            {
                // coefficients are ordered for strong unforgeability
                if (j > pos && Signature[HNTPOS + j] <= Signature[HNTPOS + j - 1])
                {
                    res = false;
                    break;
                }

                h[Signature[HNTPOS + j]] = 1;
            }

            if (res == false)
            {
                break;
            }

            pos = Signature[HNTPOS + T::DILITHIUM_OMEGA + i];
			DLTMPolyMath::PolyCaddQ(w1);
			DLTMPolyMath::PolyUseHint(w1, w1, h, T::DILITHIUM_GAMMA2);
			DLTMPolyMath::PolyW1Pack(buf, i * T::DILITHIUM_POLW1_PACKED_SIZE, w1, T::DILITHIUM_GAMMA2);
        }

		if (res == true)
		{
			// extra indices are zero for strong unforgeability
			for (j = pos; j < T::DILITHIUM_OMEGA; ++j)
			{
				if (Signature[HNTPOS + j])
				{
					res = false;
					break;
				}
			}

			if (res == true)
			{
				// call random oracle and verify challenge
				MemoryTools::Clear(kctx, 0, kctx.size() * sizeof(uint64_t));
				Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
				Keccak::Incremental(buf, 0, T::DILITHIUM_K * T::DILITHIUM_POLW1_PACKED_SIZE, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
				Keccak::SqueezePartial(kctx, c, 0, DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);

				res = IntegerTools::Verify(c, Signature, DILITHIUM_SEED_SIZE) == 0;

				// conditional copy of the message from signature
				if (res == true)
				{
					MemoryTools::Copy(Signature, T::DILITHIUM_SIGNATURE_SIZE, Message, 0, msglen);
				}
			}
		}

		return res;
	}
#else
	template<typename T>
	static bool Verify(T &Params, std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey)
	{
		std::vector<std::vector<std::array<int32_t, DILITHIUM_N>>> mat(T::DILITHIUM_K, std::vector<std::array<int32_t, DILITHIUM_N>>(T::DILITHIUM_L));
		std::vector<std::array<int32_t, DILITHIUM_N>> z(T::DILITHIUM_L);
		std::vector<std::array<int32_t, DILITHIUM_N>> h(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> t1(T::DILITHIUM_K);
		std::vector<std::array<int32_t, DILITHIUM_N>> w1(T::DILITHIUM_K);
		std::vector<uint8_t> buf(T::DILITHIUM_K * T::DILITHIUM_POLW1_PACKED_SIZE);
		std::vector<uint8_t> rho(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> mu(DILITHIUM_CRH_SIZE);
		std::vector<uint8_t> c(DILITHIUM_SEED_SIZE);
		std::vector<uint8_t> c2(DILITHIUM_SEED_SIZE);
		std::array<int32_t, DILITHIUM_N> cp;
		std::array<uint64_t, 25> kctx = { 0 };
		size_t i;
		size_t msglen;
		size_t pos;
		bool res;

		res = false;

		if (Signature.size() >= T::DILITHIUM_SIGNATURE_SIZE)
		{
			msglen = Signature.size() - T::DILITHIUM_SIGNATURE_SIZE;
			DLTMPolyMath::UnpackPk(rho, t1, PublicKey, DILITHIUM_POLT1_PACKED_SIZE);
		
			if (DLTMPolyMath::UnpackSig(c, z, h, Signature, T::DILITHIUM_POLYZ_PACKED_SIZE, T::DILITHIUM_GAMMA1, T::DILITHIUM_OMEGA) == 0)
			{
				if (DLTMPolyMath::PolyVecChkNorm(z, T::DILITHIUM_GAMMA1 - T::DILITHIUM_BETA) == 0)
				{
					// compute CRH(CRH(rho, t1), msg)
					Keccak::XOFP1600(PublicKey, 0, T::DILITHIUM_PUBLICKEY_SIZE, mu, 0, mu.size(), Keccak::KECCAK256_RATE_SIZE);
					Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
					Keccak::Incremental(Signature, T::DILITHIUM_SIGNATURE_SIZE, msglen, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
					Keccak::SqueezePartial(kctx, mu, 0, DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE);

					// matrix-vector multiplication; compute Az - c2^dt1
					DLTMPolyMath::PolyChallenge(cp, c, T::DILITHIUM_TAU);
					DLTMPolyMath::ExpandMat(mat, rho);

					DLTMPolyMath::PolyVecNtt(z);

					for (i = 0; i < w1.size(); ++i)
					{
						DLTMPolyMath::PolyVecMatrixPointwiseMont(w1[i], mat[i], z);
					}

					DLTMPolyMath::PolyNtt(cp);
					DLTMPolyMath::PolyVecShiftL(t1);
					DLTMPolyMath::PolyVecNtt(t1);

					for (i = 0; i < t1.size(); ++i)
					{
						DLTMPolyMath::PolyPointwiseMont(t1[i], cp, t1[i]);
					}

					DLTMPolyMath::PolyVecSub(w1, w1, t1);
					DLTMPolyMath::PolyVecReduce(w1);
					DLTMPolyMath::PolyVecInvNttMont(w1);

					// reconstruct w1
					DLTMPolyMath::PolyVecCaddQ(w1);
					DLTMPolyMath::PolyVecUseHint(w1, w1, h, T::DILITHIUM_GAMMA2);
					DLTMPolyMath::PolyVecPackW1(buf, w1, T::DILITHIUM_POLW1_PACKED_SIZE, T::DILITHIUM_GAMMA2);

					// call random oracle and verify challenge
					MemoryTools::Clear(kctx, 0, kctx.size() * sizeof(uint64_t));
					Keccak::Incremental(mu, 0, DILITHIUM_CRH_SIZE, 0, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx);
					Keccak::Incremental(buf, 0, buf.size(), DILITHIUM_CRH_SIZE, Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHAKE_DOMAIN, kctx, true);
					Keccak::SqueezePartial(kctx, c2, 0, DILITHIUM_SEED_SIZE, Keccak::KECCAK256_RATE_SIZE);

					res = (IntegerTools::Verify(c, c2, DILITHIUM_SEED_SIZE) == 0);

					// conditional copy of the message from signature
					if (res == true)
					{
						MemoryTools::Copy(Signature, T::DILITHIUM_SIGNATURE_SIZE, Message, 0, msglen);
					}
				}
			}
		}

		return res;
	}
#endif
};

NAMESPACE_DILITHIUMEND
#endif
