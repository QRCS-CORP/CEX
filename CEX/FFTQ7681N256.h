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

#ifndef CEX_FFTQ7681N256_H
#define CEX_FFTQ7681N256_H

#include "CexDomain.h"
#include "IPrng.h"

NAMESPACE_MODULELWE

/**
* \internal
*/

/// <summary>
/// The ModuleLWE FFT using a modulus of 12289 with 1024 coefficients
/// </summary>
class FFTQ7681N256
{
private:

	static const uint QINV = 7681;
	static const uint RLOG = 18;
	static const std::array<ushort, 128> OmegasMontgomery;
	static const std::array<ushort, 128> OmegasInvMontgomery;
	static const std::array<ushort, 256> PsisBitrevMontgomery;
	static const std::array<ushort, 256> PsisInvMontgomery;

public:

	//~~~Public Constants~~~//


#define KYBER_SHAREDKEYBYTES 32

#define KYBER_POLYBYTES 416
#define KYBER_POLYCOMPRESSEDBYTES 96
#define KYBER_POLYVECBYTES (KYBER_D * KYBER_POLYBYTES)
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_D * 352)

#define KYBER_INDCPA_MSGBYTES 32
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SEEDBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 32 + KYBER_SHAREDKEYBYTES)
#define KYBER_BYTES (KYBER_INDCPA_BYTES + KYBER_INDCPA_MSGBYTES) /* Second part is for Targhi-Unruh */

	typedef struct 
	{
		uint16_t coeffs[256];
#if !defined(WINDOWS)
	} poly;
#else
	} poly __attribute__((aligned(32)));
#endif

	typedef struct 
	{
		poly vec[3];
#if !defined(WINDOWS)
	} polyvec;
#else
	} polyvec __attribute__((aligned(32)));
#endif

	/// <summary>
	/// The number of coefficients
	/// </summary>
	static const uint N = 256;

	/// <summary>
	/// 
	/// </summary>
	static const uint D = 3;

	/// <summary>
	/// 
	/// </summary>
	static const uint K = 4;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int Q = 7681;

	/// <summary>
	/// 
	/// </summary>
	static const size_t COIN_BYTES = 32;

	/// <summary>
	/// 
	/// </summary>
	static const size_t NOISE_BYTES = 32;

	/// <summary>
	/// The byte size of A's public key polynomial
	/// </summary>
	static const size_t POLY_BYTES = 1792;

	/// <summary>
	/// The byte size of B's encrypted seed array
	/// </summary>
	static const size_t RECD_BYTES = 256;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t SEED_BYTES = 32;

	/// <summary>
	/// The byte size of A's forward message to host B
	/// </summary>
	static const size_t SENDA_BYTES = POLY_BYTES + SEED_BYTES;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t SENDB_BYTES = POLY_BYTES + RECD_BYTES;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a cipher-text
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Received">The received ciphertext</param>
	static void Decrypt(std::vector<byte> &Secret, const std::vector<ushort> &PrivateKey, const std::vector<byte> &Received)
	{

	}

	/// <summary>
	/// Encrypt a message
	/// </summary>
	/// 
	/// <param name="Secret">The secret message</param>
	/// <param name="Send">The ciphertext output</param>
	/// <param name="Received">The public asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="Parallel">Run in parallel or sequential mode</param>
	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &Send, const std::vector<byte> &Received, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel)
	{

	}

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="Parallel">Run in parallel or sequential mode</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<ushort> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel)
	{

	}

	/*static void indcpa_keypair(unsigned char *pk, unsigned char *sk, OQS_RAND *rand)
	{
		polyvec a[D], e, pkpv, skpv;
		unsigned char seed[SEED_BYTES];
		unsigned char noiseseed[COIN_BYTES];
		int i;
		unsigned char nonce = 0;
		// generate the seed
		rand->rand_n(rand, seed, SEED_BYTES);
		// hash it, don't send output of system RNG
		OQS_SHA3_shake128(seed, SEED_BYTES, seed, SEED_BYTES);
		// generate noise
		rand->rand_n(rand, noiseseed, COIN_BYTES);

		// generate the public key
		gen_a(a, seed);

		// distribute noise to sk
		for (i = 0; i < D; i++)
			poly_getnoise(skpv.vec + i, noiseseed, nonce++);

		// transform sk
		polyvec_ntt(&skpv);

		// fill e
		for (i = 0; i < KYBER_D; i++)
			poly_getnoise(e.vec + i, noiseseed, nonce++);

		// matrix-vector multiplication
		for (i = 0; i < KYBER_D; i++)
			polyvec_pointwise_acc(&pkpv.vec[i], &skpv, a + i);

		// invert pk
		polyvec_invntt(&pkpv);
		// mix pk + e
		polyvec_add(&pkpv, &pkpv, &e);

		// pack keys
		pack_sk(sk, &skpv);
		pack_pk(pk, &pkpv, seed);
	}*/


};

NAMESPACE_MODULELWEEND
#endif