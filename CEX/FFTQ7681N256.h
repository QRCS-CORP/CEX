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
#include "SHAKE.h"
#include "Keccak.h"

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

#define KYBER_N 256
#define KYBER_D 3
#define KYBER_K 4 /* used in sampler */
#define KYBER_Q 7681
#define KYBER_SEEDBYTES 32
#define KYBER_NOISESEEDBYTES 32
#define KYBER_COINBYTES 32
#define KYBER_SHAREDKEYBYTES 32
#define SHAKE128_RATE 168

#define KYBER_SHAREDKEYBYTES 32
#define KYBER_POLYBYTES 416
#define KYBER_POLYCOMPRESSEDBYTES 96
#define KYBER_POLYVECBYTES (KYBER_D * KYBER_POLYBYTES) // 4*416 =1664
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_D * 352) // 4*352 =1408
#define KYBER_INDCPA_MSGBYTES 32
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SEEDBYTES) // 1408+32 =1440
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES) // =1664
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES) // 1408 + 96 =1504
#define KYBER_PUBLICKEYBYTES (KYBER_INDCPA_PUBLICKEYBYTES) // =1440
#define KYBER_SECRETKEYBYTES (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 32 + KYBER_SHAREDKEYBYTES) //1664+1440+32+32 =3168
// second part is for Targhi-Unruh
#define KYBER_BYTES (KYBER_INDCPA_BYTES + KYBER_INDCPA_MSGBYTES) // 1504+32 =1536

	static const uint QINV = 7679;
	static const uint RLOG = 18;
	static const std::array<ushort, 128> OmegasMontgomery;
	static const std::array<ushort, 128> OmegasInvMontgomery;
	static const std::array<ushort, 256> PsisBitrevMontgomery;
	static const std::array<ushort, 256> PsisInvMontgomery;

	/*static const uint16_t oqs_kex_mlwe_kyber_omegas_montgomery[KYBER_N / 2] = { 990, 7427, 2634, 6819, 578, 3281, 2143, 1095, 484, 6362, 3336, 5382, 6086, 3823, 877, 5656, 3583, 7010, 6414, 263, 1285, 291, 7143, 7338, 1581, 5134, 5184, 5932, 4042, 5775, 2468, 3, 606, 729, 5383, 962, 3240, 7548, 5129, 7653, 5929, 4965, 2461, 641, 1584, 2666, 1142, 157, 7407, 5222, 5602, 5142, 6140, 5485, 4931, 1559, 2085, 5284, 2056, 3538, 7269, 3535, 7190, 1957, 3465, 6792, 1538, 4664, 2023, 7643, 3660, 7673, 1694, 6905, 3995, 3475, 5939, 1859, 6910, 4434, 1019, 1492, 7087, 4761, 657, 4859, 5798, 2640, 1693, 2607, 2782, 5400, 6466, 1010, 957, 3851, 2121, 6392, 7319, 3367, 3659, 3375, 6430, 7583, 1549, 5856, 4773, 6084, 5544, 1650, 3997, 4390, 6722, 2915, 4245, 2635, 6128, 7676, 5737, 1616, 3457, 3132, 7196, 4702, 6239, 851, 2122, 3009 };

	static const uint16_t oqs_kex_mlwe_kyber_omegas_inv_bitrev_montgomery[KYBER_N / 2] = { 990, 254, 862, 5047, 6586, 5538, 4400, 7103, 2025, 6804, 3858, 1595, 2299, 4345, 1319, 7197, 7678, 5213, 1906, 3639, 1749, 2497, 2547, 6100, 343, 538, 7390, 6396, 7418, 1267, 671, 4098, 5724, 491, 4146, 412, 4143, 5625, 2397, 5596, 6122, 2750, 2196, 1541, 2539, 2079, 2459, 274, 7524, 6539, 5015, 6097, 7040, 5220, 2716, 1752, 28, 2552, 133, 4441, 6719, 2298, 6952, 7075, 4672, 5559, 6830, 1442, 2979, 485, 4549, 4224, 6065, 1944, 5, 1553, 5046, 3436, 4766, 959, 3291, 3684, 6031, 2137, 1597, 2908, 1825, 6132, 98, 1251, 4306, 4022, 4314, 362, 1289, 5560, 3830, 6724, 6671, 1215, 2281, 4899, 5074, 5988, 5041, 1883, 2822, 7024, 2920, 594, 6189, 6662, 3247, 771, 5822, 1742, 4206, 3686, 776, 5987, 8, 4021, 38, 5658, 3017, 6143, 889, 4216 };

	static const uint16_t oqs_kex_mlwe_kyber_psis_bitrev_montgomery[KYBER_N] = { 990, 7427, 2634, 6819, 578, 3281, 2143, 1095, 484, 6362, 3336, 5382, 6086, 3823, 877, 5656, 3583, 7010, 6414, 263, 1285, 291, 7143, 7338, 1581, 5134, 5184, 5932, 4042, 5775, 2468, 3, 606, 729, 5383, 962, 3240, 7548, 5129, 7653, 5929, 4965, 2461, 641, 1584, 2666, 1142, 157, 7407, 5222, 5602, 5142, 6140, 5485, 4931, 1559, 2085, 5284, 2056, 3538, 7269, 3535, 7190, 1957, 3465, 6792, 1538, 4664, 2023, 7643, 3660, 7673, 1694, 6905, 3995, 3475, 5939, 1859, 6910, 4434, 1019, 1492, 7087, 4761, 657, 4859, 5798, 2640, 1693, 2607, 2782, 5400, 6466, 1010, 957, 3851, 2121, 6392, 7319, 3367, 3659, 3375, 6430, 7583, 1549, 5856, 4773, 6084, 5544, 1650, 3997, 4390, 6722, 2915, 4245, 2635, 6128, 7676, 5737, 1616, 3457, 3132, 7196, 4702, 6239, 851, 2122, 3009, 7613, 7295, 2007, 323, 5112, 3716, 2289, 6442, 6965, 2713, 7126, 3401, 963, 6596, 607, 5027, 7078, 4484, 5937, 944, 2860, 2680, 5049, 1777, 5850, 3387, 6487, 6777, 4812, 4724, 7077, 186, 6848, 6793, 3463, 5877, 1174, 7116, 3077, 5945, 6591, 590, 6643, 1337, 6036, 3991, 1675, 2053, 6055, 1162, 1679, 3883, 4311, 2106, 6163, 4486, 6374, 5006, 4576, 4288, 5180, 4102, 282, 6119, 7443, 6330, 3184, 4971, 2530, 5325, 4171, 7185, 5175, 5655, 1898, 382, 7211, 43, 5965, 6073, 1730, 332, 1577, 3304, 2329, 1699, 6150, 2379, 5113, 333, 3502, 4517, 1480, 1172, 5567, 651, 925, 4573, 599, 1367, 4109, 1863, 6929, 1605, 3866, 2065, 4048, 839, 5764, 2447, 2022, 3345, 1990, 4067, 2036, 2069, 3567, 7371, 2368, 339, 6947, 2159, 654, 7327, 2768, 6676, 987, 2214 };

	static const uint16_t oqs_kex_mlwe_kyber_psis_inv_montgomery[KYBER_N] = { 1024, 4972, 5779, 6907, 4943, 4168, 315, 5580, 90, 497, 1123, 142, 4710, 5527, 2443, 4871, 698, 2489, 2394, 4003, 684, 2241, 2390, 7224, 5072, 2064, 4741, 1687, 6841, 482, 7441, 1235, 2126, 4742, 2802, 5744, 6287, 4933, 699, 3604, 1297, 2127, 5857, 1705, 3868, 3779, 4397, 2177, 159, 622, 2240, 1275, 640, 6948, 4572, 5277, 209, 2605, 1157, 7328, 5817, 3191, 1662, 2009, 4864, 574, 2487, 164, 6197, 4436, 7257, 3462, 4268, 4281, 3414, 4515, 3170, 1290, 2003, 5855, 7156, 6062, 7531, 1732, 3249, 4884, 7512, 3590, 1049, 2123, 1397, 6093, 3691, 6130, 6541, 3946, 6258, 3322, 1788, 4241, 4900, 2309, 1400, 1757, 400, 502, 6698, 2338, 3011, 668, 7444, 4580, 6516, 6795, 2959, 4136, 3040, 2279, 6355, 3943, 2913, 6613, 7416, 4084, 6508, 5556, 4054, 3782, 61, 6567, 2212, 779, 632, 5709, 5667, 4923, 4911, 6893, 4695, 4164, 3536, 2287, 7594, 2848, 3267, 1911, 3128, 546, 1991, 156, 4958, 5531, 6903, 483, 875, 138, 250, 2234, 2266, 7222, 2842, 4258, 812, 6703, 232, 5207, 6650, 2585, 1900, 6225, 4932, 7265, 4701, 3173, 4635, 6393, 227, 7313, 4454, 4284, 6759, 1224, 5223, 1447, 395, 2608, 4502, 4037, 189, 3348, 54, 6443, 2210, 6230, 2826, 1780, 3002, 5995, 1955, 6102, 6045, 3938, 5019, 4417, 1434, 1262, 1507, 5847, 5917, 7157, 7177, 6434, 7537, 741, 4348, 1309, 145, 374, 2236, 4496, 5028, 6771, 6923, 7421, 1978, 1023, 3857, 6876, 1102, 7451, 4704, 6518, 1344, 765, 384, 5705, 1207, 1630, 4734, 1563, 6839, 5933, 1954, 4987, 7142, 5814, 7527, 4953, 7637, 4707, 2182, 5734, 2818, 541, 4097, 5641 };
	*/
public:

	//~~~Public Constants~~~//

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
	static const size_t SENDA_BYTES = KYBER_PUBLICKEYBYTES;

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t SENDB_BYTES = KYBER_SECRETKEYBYTES;

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
	static void Decrypt(std::vector<byte> &Secret, const std::vector<byte> &PrivateKey, const std::vector<byte> &Received)
	{
		//shareda(*key, (unsigned char *) alice_priv, bob_msg);
		shareda(Secret, PrivateKey, Received);
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
	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &Send, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel)
	{
		//sharedb(*key, *bob_msg, alice_msg, k->rand);
		sharedb(Secret, Send, PublicKey, Rng);
	}

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	///
	/// <param name="PublicKey">The public asymmetric key</param>
	/// <param name="PrivateKey">The private asymmetric key</param>
	/// <param name="Rng">The random provider</param>
	/// <param name="Parallel">Run in parallel or sequential mode</param>
	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, bool Parallel)
	{
		std::vector<polyvec> a(KYBER_D);
		polyvec e;
		polyvec pkpv;
		polyvec skpv;
		std::vector<byte> seed(KYBER_SEEDBYTES);
		std::vector<byte> noiseseed(KYBER_COINBYTES);
		size_t i;
		byte nonce = 0;

		seed = Rng->GetBytes(KYBER_SEEDBYTES);
		Kdf::SHAKE prf(Kdf::ShakeModes::SHAKE128);
		prf.Initialize(seed);
		prf.Generate(seed);
		//OQS_SHA3_shake128(seed, KYBER_SEEDBYTES, seed, KYBER_SEEDBYTES); // Don't send output of system RNG
		noiseseed = Rng->GetBytes(KYBER_COINBYTES);

		GenerateMatrix(a, seed, 0);

		for (i = 0; i < KYBER_D; i++)
		{
			poly_getnoise(skpv.vec[i], noiseseed, nonce++);
		}

		polyvec_ntt(skpv);

		for (i = 0; i < KYBER_D; i++)
			poly_getnoise(e.vec[i], noiseseed, nonce++);

		// matrix-vector multiplication
		for (i = 0; i < KYBER_D; i++)
			polyvec_pointwise_acc(pkpv.vec[i], skpv, a[i]);

		polyvec_invntt(pkpv);
		polyvec_add(pkpv, pkpv, e);

		pack_sk(PrivateKey.data(), &skpv);
		pack_pk(PublicKey.data(), &pkpv, seed.data());
	}

	//enc
	static void sharedb(std::vector<byte> &sharedkey, std::vector<byte> &send, const std::vector<byte> &received, std::unique_ptr<Prng::IPrng> &rand)
	{
		std::vector<byte> krq(96); // Will contain key, coins, qrom-hash
		std::vector<byte> buf(64);
		int i;

		rand->GetBytes(buf, 0, 32);
		shake128(buf, 0, 32, buf, 32); // Don't release system RNG output

		shake128(buf, 32, 32, received, KYBER_PUBLICKEYBYTES); // Multitarget countermeasure for coins + contributory KEM
		shake128(krq, 0, 96, buf, 64);
		std::vector<byte> krqx(64);
		std::memcpy(&krqx[0], &krq[32], 64);
		indcpa_enc(send.data(), buf.data(), received.data(), krqx); // coins are in krq+32 + 32

		for (i = 0; i < 32; i++)
			send[i + KYBER_INDCPA_BYTES] = krq[i + 32]; // was krq[i + 64]

		shake128(krq, 32, 32, send, KYBER_BYTES); // overwrite coins in krq with h(c)
		shake128(sharedkey, 0, 32, krq, 64);          // hash concatenation of pre-k and h(c) to k
	}

	static void shake128(std::vector<byte> &output, size_t outoffset, size_t outlen, const std::vector<byte> &input, size_t inlen)
	{
		Kdf::SHAKE prf(Kdf::ShakeModes::SHAKE128);
		std::vector<byte> key(inlen);
		std::memcpy(&key[0], &input[0], inlen);
		prf.Initialize(key);
		prf.Generate(output, outoffset, outlen);
	}

	//dec
	static void shareda(std::vector<byte> &sharedkey, const std::vector<byte> &sk, const std::vector<byte> &received)
	{
		int i, fail;
		std::vector<byte> cmp(KYBER_BYTES);
		std::vector<byte> buf(64);
		std::vector<byte> krq(96); // Will contain key, coins, qrom-hash
		std::vector<byte> pk(sk.size() - KYBER_INDCPA_SECRETKEYBYTES);
		std::memcpy(&pk[0], &sk[KYBER_INDCPA_SECRETKEYBYTES], pk.size());
		//const unsigned char *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

		indcpa_dec(buf, received, sk);

		// shake128(buf+32, 32, pk, KYBER_PUBLICKEYBYTES); 
		// Multitarget countermeasure for coins + contributory KEM
		// Save hash by storing h(pk) in sk
		for (i = 0; i < 32; i++)
			buf[32 + i] = sk[KYBER_SECRETKEYBYTES - 64 + i];

		shake128(krq, 0, 96, buf, 64);

		// coins are in krq+32
		std::vector<byte> krqx(64);
		std::memcpy(&krqx[0], &krq[32], 64);
		indcpa_enc(cmp.data(), buf.data(), pk.data(), krqx);//krq + 32

		for (i = 0; i < 32; i++)
			cmp[i + KYBER_INDCPA_BYTES] = krq[i + 64];

		fail = verify(received.data(), cmp.data(), KYBER_BYTES);
		// overwrite coins in krq with h(c)
		shake128(krq, 32, 32, received, KYBER_BYTES);
		// Overwrite pre-k with z on re-encryption failure

		std::vector<byte> sk2(KYBER_SHAREDKEYBYTES);
		std::memcpy(&sk2[0], &sk[KYBER_SECRETKEYBYTES - KYBER_SHAREDKEYBYTES], KYBER_SHAREDKEYBYTES);
		cmov(krq.data(), sk2.data(), KYBER_SHAREDKEYBYTES, fail);
		//cmov(krq.data(), sk + KYBER_SECRETKEYBYTES - KYBER_SHAREDKEYBYTES, KYBER_SHAREDKEYBYTES, fail);

		// hash concatenation of pre-k and h(c) to k
		shake128(sharedkey, 0, 32, krq, 64);
	}

	// returns 0 for equal strings, 1 for non-equal strings
	static int verify(const unsigned char *a, const unsigned char *b, size_t len)
	{
		int64_t r;
		size_t i;
		r = 0;

		for (i = 0; i < len; i++)
			r |= a[i] ^ b[i];

		r = (-r) >> 63;
		return r;
	}

	// b = 1 means mov, b = 0 means don't mov
	static void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b) 
	{
		size_t i;

		b = -b;
		for (i = 0; i < len; i++)
			r[i] ^= b & (x[i] ^ r[i]);
	}

	static void indcpa_dec(std::vector<byte> &m, const std::vector<byte> &c, const std::vector<byte> &sk)
	{
		polyvec bp, skpv;
		poly v, mp;
		size_t i;

		unpack_ciphertext(&bp, &v, c.data());
		unpack_sk(&skpv, sk.data());

		for (i = 0; i < KYBER_D; i++)
			bitrev_vector(bp.vec[i].coeffs);

		polyvec_ntt(bp);

		polyvec_pointwise_acc(mp, skpv, bp);
		poly_invntt(mp);

		poly_sub(&mp, &mp, &v);

		poly_tomsg(m.data(), &mp);
	}

	static void indcpa_enc(unsigned char *c, const unsigned char *m, const unsigned char *pk, const std::vector<byte> &coins)
	{
		polyvec sp, pkpv, ep, bp;
		std::vector<polyvec> at(KYBER_D);
		poly v, k, epp;
		std::vector<byte> seed(KYBER_SEEDBYTES);
		int i;
		unsigned char nonce = 0;

		unpack_pk(&pkpv, seed.data(), pk);

		poly_frommsg(&k, m);

		for (i = 0; i < KYBER_D; i++)
			bitrev_vector(pkpv.vec[i].coeffs);

		polyvec_ntt(pkpv);

		GenerateMatrix(at, seed, 1);
		//gen_at(at, seed);

		for (i = 0; i < KYBER_D; i++)
			poly_getnoise(sp.vec[i], coins, nonce++);

		polyvec_ntt(sp);

		for (i = 0; i < KYBER_D; i++)
			poly_getnoise(ep.vec[i], coins, nonce++);

		// matrix-vector multiplication
		for (i = 0; i < KYBER_D; i++)
			polyvec_pointwise_acc(bp.vec[i], sp, at[i]);

		polyvec_invntt(bp);
		polyvec_add(bp, bp, ep);

		polyvec_pointwise_acc(v, pkpv, sp);
		poly_invntt(v);

		poly_getnoise(epp, coins, nonce++);

		poly_add(v, v, epp);
		poly_add(v, v, k);

		pack_ciphertext(c, &bp, &v);
	}

	static void GenerateMatrix(std::vector<polyvec> &A, const std::vector<byte> &Seed, bool Transposed) //XXX: Not static for benchmarking
	{
		// Generate entry a_{i,j} of matrix A as Parse(SHAKE128(seed|i|j))
		uint pos = 0, ctr;
		ushort val;
		uint nblocks = 4;
		std::vector<byte> buf(SHAKE128_RATE * 4); // was * nblocks, but VS doesn't like this buf init
		int i, j;
		uint16_t dsep;
		std::vector<byte> sep{ 0x01, 0xA8, 0x01, 0x00, 0x01, 0x10, 0x00, 0x00 };

		for (i = 0; i < KYBER_D; i++)
		{
			for (j = 0; j < KYBER_D; j++)
			{
				ctr = 0;
				pos = 0;
				if (Transposed)
				{
					dsep = j + (i << 8);
				}
				else
				{
					dsep = i + (j << 8);
				}

				sep[6] = dsep & 0xFF;
				sep[7] = dsep >> 8;
				Kdf::SHAKE prf(Kdf::ShakeModes::SHAKE128);
				prf.DomainString(sep);
				prf.DomainCode() = 0x04;
				prf.Initialize(Seed);
				prf.Generate(buf); //218,16,78
				//simple_absorb(state, dsep, seed, KYBER_SEEDBYTES);
				//squeezeblocks(buf, nblocks, state, SHAKE128_RATE);

				while (ctr < KYBER_N)
				{
					val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
					if (val < KYBER_Q)
					{
						A[i].vec[j].coeffs[ctr++] = val;
					}
					pos += 2;

					if (pos > SHAKE128_RATE * nblocks - 2)
					{
						nblocks = 1;
						prf.Generate(buf);
						//squeezeblocks(buf, nblocks, state, SHAKE128_RATE);
						pos = 0;
					}
				}
			}
		}
	}/**/

	static void pack_ciphertext(unsigned char *r, const polyvec *b, const poly *v)
	{
		polyvec_compress(r, b);
		poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
	}

	static void pack_pk(unsigned char *r, const polyvec *pk, const unsigned char *seed)
	{
		int i;
		polyvec_compress(r, pk);

		for (i = 0; i < KYBER_SEEDBYTES; i++)
			r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
	}

	static void pack_sk(unsigned char *r, const polyvec *sk)
	{
		polyvec_tobytes(r, sk);
	}

	static void poly_add(poly &r, const poly &a, const poly &b) 
	{
		int i;
		for (i = 0; i < KYBER_N; i++)
			r.coeffs[i] = barrett_reduce(a.coeffs[i] + b.coeffs[i]);
	}

	static void poly_compress(unsigned char *r, const poly *a) 
	{
		uint32_t t[8];
		unsigned int i, j, k = 0;

		for (i = 0; i < KYBER_N; i += 8)
		{
			for (j = 0; j < 8; j++)
				t[j] = (((freeze(a->coeffs[i + j]) << 3) + KYBER_Q / 2) / KYBER_Q) & 7;

			r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
			r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
			r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
			k += 3;
		}
	}

	static void poly_decompress(poly *r, const unsigned char *a)
	{
		unsigned int i;
		for (i = 0; i < KYBER_N; i += 8)
		{
			r->coeffs[i + 0] = (((a[0] & 7) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 1] = ((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 3] = ((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 4] = ((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 6] = ((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3;
			r->coeffs[i + 7] = ((((a[2] >> 5)) * KYBER_Q) + 4) >> 3;
			a += 3;
		}
	}

	static void poly_frombytes(poly *r, const unsigned char *a) 
	{
		int i;
		for (i = 0; i < KYBER_N / 8; i++) {
			r->coeffs[8 * i + 0] = a[13 * i + 0] | (((uint16_t)a[13 * i + 1] & 0x1f) << 8);
			r->coeffs[8 * i + 1] = (a[13 * i + 1] >> 5) | (((uint16_t)a[13 * i + 2]) << 3) | (((uint16_t)a[13 * i + 3] & 0x03) << 11);
			r->coeffs[8 * i + 2] = (a[13 * i + 3] >> 2) | (((uint16_t)a[13 * i + 4] & 0x7f) << 6);
			r->coeffs[8 * i + 3] = (a[13 * i + 4] >> 7) | (((uint16_t)a[13 * i + 5]) << 1) | (((uint16_t)a[13 * i + 6] & 0x0f) << 9);
			r->coeffs[8 * i + 4] = (a[13 * i + 6] >> 4) | (((uint16_t)a[13 * i + 7]) << 4) | (((uint16_t)a[13 * i + 8] & 0x01) << 12);
			r->coeffs[8 * i + 5] = (a[13 * i + 8] >> 1) | (((uint16_t)a[13 * i + 9] & 0x3f) << 7);
			r->coeffs[8 * i + 6] = (a[13 * i + 9] >> 6) | (((uint16_t)a[13 * i + 10]) << 2) | (((uint16_t)a[13 * i + 11] & 0x07) << 10);
			r->coeffs[8 * i + 7] = (a[13 * i + 11] >> 3) | (((uint16_t)a[13 * i + 12]) << 5);
		}
	}

	static void poly_frommsg(poly *r, const unsigned char msg[KYBER_SHAREDKEYBYTES])
	{
		uint16_t i, j, mask;

		for (i = 0; i < KYBER_SHAREDKEYBYTES; i++) {
			for (j = 0; j < 8; j++) {
				mask = -((msg[i] >> j) & 1);
				r->coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
			}
		}
	}

	static void poly_getnoise(poly &r, const std::vector<byte> &seed, byte nonce)
	{
		std::vector<byte> buf(KYBER_N);
		Kdf::SHAKE prf(Kdf::ShakeModes::SHAKE128);
		prf.DomainCode() = nonce;
		prf.Initialize(seed);
		prf.Generate(buf);
		//OQS_SHA3_cshake128_simple(buf, KYBER_N, nonce, seed, KYBER_NOISESEEDBYTES);

		cbd(r, buf);
	}

	static void poly_invntt(poly &r) 
	{
		bitrev_vector(r.coeffs);
		ntt(r.coeffs, OmegasInvMontgomery.data());
		mul_coefficients(r.coeffs, PsisBitrevMontgomery.data());
	}

	static void poly_ntt(poly &r) 
	{
		mul_coefficients(r.coeffs, PsisBitrevMontgomery.data());
		ntt(r.coeffs, OmegasMontgomery.data());
	}

	static void poly_sub(poly *r, const poly *a, const poly *b) 
	{
		int i;
		for (i = 0; i < KYBER_N; i++)
			r->coeffs[i] = barrett_reduce(a->coeffs[i] + 3 * KYBER_Q - b->coeffs[i]);
	}

	static void poly_tobytes(unsigned char *r, const poly *a) 
	{
		int i, j;
		uint16_t t[8];

		for (i = 0; i < KYBER_N / 8; i++) {
			for (j = 0; j < 8; j++)
				t[j] = freeze(a->coeffs[8 * i + j]);

			r[13 * i + 0] = t[0] & 0xff;
			r[13 * i + 1] = (t[0] >> 8) | ((t[1] & 0x07) << 5);
			r[13 * i + 2] = (t[1] >> 3) & 0xff;
			r[13 * i + 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
			r[13 * i + 4] = (t[2] >> 6) | ((t[3] & 0x01) << 7);
			r[13 * i + 5] = (t[3] >> 1) & 0xff;
			r[13 * i + 6] = (t[3] >> 9) | ((t[4] & 0x0f) << 4);
			r[13 * i + 7] = (t[4] >> 4) & 0xff;
			r[13 * i + 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
			r[13 * i + 9] = (t[5] >> 7) | ((t[6] & 0x03) << 6);
			r[13 * i + 10] = (t[6] >> 2) & 0xff;
			r[13 * i + 11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
			r[13 * i + 12] = (t[7] >> 5);
		}
	}

	static void poly_tomsg(unsigned char msg[KYBER_SHAREDKEYBYTES], const poly *a)
	{
		uint16_t t;
		int i, j;

		for (i = 0; i < KYBER_SHAREDKEYBYTES; i++) 
		{
			msg[i] = 0;
			for (j = 0; j < 8; j++) {
				t = (((freeze(a->coeffs[8 * i + j]) << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
				msg[i] |= t << j;
			}
		}
	}

	static void polyvec_add(polyvec &r, const polyvec &a, const polyvec &b) 
	{
		int i;
		for (i = 0; i < KYBER_D; i++)
			poly_add(r.vec[i], a.vec[i], b.vec[i]);
	}

	static void polyvec_compress(unsigned char *r, const polyvec *a)
	{
		int i, j, k;
		uint16_t t[8];
		for (i = 0; i < KYBER_D; i++) 
		{
			for (j = 0; j < KYBER_N / 8; j++) 
			{
				for (k = 0; k < 8; k++)
					t[k] = ((((uint32_t)freeze(a->vec[i].coeffs[8 * j + k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7ff;

				r[11 * j + 0] = t[0] & 0xff;
				r[11 * j + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
				r[11 * j + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
				r[11 * j + 3] = (t[2] >> 2) & 0xff;
				r[11 * j + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
				r[11 * j + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
				r[11 * j + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
				r[11 * j + 7] = (t[5] >> 1) & 0xff;
				r[11 * j + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
				r[11 * j + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
				r[11 * j + 10] = (t[7] >> 3);
			}
			r += 352;
		}
	}

	static void polyvec_decompress(polyvec *r, const unsigned char *a)
	{
		int i, j;
		for (i = 0; i < KYBER_D; i++) {
			for (j = 0; j < KYBER_N / 8; j++) {
				r->vec[i].coeffs[8 * j + 0] = (((a[11 * j + 0] | (((uint32_t)a[11 * j + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 1] = ((((a[11 * j + 1] >> 3) | (((uint32_t)a[11 * j + 2] & 0x3f) << 5)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 2] = ((((a[11 * j + 2] >> 6) | (((uint32_t)a[11 * j + 3] & 0xff) << 2) | (((uint32_t)a[11 * j + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 3] = ((((a[11 * j + 4] >> 1) | (((uint32_t)a[11 * j + 5] & 0x0f) << 7)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 4] = ((((a[11 * j + 5] >> 4) | (((uint32_t)a[11 * j + 6] & 0x7f) << 4)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 5] = ((((a[11 * j + 6] >> 7) | (((uint32_t)a[11 * j + 7] & 0xff) << 1) | (((uint32_t)a[11 * j + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 6] = ((((a[11 * j + 8] >> 2) | (((uint32_t)a[11 * j + 9] & 0x1f) << 6)) * KYBER_Q) + 1024) >> 11;
				r->vec[i].coeffs[8 * j + 7] = ((((a[11 * j + 9] >> 5) | (((uint32_t)a[11 * j + 10] & 0xff) << 3)) * KYBER_Q) + 1024) >> 11;
			}
			a += 352;
		}
	}

	static void polyvec_frombytes(polyvec *r, const unsigned char *a) 
	{
		int i;
		for (i = 0; i < KYBER_D; i++)
			poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
	}

	static void polyvec_invntt(polyvec &r) 
	{
		int i;
		for (i = 0; i < KYBER_D; i++)
			poly_invntt(r.vec[i]);
	}

	static void polyvec_ntt(polyvec &r) 
	{
		int i;
		for (i = 0; i < KYBER_D; i++)
		{
			poly_ntt(r.vec[i]);
		}
	}

	static void polyvec_pointwise_acc(poly &r, const polyvec &a, const polyvec &b) 
	{
		int i, j;
		uint16_t t;
		for (j = 0; j < KYBER_N; j++)
		{
			t = montgomery_reduce(4613 * (uint32_t)b.vec[0].coeffs[j]); // 4613 = 2^{2*18} % q
			r.coeffs[j] = montgomery_reduce(a.vec[0].coeffs[j] * t);
			for (i = 1; i < KYBER_D; i++)
			{
				t = montgomery_reduce(4613 * (uint32_t)b.vec[i].coeffs[j]);
				r.coeffs[j] += montgomery_reduce(a.vec[i].coeffs[j] * t);
			}
			r.coeffs[j] = barrett_reduce(r.coeffs[j]);
		}
	}

	static void polyvec_tobytes(unsigned char *r, const polyvec *a)
	{
		int i;
		for (i = 0; i < KYBER_D; i++)
			poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
	}

	static void unpack_ciphertext(polyvec *b, poly *v, const unsigned char *c)
	{
		polyvec_decompress(b, c);
		poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
	}

	static void unpack_pk(polyvec *pk, unsigned char *seed, const unsigned char *packedpk)
	{
		int i;
		polyvec_decompress(pk, packedpk);

		for (i = 0; i < KYBER_SEEDBYTES; i++)
			seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
	}

	static void unpack_sk(polyvec *sk, const unsigned char *packedsk)
	{
		polyvec_frombytes(sk, packedsk);
	}

	static uint16_t barrett_reduce(uint16_t a) 
	{
		uint32_t u;

		u = a >> 13;
		u *= KYBER_Q;
		a -= u;
		return a;
	}

	static void bitrev_vector(uint16_t *poly) 
	{
		static uint16_t bitrev_table[KYBER_N] = 
		{
			0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240,
			8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
			4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244,
			12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
			2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242,
			10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
			6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246,
			14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
			1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241,
			9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
			5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245,
			13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
			3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243,
			11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
			7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247,
			15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255,
		};
		unsigned int i, r;
		uint16_t tmp;

		for (i = 0; i < KYBER_N; i++) {
			r = bitrev_table[i];
			if (i < r) {
				tmp = poly[i];
				poly[i] = poly[r];
				poly[r] = tmp;
			}
		}
	}

	static void cbd(poly &r, const std::vector<byte> &buf)
	{
#if KYBER_K != 4
#error "poly_getnoise in poly.c only supports k=4"
#endif

		uint32_t t, d, a[4], b[4];
		int i, j;

		for (i = 0; i < KYBER_N / 4; i++) 
		{
			t = Utility::IntUtils::LeBytesTo32(buf, 4 * i);
			d = 0;
			for (j = 0; j < 4; j++)
			{
				d += (t >> j) & 0x11111111;
			}
			a[0] = d & 0xf;
			b[0] = (d >> 4) & 0xf;
			a[1] = (d >> 8) & 0xf;
			b[1] = (d >> 12) & 0xf;
			a[2] = (d >> 16) & 0xf;
			b[2] = (d >> 20) & 0xf;
			a[3] = (d >> 24) & 0xf;
			b[3] = (d >> 28);

			r.coeffs[4 * i + 0] = a[0] + KYBER_Q - b[0];
			r.coeffs[4 * i + 1] = a[1] + KYBER_Q - b[1];
			r.coeffs[4 * i + 2] = a[2] + KYBER_Q - b[2];
			r.coeffs[4 * i + 3] = a[3] + KYBER_Q - b[3];
		}
	}

	static uint16_t freeze(uint16_t x) 
	{
		uint16_t m, r;
		int16_t c;
		r = barrett_reduce(x);

		m = r - KYBER_Q;
		c = m;
		c >>= 15;
		r = m ^ ((r ^ m) & c);

		return r;
	}

	static uint16_t montgomery_reduce(uint32_t a) 
	{
		uint32_t u;

		u = (a * QINV);
		u &= ((1 << RLOG) - 1);
		u *= KYBER_Q;
		a = a + u;
		return a >> RLOG;
	}

	static void mul_coefficients(uint16_t *poly, const uint16_t *factors) 
	{
		unsigned int i;

		for (i = 0; i < KYBER_N; i++)
			poly[i] = montgomery_reduce((poly[i] * factors[i]));
	}

	static void ntt(uint16_t *a, const uint16_t *omega) 
	{
		int start, j, jTwiddle, level;
		uint16_t temp, W;
		uint32_t t;

		for (level = 0; level < 8; level++) {
			for (start = 0; start < (1 << level); start++) {
				jTwiddle = 0;
				for (j = start; j < KYBER_N - 1; j += 2 * (1 << level)) {
					W = omega[jTwiddle++];
					temp = a[j];

					if (level & 1) // odd level
						a[j] = barrett_reduce((temp + a[j + (1 << level)]));
					else
						a[j] = (temp + a[j + (1 << level)]); // Omit reduction (be lazy)

					t = (W * ((uint32_t)temp + 4 * KYBER_Q - a[j + (1 << level)]));

					a[j + (1 << level)] = montgomery_reduce(t);
				}
			}
		}
	}

};

NAMESPACE_MODULELWEEND
#endif