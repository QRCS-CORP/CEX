#ifndef CEX_KYBER_H
#define CEX_KYBER_H

#include "CexDomain.h"
#include "CSP.h"
#include "Keccak256.h"
#include "Keccak512.h"
#include "SHAKE.h"
#include "SymmetricKey.h"

#include "BCG.h"

NAMESPACE_MODULELWE

class Kyber
{
private:

#ifndef KYBER_K
#define KYBER_K 3 // Change this for different security strengths
#endif

#define KYBER_N 256
#define KYBER_Q 7681

#if   (KYBER_K == 2) // Kyber512
#define KYBER_ETA 5
#elif (KYBER_K == 3) // Kyber768
#define KYBER_ETA 4
#elif (KYBER_K == 4) // Kyber1024
#define KYBER_ETA 3
#else
#error "KYBER_K must be in {2,3,4}"
#endif

// size in bytes of shared key, hashes, and seeds
#define KYBER_SYMBYTES 32   
#define KYBER_POLYBYTES              416 
#define KYBER_POLYCOMPRESSEDBYTES    96 
#define KYBER_POLYVECBYTES           (KYBER_K * KYBER_POLYBYTES) // (k3)=1248
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352) // (k3)=1056
#define KYBER_INDCPA_MSGBYTES       KYBER_SYMBYTES // 32
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SYMBYTES) // (k3)1088
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES) // (k3)=1248
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES) // 1056+96=1152
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES) // (k3)=1088
// 32 bytes of additional space to save H(pk)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES) // (k3) 1248+1088+64=2400
#define KYBER_CIPHERTEXTBYTES  KYBER_INDCPA_BYTES // (k3)=1152
#define SHAKE128_RATE 168

	static const uint32_t QINV = 7679; // -inverse_mod(q,2^18)
	static const uint32_t RLOG = 18;
	static const uint16_t zetas[KYBER_N];
	static const uint16_t omegas_inv_bitrev_montgomery[KYBER_N / 2];
	static const uint16_t psis_inv_montgomery[KYBER_N];

public:

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

	static void KyberTest()
	{
		unsigned char pk[KYBER_PUBLICKEYBYTES];
		unsigned char sk[KYBER_SECRETKEYBYTES];
		crypto_kem_keypair(pk, sk);

		unsigned char ct[KYBER_CIPHERTEXTBYTES];
		unsigned char ss[KYBER_SYMBYTES];
		crypto_kem_enc(ct, ss, pk); // pk=1088, sk=2400, ct=1152, ss=32

		unsigned char ss2[KYBER_SYMBYTES];
		if (crypto_kem_dec(ss2, ct, sk) != 0)
		{
			throw;
		}
	}

	static int crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
	{
		size_t i;

		indcpa_keypair(pk, sk);

		for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
		{
			sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
		}

		sha3_256(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
        // Value z for pseudo-random output on reject 
		randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);

		return 0;
	}

	/*************************************************
	* Name:        crypto_kem_enc
	*
	* Description: Generates cipher text and shared
	*              secret for given public key
	*
	* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
	*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
	*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
	*
	* Returns 0 (success)
	**************************************************/
	static int crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
	{
        /* Will contain key, coins */
		uint8_t kr[2 * KYBER_SYMBYTES];
		uint8_t buf[2 * KYBER_SYMBYTES];

		randombytes(buf, KYBER_SYMBYTES);
        /* Don't release system RNG output */
		sha3_256(buf, buf, KYBER_SYMBYTES);
        /* Multitarget countermeasure for coins + contributory KEM */
		sha3_256(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
		sha3_512(kr, buf, 2 * KYBER_SYMBYTES);
        /* coins are in kr+KYBER_SYMBYTES */
		indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);
        /* overwrite coins in kr with H(c) */
		sha3_256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
        /* hash concatenation of pre-k and H(c) to k */
		sha3_256(ss, kr, 2 * KYBER_SYMBYTES);

		return 0;
	}

	/*************************************************
	* Name:        crypto_kem_dec
	*
	* Description: Generates shared secret for given
	*              cipher text and private key
	*
	* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
	*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
	*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
	*
	* Returns 0 for sucess or -1 for failure
	*
	* On failure, ss will contain a randomized value.
	**************************************************/
	static int crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
	{
		size_t i;
		int fail;
		unsigned char cmp[KYBER_CIPHERTEXTBYTES];
		unsigned char buf[2 * KYBER_SYMBYTES];
        /* Will contain key, coins, qrom-hash */
		unsigned char kr[2 * KYBER_SYMBYTES];
		const unsigned char *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

		indcpa_dec(buf, ct, sk);

        /* Multitarget countermeasure for coins + contributory KEM */
		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			/* Save hash by storing H(pk) in sk */
			buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
		}

		sha3_512(kr, buf, 2 * KYBER_SYMBYTES);
        /* coins are in kr+KYBER_SYMBYTES */
		indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

		fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
        /* overwrite coins in kr with H(c)  */
		sha3_256(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
		/* Overwrite pre-k with z on re-encryption failure */
		cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
        /* hash concatenation of pre-k and H(c) to k */
		sha3_256(ss, kr, 2 * KYBER_SYMBYTES);

		return -fail;
	}

//private:

	static uint16_t barrett_reduce(uint16_t x)
	{
		uint32_t u;

		/* Note: newhope is: u = (((uint32_t)x * 5) >> 16); */
		u = x >> 13;
		u *= KYBER_Q;
		x -= u;

		return x;
	}

	static void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b)
	{
		size_t i;

		b = ~b + 1;

		for (i = 0; i < length; i++)
		{
			r[i] ^= b & (x[i] ^ r[i]);
		}
	}

	static uint16_t freeze(uint16_t x)
	{
		uint16_t m;
		uint16_t r;
		int16_t c;

		r = barrett_reduce(x);
		m = r - KYBER_Q;
		c = m;
		c >>= 15;
		r = m ^ ((r ^ m) & c);

		return r;
	}

	static void indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk)
	{
		polyvec bp;
		polyvec skpv;
		poly mp;
		poly v;

		unpack_ciphertext(&bp, &v, c);
		unpack_sk(&skpv, sk);

		polyvec_ntt(&bp);
		polyvec_pointwise_acc(&mp, &skpv, &bp);
		poly_invntt(&mp);
		poly_sub(&mp, &mp, &v);
		poly_tomsg(m, &mp);
	}

	static void indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins)
	{
		polyvec at[KYBER_K];
		uint8_t seed[KYBER_SYMBYTES];
		polyvec bp;
		polyvec ep;
		polyvec pkpv;
		polyvec sp;
		poly epp;
		poly k;
		poly v;
		size_t i;
		uint8_t nonce;

		unpack_pk(&pkpv, seed, pk);
		poly_frommsg(&k, m);
		polyvec_ntt(&pkpv);

		gen_matrix(at, seed, 1);
		nonce = 0;


		std::vector<byte> gkey(32);
		std::memcpy(gkey.data(), coins, 32);
		Drbg::BCG* gen = new Drbg::BCG(Enumeration::BlockCiphers::Rijndael);
		gen->Initialize(gkey);



		for (i = 0; i < KYBER_K; i++)
		{
			//poly_getnoise(sp.vec + i, coins, nonce++);
			poly_getnoise2(sp.vec + i, gen);
		}

		polyvec_ntt(&sp);

		for (i = 0; i < KYBER_K; i++)
		{
			//poly_getnoise(ep.vec + i, coins, nonce++);
			poly_getnoise2(ep.vec + i, gen);
		}

		/* matrix-vector multiplication */
		for (i = 0; i < KYBER_K; i++)
		{
			polyvec_pointwise_acc(&bp.vec[i], &sp, at + i);
		}

		polyvec_invntt(&bp);
		polyvec_add(&bp, &bp, &ep);
		polyvec_pointwise_acc(&v, &pkpv, &sp);
		poly_invntt(&v);


		//poly_getnoise(&epp, coins, nonce++);
		poly_getnoise2(&epp, gen);

		poly_add(&v, &v, &epp);
		poly_add(&v, &v, &k);

		pack_ciphertext(c, &bp, &v);
	}

	static void indcpa_keypair(uint8_t* pk, uint8_t* sk)
	{
		polyvec a[KYBER_K];
		uint8_t buf[KYBER_SYMBYTES + KYBER_SYMBYTES];
		polyvec e;
		polyvec pkpv;
		polyvec skpv;
		size_t i;
		uint8_t* publicseed = buf;
		uint8_t* noiseseed = buf + KYBER_SYMBYTES;
		uint8_t nonce;

		randombytes(buf, KYBER_SYMBYTES);
		sha3_512(buf, buf, KYBER_SYMBYTES);

		gen_matrix(a, publicseed, 0);
		nonce = 0;


		std::vector<byte> gkey(32);
		std::memcpy(gkey.data(), noiseseed, 32);
		Drbg::BCG* gen = new Drbg::BCG(Enumeration::BlockCiphers::Rijndael);
		gen->Initialize(gkey);



		for (i = 0; i < KYBER_K; i++)
		{
			//poly_getnoise(skpv.vec + i, noiseseed, nonce++);
			poly_getnoise2(skpv.vec + i, gen);
		}

		polyvec_ntt(&skpv);

		for (i = 0; i < KYBER_K; i++)
		{
			//poly_getnoise(e.vec + i, noiseseed, nonce++);
			poly_getnoise2(e.vec + i, gen);
		}

		// matrix-vector multiplication
		for (i = 0; i < KYBER_K; i++)
		{
			polyvec_pointwise_acc(&pkpv.vec[i], &skpv, a + i);
		}

		polyvec_invntt(&pkpv);
		polyvec_add(&pkpv, &pkpv, &e);
		pack_sk(sk, &skpv);
		pack_pk(pk, &pkpv, publicseed);
	}

	static void gen_matrix(polyvec *a, const uint8_t* seed, int transposed)
	{
		uint8_t extseed[KYBER_SYMBYTES + 2];
		uint8_t buf[SHAKE128_RATE * 4];
		size_t ctr;
		size_t nblocks;
		size_t pos;
		uint16_t i;
		uint16_t j;
		uint16_t val;

		nblocks = 4;
		pos = 0;

		for (i = 0; i<KYBER_SYMBYTES; i++)
			extseed[i] = seed[i];

		for (i = 0; i<KYBER_K; i++)
		{
			for (j = 0; j<KYBER_K; j++)
			{
				ctr = pos = 0;
				if (transposed)
				{
					extseed[KYBER_SYMBYTES] = i;
					extseed[KYBER_SYMBYTES + 1] = j;
				}
				else
				{
					extseed[KYBER_SYMBYTES] = j;
					extseed[KYBER_SYMBYTES + 1] = i;
				}

				shake128(buf, SHAKE128_RATE * nblocks, extseed, KYBER_SYMBYTES + 2);

				while (ctr < KYBER_N)
				{
					val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
					if (val < KYBER_Q)
					{
						a[i].vec[j].coeffs[ctr++] = val;
					}
					pos += 2;

					if (pos > SHAKE128_RATE * nblocks - 2)
					{
						nblocks = 1;
						//shake128_squeezeblocks(buf, nblocks, state);
						pos = 0;
					}
				}
			}
		}
	}

	static void gen_matrix2(polyvec *a, const uint8_t* seed, int transposed)
	{
		size_t ctr;
		size_t pos;
		uint16_t i;
		uint16_t j;
		uint16_t val;
		std::vector<uint8_t> buf(KYBER_K * KYBER_N);
		std::vector<uint8_t> gkey(32);
		std::memcpy(gkey.data(), seed, 32);

		Drbg::BCG gen(Enumeration::BlockCiphers::Rijndael);
		gen.Initialize(gkey);

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_K; j++)
			{
				ctr = 0;
				pos = 0;

				gen.Generate(buf);

				while (ctr < KYBER_N)
				{
					val = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1FFFU;
					if (val < KYBER_Q)
					{
						a[i].vec[j].coeffs[ctr++] = val;
					}
					pos += 2;

					if (pos > ((KYBER_K * KYBER_N) - 2))
					{
						gen.Generate(buf);
						pos = 0;
					}
				}
			}
		}
	}

	static void cbd(poly* r, const uint8_t* buf)
	{
#if (KYBER_ETA == 3)

		uint16_t a[4];
		uint16_t b[4];
		size_t i;
		size_t j;
		uint32_t t;
		uint32_t d;

		for (i = 0; i < KYBER_N / 4; i++)
		{
			t = lebytesto32(buf + 3 * i, 3);
			d = 0;

			for (j = 0; j < 3; j++)
			{
				d += (t >> j) & 0x249249UL;
			}

			a[0] = (d & 0x7);
			b[0] = ((d >> 3) & 0x7);
			a[1] = ((d >> 6) & 0x7);
			b[1] = ((d >> 9) & 0x7);
			a[2] = ((d >> 12) & 0x7);
			b[2] = ((d >> 15) & 0x7);
			a[3] = ((d >> 18) & 0x7);
			b[3] = (d >> 21);

			r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
			r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
			r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
			r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
		}

#elif (KYBER_ETA == 4)

		uint16_t a[4];
		uint16_t b[4];
		size_t i;
		size_t j;
		uint32_t t;
		uint32_t d;

		for (i = 0; i < KYBER_N / 4; i++)
		{
			t = lebytesto32(buf + (4 * i), 4);
			d = 0;

			for (j = 0; j < 4; j++)
			{
				d += (t >> j) & 0x11111111UL;
			}

			a[0] = (d & 0xF);
			b[0] = ((d >> 4) & 0xF);
			a[1] = ((d >> 8) & 0xF);
			b[1] = ((d >> 12) & 0xF);
			a[2] = ((d >> 16) & 0xF);
			b[2] = ((d >> 20) & 0xF);
			a[3] = ((d >> 24) & 0xF);
			b[3] = (d >> 28);

			r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
			r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
			r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
			r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
		}

#elif (KYBER_ETA == 5)

		uint32_t a[4];
		uint32_t b[4];
		uint64_t d;
		uint64_t t;
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_N / 4; i++)
		{
			t = lebytesto64(buf + (5 * i), 5);
			d = 0;

			for (j = 0; j < 5; j++)
			{
				d += (t >> j) & 0x0842108421ULL;
			}

			a[0] = (d & 0x1F);
			b[0] = ((d >> 5) & 0x1F);
			a[1] = ((d >> 10) & 0x1F);
			b[1] = ((d >> 15) & 0x1F);
			a[2] = ((d >> 20) & 0x1F);
			b[2] = ((d >> 25) & 0x1F);
			a[3] = ((d >> 30) & 0x1F);
			b[3] = (d >> 35);

			r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
			r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
			r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
			r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
		}

#else

#	error "poly_getnoise in poly.c only supports eta in {3,4,5}"

#endif
	}

	static void invntt(uint16_t* p)
	{
		uint16_t level;
		uint16_t tmp;
		uint16_t W;
		uint32_t j;
		uint32_t jTwiddle;
		uint32_t start;
		uint32_t t;
		uint16_t tpos;

		for (level = 0; level < 8; level++)
		{
			for (start = 0; start < (1U << level); start++)
			{
				jTwiddle = 0;

				for (j = start; j < KYBER_N - 1; j += 2 * (1U << level))
				{
					W = omegas_inv_bitrev_montgomery[jTwiddle];
					++jTwiddle;
					tmp = p[j];
					tpos = j + (1U << level);

					if (level & 1U)
					{
						p[j] = barrett_reduce(tmp + p[tpos]);
					}
					else
					{
						p[j] = (tmp + p[tpos]);
					}

					t = (uint32_t)W * (tmp + ((4 * KYBER_Q) - p[tpos]));
					p[tpos] = montgomery_reduce(t);
				}
			}
		}

		for (j = 0; j < KYBER_N; j++)
		{
			p[j] = montgomery_reduce((uint32_t)p[j] * psis_inv_montgomery[j]);
		}
	}

#if (KYBER_ETA == 3) || (KYBER_ETA == 4)

	static uint32_t lebytesto32(const uint8_t* a, size_t bytes)
	{
		size_t i;
		uint32_t r;

		r = a[0];

		for (i = 1; i < bytes; i++)
		{
			r |= (uint32_t)a[i] << (8 * i);
		}

		return r;
	}

#else

	static uint64_t lebytesto64(const uint8_t* a, size_t bytes)
	{
		size_t i;
		uint64_t r;

		r = a[0];

		for (i = 1; i < bytes; i++)
		{
			r |= (uint64_t)a[i] << (8 * i);
		}

		return r;
	}

#endif

	static uint16_t montgomery_reduce(uint32_t x)
	{
		uint32_t u;

		u = (x * QINV);
		u &= ((1 << RLOG) - 1);
		u *= KYBER_Q;
		x = x + u;

		return x >> RLOG;
	}

	static void ntt(uint16_t* p)
	{
		uint32_t j;
		uint32_t k;
		uint32_t zeta;
		int16_t level;
		uint16_t start;
		uint16_t t;
		uint16_t tpos;

		j = 0;
		k = 1;

		for (level = 7; level >= 0; level--)
		{
			for (start = 0; start < KYBER_N; start = j + (1U << level))
			{
				zeta = zetas[k];
				++k;

				for (j = start; j < start + (1U << level); ++j)
				{
					tpos = j + (1U << level);
					t = montgomery_reduce(zeta * p[tpos]);

					p[tpos] = barrett_reduce(p[j] + ((4 * KYBER_Q) - t));

					if (level & 1U)
					{
						p[j] = p[j] + t;
					}
					else
					{
						p[j] = barrett_reduce(p[j] + t);
					}
				}
			}
		}
	}

	static void pack_ciphertext(uint8_t* r, const polyvec* b, const poly* v)
	{
		/* Serialize the ciphertext as concatenation of the
		compressed and serialized vector of polynomials b
		and the compressed and serialized polynomial v. */

		polyvec_compress(r, b);
		poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
	}

	static void pack_pk(uint8_t* r, const polyvec* pk, const uint8_t* seed)
	{
		/* Serialize the public key as concatenation of the
		compressed and serialized vector of polynomials pk
		and the public seed used to generate the matrix A. */

		size_t i;

		polyvec_compress(r, pk);

		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			r[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
		}
	}

	static void pack_sk(uint8_t* r, const polyvec* sk)
	{
		/* Serialize the secret key. */

		polyvec_tobytes(r, sk);
	}

	static void poly_add(poly* r, const poly* a, const poly* b)
	{
		size_t i;

		for (i = 0; i < KYBER_N; i++)
		{
			r->coeffs[i] = barrett_reduce(a->coeffs[i] + b->coeffs[i]);
		}
	}

	static void poly_compress(uint8_t* r, const poly* a)
	{
		uint32_t t[8];
		size_t i;
		size_t j;
		size_t k;

		k = 0;

		for (i = 0; i < KYBER_N; i += 8)
		{
			for (j = 0; j < 8; j++)
			{
				/*lint -save -e662 */
				/*lint -save -e661 */
				/* checked: lint-misra 661-662 'possible out-of-bounds', this is a false positive */
				t[j] = ((((freeze(a->coeffs[i + j]) << 3) + (KYBER_Q / 2)) / KYBER_Q) & 7);
				/*lint -restore */
			}

			r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
			r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
			r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);

			k += 3;
		}
	}

	static void poly_decompress(poly* r, const uint8_t* a)
	{
		size_t i;

		for (i = 0; i < KYBER_N; i += 8)
		{
			/* checked: lint-misra 661-662 errors are all 'possible out-of-bounds' false positives */
			/*lint -save -e662 */
			/*lint -save -e661 */
			r->coeffs[i] = ((((a[0] & 7) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 1] = (((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 2] = (((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 3] = (((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 4] = (((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 5] = (((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 6] = (((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3);
			r->coeffs[i + 7] = (((((a[2] >> 5)) * KYBER_Q) + 4) >> 3);
			a += 3;
			/*lint -restore */
		}
	}

	static void poly_frombytes(poly* r, const uint8_t* a)
	{
		size_t i;

		for (i = 0; i < KYBER_N / 8; i++)
		{
			r->coeffs[8 * i] = (a[13 * i] | (((uint16_t)a[(13 * i) + 1] & 0x1F) << 8));
			r->coeffs[(8 * i) + 1] = ((a[(13 * i) + 1] >> 5) | (((uint16_t)a[(13 * i) + 2]) << 3) | (((uint16_t)a[(13 * i) + 3] & 0x03) << 11));
			r->coeffs[(8 * i) + 2] = ((a[(13 * i) + 3] >> 2) | (((uint16_t)a[(13 * i) + 4] & 0x7F) << 6));
			r->coeffs[(8 * i) + 3] = ((a[(13 * i) + 4] >> 7) | (((uint16_t)a[(13 * i) + 5]) << 1) | (((uint16_t)a[(13 * i) + 6] & 0x0F) << 9));
			r->coeffs[(8 * i) + 4] = ((a[(13 * i) + 6] >> 4) | (((uint16_t)a[(13 * i) + 7]) << 4) | (((uint16_t)a[(13 * i) + 8] & 0x01) << 12));
			r->coeffs[(8 * i) + 5] = ((a[(13 * i) + 8] >> 1) | (((uint16_t)a[(13 * i) + 9] & 0x3F) << 7));
			r->coeffs[(8 * i) + 6] = ((a[(13 * i) + 9] >> 6) | (((uint16_t)a[(13 * i) + 10]) << 2) | (((uint16_t)a[(13 * i) + 11] & 0x07) << 10));
			r->coeffs[(8 * i) + 7] = ((a[(13 * i) + 11] >> 3) | (((uint16_t)a[(13 * i) + 12]) << 5));
		}
	}

	static void poly_frommsg(poly* r, const uint8_t msg[KYBER_SYMBYTES])
	{
		size_t i;
		size_t j;
		uint16_t mask;

		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			for (j = 0; j < 8; j++)
			{
				mask = ~((msg[i] >> j) & 1) + 1;
				r->coeffs[(8 * i) + j] = (mask & ((KYBER_Q + 1) / 2));
			}
		}
	}

	static void poly_getnoise(poly* r, const uint8_t* seed, uint8_t nonce)
	{
		uint8_t buf[(KYBER_ETA * KYBER_N) / 4];

		uint8_t extseed[KYBER_SYMBYTES + 1];
		size_t i;

		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			extseed[i] = seed[i];
		}

		extseed[KYBER_SYMBYTES] = nonce;
		shake256(buf, (KYBER_ETA * KYBER_N) / 4, extseed, KYBER_SYMBYTES + 1);

		cbd(r, buf);


		/*std::vector<byte> buf((KYBER_ETA * KYBER_N) / 4);
		std::vector<byte> gkey(32);
		std::memcpy(gkey.data(), seed, 32);
		Drbg::BCG gen(Enumeration::BlockCiphers::Rijndael);

		gen.Initialize(gkey);
		gen.Generate(buf);

		cbd(r, buf.data());*/
	}

	static void poly_getnoise2(poly* r, Drbg::BCG* gen)
	{
		std::vector<byte> buf((KYBER_ETA * KYBER_N) / 4);
		gen->Generate(buf);

		cbd(r, buf.data());
	}

	static void poly_invntt(poly* r)
	{
		invntt(r->coeffs);
	}

	static void poly_ntt(poly* r)
	{
		ntt(r->coeffs);
	}

	static void poly_sub(poly* r, const poly* a, const poly* b)
	{
		size_t i;

		for (i = 0; i < KYBER_N; i++)
		{
			r->coeffs[i] = barrett_reduce(a->coeffs[i] + ((3 * KYBER_Q) - b->coeffs[i]));
		}
	}

	static void poly_tobytes(uint8_t* r, const poly* a)
	{
		uint16_t t[8];
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_N / 8; i++)
		{
			for (j = 0; j < 8; j++)
			{
				t[j] = freeze(a->coeffs[(8 * i) + j]);
			}

			r[13 * i] = (t[0] & 0xFF);
			r[(13 * i) + 1] = ((t[0] >> 8) | ((t[1] & 0x07) << 5));
			r[(13 * i) + 2] = ((t[1] >> 3) & 0xFF);
			r[(13 * i) + 3] = ((t[1] >> 11) | ((t[2] & 0x3F) << 2));
			r[(13 * i) + 4] = ((t[2] >> 6) | ((t[3] & 0x01) << 7));
			r[(13 * i) + 5] = ((t[3] >> 1) & 0xFF);
			r[(13 * i) + 6] = ((t[3] >> 9) | ((t[4] & 0x0F) << 4));
			r[(13 * i) + 7] = ((t[4] >> 4) & 0xFF);
			r[(13 * i) + 8] = ((t[4] >> 12) | ((t[5] & 0x7F) << 1));
			r[(13 * i) + 9] = ((t[5] >> 7) | ((t[6] & 0x03) << 6));
			r[(13 * i) + 10] = ((t[6] >> 2) & 0xFF);
			r[(13 * i) + 11] = ((t[6] >> 10) | ((t[7] & 0x1F) << 3));
			r[(13 * i) + 12] = (t[7] >> 5);
		}
	}

	static void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], const poly* a)
	{
		size_t i;
		size_t j;
		uint16_t t;

		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			msg[i] = 0;

			for (j = 0; j < 8; j++)
			{
				t = ((((freeze(a->coeffs[(8 * i) + j]) << 1) + KYBER_Q / 2) / KYBER_Q) & 1);
				msg[i] |= (t << j);
			}
		}
	}

	static void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b)
	{
		size_t i;

		for (i = 0; i < KYBER_K; i++)
		{
			poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
		}
	}

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))

	static void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[8];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				for (k = 0; k < 8; k++)
				{
					t[k] = ((((uint32_t)freeze(a->vec[i].coeffs[(8 * j) + k]) << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF;
				}

				r[11 * j] = (t[0] & 0xFF);
				r[(11 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x1F) << 3));
				r[(11 * j) + 2] = ((t[1] >> 5) | ((t[2] & 0x03) << 6));
				r[(11 * j) + 3] = ((t[2] >> 2) & 0xFF);
				r[(11 * j) + 4] = ((t[2] >> 10) | ((t[3] & 0x7F) << 1));
				r[(11 * j) + 5] = ((t[3] >> 7) | ((t[4] & 0x0F) << 4));
				r[(11 * j) + 6] = ((t[4] >> 4) | ((t[5] & 0x01) << 7));
				r[(11 * j) + 7] = ((t[5] >> 1) & 0xFF);
				r[(11 * j) + 8] = ((t[5] >> 9) | ((t[6] & 0x3F) << 2));
				r[(11 * j) + 9] = ((t[6] >> 6) | ((t[7] & 0x07) << 5));
				r[(11 * j) + 10] = (t[7] >> 3);
			}
			r += 352;
		}
	}

	static void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				r->vec[i].coeffs[8 * j] = ((((a[11 * j] | (((uint32_t)a[(11 * j) + 1] & 0x07) << 8)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 1] = (((((a[(11 * j) + 1] >> 3) | (((uint32_t)a[(11 * j) + 2] & 0x3F) << 5)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 2] = (((((a[(11 * j) + 2] >> 6) | (((uint32_t)a[(11 * j) + 3] & 0xFF) << 2) | (((uint32_t)a[(11 * j) + 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 3] = (((((a[(11 * j) + 4] >> 1) | (((uint32_t)a[(11 * j) + 5] & 0x0F) << 7)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 4] = (((((a[(11 * j) + 5] >> 4) | (((uint32_t)a[(11 * j) + 6] & 0x7F) << 4)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 5] = (((((a[(11 * j) + 6] >> 7) | (((uint32_t)a[(11 * j) + 7] & 0xFF) << 1) | (((uint32_t)a[(11 * j) + 8] & 0x03) << 9)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 6] = (((((a[(11 * j) + 8] >> 2) | (((uint32_t)a[(11 * j) + 9] & 0x1F) << 6)) * KYBER_Q) + 1024) >> 11);
				r->vec[i].coeffs[(8 * j) + 7] = (((((a[(11 * j) + 9] >> 5) | (((uint32_t)a[(11 * j) + 10] & 0xFF) << 3)) * KYBER_Q) + 1024) >> 11);
			}
			a += 352;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))

	static void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[4];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 4; j++)
			{
				for (k = 0; k < 4; k++)
				{
					t[k] = (((((uint32_t)freeze(a->vec[i].coeffs[(4 * j) + k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
				}

				r[5 * j] = (t[0] & 0xFF);
				r[(5 * j) + 1] = (t[0] >> 8) | ((t[1] & 0x3F) << 2);
				r[(5 * j) + 2] = (t[1] >> 6) | ((t[2] & 0x0F) << 4);
				r[(5 * j) + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
				r[(5 * j) + 4] = (t[3] >> 2);
			}
			r += 320;
		}
	}

	static void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 4; j++)
			{
				r->vec[i].coeffs[4 * j] = ((((a[5 * j] | (((uint32_t)a[(5 * j) + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 1] = (((((a[(5 * j) + 1] >> 2) | (((uint32_t)a[(5 * j) + 2] & 0x0F) << 6)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 2] = (((((a[(5 * j) + 2] >> 4) | (((uint32_t)a[(5 * j) + 3] & 0x3F) << 4)) * KYBER_Q) + 512) >> 10);
				r->vec[i].coeffs[(4 * j) + 3] = (((((a[(5 * j) + 3] >> 6) | (((uint32_t)a[(5 * j) + 4] & 0xFF) << 2)) * KYBER_Q) + 512) >> 10);
			}
			a += 320;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 288))

static void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		uint16_t t[8];
		size_t i;
		size_t j;
		size_t k;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				for (k = 0; k < 8; k++)
				{
					t[k] = (((((uint32_t)freeze(a->vec[i].coeffs[(8 * j) + k]) << 9) + KYBER_Q / 2) / KYBER_Q) & 0x1FF);
				}

				r[9 * j] = (t[0] & 0xFF);
				r[(9 * j) + 1] = ((t[0] >> 8) | ((t[1] & 0x7F) << 1));
				r[(9 * j) + 2] = ((t[1] >> 7) | ((t[2] & 0x3F) << 2));
				r[(9 * j) + 3] = ((t[2] >> 6) | ((t[3] & 0x1F) << 3));
				r[(9 * j) + 4] = ((t[3] >> 5) | ((t[4] & 0x0F) << 4));
				r[(9 * j) + 5] = ((t[4] >> 4) | ((t[5] & 0x07) << 5));
				r[(9 * j) + 6] = ((t[5] >> 3) | ((t[6] & 0x03) << 6));
				r[(9 * j) + 7] = ((t[6] >> 2) | ((t[7] & 0x01) << 7));
				r[(9 * j) + 8] = ((t[7] >> 1);
			}
			r += 288;
		}
	}

static void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N / 8; j++)
			{
				r->vec[i].coeffs[8 * j] = ((((a[9 * j] | (((uint32_t)a[(9 * j) + 1] & 0x01) << 8)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 1] = (((((a[(9 * j) + 1] >> 1) | (((uint32_t)a[(9 * j) + 2] & 0x03) << 7)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 2] = (((((a[(9 * j) + 2] >> 2) | (((uint32_t)a[(9 * j) + 3] & 0x07) << 6)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 3] = (((((a[(9 * j) + 3] >> 3) | (((uint32_t)a[(9 * j) + 4] & 0x0F) << 5)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 4] = (((((a[(9 * j) + 4] >> 4) | (((uint32_t)a[(9 * j) + 5] & 0x1F) << 4)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 5] = (((((a[(9 * j) + 5] >> 5) | (((uint32_t)a[(9 * j) + 6] & 0x3F) << 3)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 6] = (((((a[(9 * j) + 6] >> 6) | (((uint32_t)a[(9 * j) + 7] & 0x7F) << 2)) * KYBER_Q) + 256) >> 9);
				r->vec[i].coeffs[(8 * j) + 7] = (((((a[(9 * j) + 7] >> 7) | (((uint32_t)a[(9 * j) + 8] & 0xFF) << 1)) * KYBER_Q) + 256) >> 9);
			}
			a += 288;
		}
	}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 256))

static void polyvec_compress(uint8_t* r, const polyvec* a)
	{
		size_t i;
		size_t j;
		size_t k;
		uint16_t t;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N; j++)
			{
				r[j] = (((((uint32_t)freeze(a->vec[i].coeffs[j]) << 8) + KYBER_Q / 2) / KYBER_Q) & 0xFF);
			}
			r += 256;
		}
	}

static void polyvec_decompress(polyvec* r, const uint8_t* a)
	{
		size_t i;
		size_t j;

		for (i = 0; i < KYBER_K; i++)
		{
			for (j = 0; j < KYBER_N; j++)
			{
				r->vec[i].coeffs[j] = (((a[j] * KYBER_Q) + 128) >> 8);
	}
			a += 256;
		}
	}

#else 
#error "Unsupported compression of polyvec"
#endif

	static void polyvec_frombytes(polyvec* r, const uint8_t* a)
	{
		size_t i;

		for (i = 0; i < KYBER_K; i++)
		{
			poly_frombytes(&r->vec[i], a + (i * KYBER_POLYBYTES));
		}
	}

	static void polyvec_invntt(polyvec* r)
	{
		size_t i;

		for (i = 0; i < KYBER_K; i++)
		{
			poly_invntt(&r->vec[i]);
		}
	}

	static void polyvec_ntt(polyvec* r)
	{
		size_t i;

		for (i = 0; i < KYBER_K; i++)
		{
			poly_ntt(&r->vec[i]);
		}
	}

	static void polyvec_pointwise_acc(poly* r, const polyvec* a, const polyvec* b)
	{
		size_t i;
		size_t j;
		uint16_t t;

		for (j = 0; j < KYBER_N; j++)
		{
			/* 4613(0x1205UL) = 2^{2*18} % q */
			t = montgomery_reduce(0x1205UL * (uint32_t)b->vec[0].coeffs[j]);
			r->coeffs[j] = montgomery_reduce(a->vec[0].coeffs[j] * t);

			for (i = 1; i < KYBER_K; i++)
			{
				t = montgomery_reduce(0x1205UL * (uint32_t)b->vec[i].coeffs[j]);
				r->coeffs[j] += montgomery_reduce(a->vec[i].coeffs[j] * t);
			}

			r->coeffs[j] = barrett_reduce(r->coeffs[j]);
		}
	}

	static void polyvec_tobytes(uint8_t* r, const polyvec* a)
	{
		size_t i;

		for (i = 0; i < KYBER_K; i++)
		{
			poly_tobytes(r + (i * KYBER_POLYBYTES), &a->vec[i]);
		}
	}

	static void randombytes(unsigned char *buf, size_t buflen)
	{
		Provider::CSP rnd;
		std::vector<byte> buf2(buflen);
		rnd.GetBytes(buf2);
		std::memcpy(buf, buf2.data(), buflen);
	}

	static void sha3_256(unsigned char *output, const unsigned char *input, unsigned long long inlen)
	{
		Digest::Keccak256 dgt;
		std::vector<byte> inpbuf(inlen);
		std::vector<byte> outbuf(32);

		std::memcpy(inpbuf.data(), input, inlen);
		dgt.Compute(inpbuf, outbuf);
		std::memcpy(output, outbuf.data(), 32);
	}

	static void sha3_512(unsigned char *output, const unsigned char *input, unsigned long long inlen)
	{
		Digest::Keccak512 dgt;
		std::vector<byte> inpbuf(inlen);
		std::vector<byte> outbuf(64);

		std::memcpy(inpbuf.data(), input, inlen);
		dgt.Compute(inpbuf, outbuf);
		std::memcpy(output, outbuf.data(), 64);
	}

	static void shake128(unsigned char *output, unsigned int outlen, const unsigned char *input, unsigned int inplen)
	{
		std::vector<byte> tmpS(outlen);
		std::vector<byte> tmpK(inplen);
		std::memcpy(tmpK.data(), input, tmpK.size());
		Key::Symmetric::SymmetricKey key(tmpK);
		Kdf::SHAKE kdf(Enumeration::ShakeModes::SHAKE128);
		kdf.Initialize(key);
		kdf.Generate(tmpS, 0, outlen);
		std::memcpy(output, tmpS.data(), outlen);
	}

	static void shake256(unsigned char *output, unsigned int outlen, const unsigned char *input, unsigned int inplen)
	{
		std::vector<byte> tmpK(inplen);
		std::memcpy(tmpK.data(), input, tmpK.size());
		Key::Symmetric::SymmetricKey key(tmpK);
		Kdf::SHAKE kdf(Enumeration::ShakeModes::SHAKE256);
		kdf.Initialize(key);
		std::vector<byte> tmpS(outlen);
		kdf.Generate(tmpS);
		std::memcpy(output, tmpS.data(), outlen);
	}

	static void unpack_ciphertext(polyvec* b, poly* v, const uint8_t* c)
	{
		/* De-serialize and decompress ciphertext from a byte array;
		approximate inverse of pack_ciphertext. */

		polyvec_decompress(b, c);
		poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
	}

	static void unpack_pk(polyvec* pk, uint8_t* seed, const uint8_t* packedpk)
	{
		/* De-serialize and decompress public key from a byte array;
		approximate inverse of pack_pk. */

		size_t i;

		polyvec_decompress(pk, packedpk);

		for (i = 0; i < KYBER_SYMBYTES; i++)
		{
			seed[i] = packedpk[i + KYBER_POLYVECCOMPRESSEDBYTES];
		}
	}

	static void unpack_sk(polyvec* sk, const uint8_t* packedsk)
	{
		/* De-serialize the secret key; inverse of pack_sk */

		polyvec_frombytes(sk, packedsk);
	}

	static int32_t verify(const uint8_t* a, const uint8_t* b, size_t length)
	{
		size_t i;
		int32_t r;

		r = 0;

		for (i = 0; i < length; ++i)
		{
			r |= (a[i] ^ b[i]);
		}

		return r;
	}
};

NAMESPACE_MODULELWEEND
#endif
