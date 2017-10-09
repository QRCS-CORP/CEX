#ifndef _CEX_MCOPERATIONS_H
#define _CEX_MCOPERATIONS_H

#include "CexDomain.h"
#include "sk_gen2.h"
#include "pk_gen2.h"
#include "encrypt2.h"
#include "decrypt2.h"
#include "params.h"
#include "IPrng.h"
#include "Salsa20.h"
#include "Keccak512.h"
#include "SymmetricKey.h"
#include "GCM.h"
#include "IntUtils.h"

#include "decrypt3.h"
#include "encrypt3.h"
#include "sk_gen3.h"
#include "pk_gen3.h"

//#include "FFTM12T62.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class operations
{
public:

	static int mcbits_encrypt(unsigned char *c, size_t &clen, const unsigned char *m, unsigned long long mlen, const unsigned char *pk, Prng::IPrng* r)
	{
		unsigned char e[1 << (GFBITS - 3)];
		std::vector<byte> key(64);
		std::vector<byte> key2(32);
		std::vector<byte> nonce(16);
		std::vector<byte> tag(16);
		std::vector<byte> m2(32);
		std::vector<byte> c2(141);
		std::vector<byte> ct2(32);
		memcpy(&m2[0], &m[0], 32);

		encrypt2::encrypt(c, e, pk, r);
		memcpy(&c2[0], &c[0], 141);

		std::vector<byte> e2(1 << (GFBITS - 3));
		memcpy(&e2[0], &e[0], e2.size());

		Digest::Keccak512 dgt;
		dgt.Compute(e2, key);
		memcpy(&key2[0], &key[0], 32);
		memcpy(&nonce[0], &key[32], 16);

		Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
		Key::Symmetric::SymmetricKey k(key2, nonce);
		cpr.Initialize(true, k);
		cpr.Transform(m2, 0, c2, c2.size() - 48, 32);
		cpr.Finalize(c2, c2.size() - 16, 16);
		//p1305::crypto_onetimeauth_poly1305_donna(tag, ct, mlen, (unsigned char*)key.data() + 32);
		memcpy(&c[0], &c2[0], c2.size());

		clen = SYND_BYTES + mlen + 16;

#undef ct
#undef tag

		return 0;
	}

	static int mcbits_encrypt2(std::vector<byte> &c, size_t clen, std::vector<byte> &m, size_t mlen, const std::vector<byte> &pk, Prng::IPrng* r, size_t Dimension, size_t Factor)
	{
		std::vector<byte> m2 = m;
		std::vector<byte> c2 = c;
		std::vector<byte> e2(1 << (Dimension - 3));

		std::vector<byte> e(1 << (Dimension - 3));
		std::vector<byte> rnd(64);
		std::vector<byte> key(32);
		std::vector<byte> nonce(16);
		//std::vector<byte> tag(16);

		encrypt3::encrypt(c, e, pk, r, Dimension, Factor);

		Digest::Keccak512 dgt;
		dgt.Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 32);
		memcpy(&nonce[0], &rnd[32], 16);

		Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
		Key::Symmetric::SymmetricKey k(key, nonce);
		cpr.Initialize(true, k);
		cpr.Transform(m, 0, c, c.size() - 48, 32);
		cpr.Finalize(c, c.size() - 16, 16);

		/*Digest::Keccak512* dgt2 = new Digest::Keccak512;
		Cipher::Symmetric::Block::Mode::GCM* cpr2 = new Cipher::Symmetric::Block::Mode::GCM(Enumeration::BlockCiphers::Rijndael);

		int x = FFTM12T62::Encrypt(c, m, pk, r, dgt2, cpr2);*/

		return 0;
	}

	static int oqs_kex_mcbits_decrypt(unsigned char *m, size_t mlen, const unsigned char *c, unsigned long long clen, const unsigned char *sk)
	{
		int ret = 0;
		int ret_verify;
		int ret_decrypt, ret_decrypt2;
		unsigned char key[64];
		unsigned char nonce[8] = { 0 };
		unsigned char e[1 << (GFBITS - 3)];

		if (clen < SYND_BYTES + 16)
			return -1;
		else
			mlen = clen - SYND_BYTES - 16;

#define ct (c + SYND_BYTES)
#define tag (ct + *mlen)

		ret_decrypt = decrypt2::decrypt(e, sk, c);

		// added
		std::vector<byte> ex(1 << (GFBITS - 3));
		std::vector<byte> skx(5984);
		std::vector<byte> cx(clen);
		memcpy(&cx[0], &c[0], cx.size());
		memcpy(&skx[0], &sk[0], skx.size());
		ret_decrypt2 = decrypt3::decrypt(ex, skx, cx, GFBITS, SYS_T);

		for (size_t i = 0; i < ex.size(); ++i)
		{
			if (e[i] != ex[i])
			{
				throw;
			}

		}
		for (size_t i = 0; i < cx.size(); ++i)
		{
			if (c[i] != cx[i])
			{
				throw;
			}
		}
		//

		std::vector<byte> e2(1 << (GFBITS - 3));
		memcpy(&e2[0], &e[0], e2.size());

		std::vector<byte> keym(64);
		std::vector<byte> key2(32);
		std::vector<byte> key3(32);
		std::vector<byte> nonce2(16);

		Digest::Keccak512 dgt;
		dgt.Compute(e2, keym);
		memcpy(&key2[0], &keym[0], 32);
		memcpy(&nonce2[0], &keym[32], 16);

		std::vector<byte> m2(32);
		std::vector<byte> c2(141);
		memcpy(&c2[0], &c[0], 141);
		memcpy(&m2[0], &m[0], 32);

		Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
		Key::Symmetric::SymmetricKey k(key2, nonce2);
		cpr.Initialize(false, k);
		cpr.Transform(c2, c2.size() - 48, key3, 0, 32);
		cpr.Verify(c2, c2.size() - 16, 16);

		//p1305::crypto_onetimeauth_poly1305_donna(tag, ct, mlen, (unsigned char*)key.data() + 32);
		memcpy(&m[0], &key3[0], key3.size());




		////crypto_hash_keccakc1024(key, e, sizeof(e)); TODO is this ok to replace with the below?
		//OQS_SHA3_sha3512(key, e, sizeof(e));

		//ret_verify = crypto_onetimeauth_poly1305_verify(tag, ct, *mlen, key + 32);
		//crypto_stream_salsa20_xor(m, ct, *mlen, nonce, key);

		//ret = ret_verify | ret_decrypt;

#undef ct
#undef tag

		return ret;
	}

	/*static int oqs_kex_mcbits_decrypt2(std::vector<byte> &m, size_t mlen, const std::vector<byte> &c, size_t clen, const std::vector<byte> &sk, size_t Dimension, size_t Factor)
	{
		std::vector<byte> m2 = m;
		std::vector<byte> c2 = c;

		std::vector<byte> e(1 << (GFBITS - 3)); 

		if (decrypt3::decrypt(e, sk, c, GFBITS, SYS_T) != 0)
			return -1;

		std::vector<byte> rnd(64);
		std::vector<byte> key(32);
		std::vector<byte> nonce(16);
		Digest::Keccak512 dgt;

		dgt.Compute(e, rnd);
		memcpy(&key[0], &rnd[0], 32);
		memcpy(&nonce[0], &rnd[32], 16);

		Cipher::Symmetric::Block::Mode::GCM cpr(Enumeration::BlockCiphers::Rijndael);
		Key::Symmetric::SymmetricKey kp(key, nonce);
		cpr.Initialize(false, kp);
		cpr.Transform(c, c.size() - 48, m, 0, 32);

		if (!cpr.Verify(c, c.size() - 16, 16))
			return -1;

		Digest::Keccak512* dgt = new Digest::Keccak512;
		Cipher::Symmetric::Block::Mode::GCM* cpr = new Cipher::Symmetric::Block::Mode::GCM(Enumeration::BlockCiphers::Rijndael);

		int x = FFTM12T62::Decrypt(m, c, sk, dgt, cpr);

		return x;
	}*/

	static int oqs_kex_mcbits_gen_keypair2(std::vector<byte> &pk, std::vector<byte> &sk, Prng::IPrng* r, size_t Dimension, size_t Factor)
	{
		int x = 0;// FFTM12T62::Generate(pk, sk, r);
		return x;
		/*std::vector<byte> pk2 = pk;

		while (1)
		{
			sk_gen2::sk_gen(sk.data(), r);
			//sk_gen3::sk_gen(sk, r, Dimension, Factor);

			pk_gen3::pk_gen(pk2, sk, Dimension, Factor);
			pk_gen2::pk_gen(pk.data(), sk.data());

			//if (pk != pk2)
			//	throw;

			//sk_gen2::sk_gen(sk.data(), r);
			if (pk_gen2::pk_gen(pk.data(), sk.data()) == 0)
				break;
			//if (pk_gen3::pk_gen(pk, sk, Dimension, Factor) == 0)
			//	break;
		}

		return 0;*/
	}

	static int oqs_kex_mcbits_gen_keypair(unsigned char *pk, unsigned char *sk, Prng::IPrng* r)
	{

		while (1)
		{
			sk_gen2::sk_gen(sk, r);

			if (pk_gen2::pk_gen(pk, sk) == 0)
				break;
		}

		return 0;
	}
};

NAMESPACE_MCELIECEEND
#endif