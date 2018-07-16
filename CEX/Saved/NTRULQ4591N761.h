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

#ifndef CEX_NTRULQ4591N761_H
#define CEX_NTRULQ4591N761_H

#include "CexDomain.h"
#include "BCG.h"
#include "CSR.h"
#include "IPrng.h"
#include "Keccak512.h"

NAMESPACE_NTRU

/// 
/// internal
/// 

/// <summary>
/// The NTRU LPrime functions
/// </summary>
class NTRULQ4591N761
{
public:

	//~~~Public Constants~~~//

	/// <summary>
	/// The byte size of B's reply message to host A
	/// </summary>
	static const size_t CPRTXT_SIZE = 1175;

	/// <summary>
	/// The parameter sets formal name
	/// </summary>
	static const std::string Name;

	/// <summary>
	/// The P dimension
	/// </summary>
	static const int P = 761;

	/// <summary>
	/// The byte size of the public key polynomial
	/// </summary>
	static const size_t PUBKEY_SIZE = 1047;

	/// <summary>
	/// The byte size of the private key polynomial
	/// </summary>
	static const size_t PRIKEY_SIZE = 1238;

	/// <summary>
	/// The modulus factor
	/// </summary>
	static const int Q = 4591;

	/// <summary>
	/// The modulus shift factor
	/// </summary>
	static const int QSHIFT = 2295;

	/// <summary>
	/// The byte size of the secret seed array
	/// </summary>
	static const size_t SEED_BYTES = 32;

	/// <summary>
	/// The W dimension
	/// </summary>
	static const int W = 250;

	static const size_t NTRU_RQENCODE_LEN = 1218;
	static const size_t NTRU_RQENCODEROUNDED_LEN = 1015;
	static const size_t NTRU_SMALLENCODE_LEN = 191;

	//~~~Public Functions~~~//

	static void SelfTest()
	{
		std::vector<byte> msg1(SEED_BYTES);
		std::vector<byte> msg2(SEED_BYTES);
		std::vector<byte> ct(CPRTXT_SIZE);
		std::vector<byte> pk(PUBKEY_SIZE);
		std::vector<byte> sk(PRIKEY_SIZE);
		Prng::IPrng* rng = new Prng::CSR();
		std::unique_ptr<Prng::IPrng> rngP(rng);

		Generate(pk, sk, rngP);

		rng->GetBytes(msg1);
		Encrypt(msg1, ct, pk, rngP);

		Decrypt(msg2, ct, sk);

		if (msg1 != msg2)
		{
			throw;
		}
	}

	static int Decrypt(std::vector<byte> &Secret, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey)
	{
		//int xx = crypto_kem_dec((uint8_t*)Secret.data(), (uint8_t*)CipherText.data(), (uint8_t*)PrivateKey.data());

		std::array<int16_t, P> aB;
		std::array<int16_t, P> B;
		std::array<int16_t, 256> C;
		std::array<int8_t, P> a;
		std::vector<byte> r(32);
		std::vector<byte> checkcstr(CPRTXT_SIZE);
		std::vector<byte> maybek(32);
		size_t i;
		uint result;
		uint tmp;

		SmallDecode(a, PrivateKey);
		RqDecodeRounded(B, CipherText);
		RqMult(aB, B, a);

		for (i = 0; i < 128; ++i)
		{
			tmp = CipherText[32 + NTRU_RQENCODEROUNDED_LEN + i];
			C[2 * i] = (tmp & 15) * 287 - 2007;
			C[2 * i + 1] = (tmp >> 4) * 287 - 2007;
		}

		for (i = 0; i < 256; ++i)
		{
			C[i] = -(ModqFreeze(C[i] - aB[i] + 4 * W + 1) >> 14);
		}

		for (i = 0; i < 256; ++i)
		{
			r[i / 8] |= (C[i] << (i & 7));
		}

		std::vector<byte> sk(PrivateKey.size() - NTRU_SMALLENCODE_LEN);
		memcpy(sk.data(), (byte*)(PrivateKey.data() + NTRU_SMALLENCODE_LEN), sk.size());
		Hide(checkcstr, maybek, sk, r);
		result = Verify(CipherText, checkcstr);

		for (i = 0; i < 32; ++i)
		{
			Secret[i] = maybek[i] & ~result;
		}

		return result;/**/

	}

	static void Encrypt(std::vector<byte> &Secret, std::vector<byte> &CipherText, const std::vector<byte> &PublicKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::vector<byte> r(32);

		Rng->GetBytes(r);
		Hide(CipherText, Secret, PublicKey, r);
	}

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
	{
		std::array<int16_t, P> A;
		std::array<int16_t, P> G;
		std::array<int8_t, P> a;
		std::vector<byte> k1(32);
		std::vector<byte> k2(32);

		Rng->GetBytes(k1);
		Rng->GetBytes(k2);

		RqFromSeed(G, k1);
		SeededWeightW(a, k2);
		RqMult(A, G, a);
		RqRound3(A, A);
		std::memcpy(PublicKey.data(), k1.data(), 32);
		RqEncodeRounded(PublicKey, A);

		SmallEncode(PrivateKey, a);
		std::memcpy(PrivateKey.data() + NTRU_SMALLENCODE_LEN, PublicKey.data(), PUBKEY_SIZE);
	}

	static int crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
	{
		int8_t a[P];
		int16_t B[P];
		int16_t aB[P];
		int16_t C[256];
		uint8_t r[32];
		uint8_t checkcstr[CPRTXT_SIZE];
		uint8_t maybek[32];
		size_t i;
		uint32_t result;

		small_decode(a, sk); //a= 0,0,-1,0,0,0,1..
		rq_decoderounded(B, ct + 32);
		rq_mult(aB, B, a);

		for (i = 0; i < 128; ++i)
		{
			uint32_t x = ct[32 + NTRU_RQENCODEROUNDED_LEN + i];
			C[2 * i] = (x & 15) * 287 - 2007;
			C[2 * i + 1] = (x >> 4) * 287 - 2007;
		}
		// C= {-2007, -572, -572, -572, 576, 1724, 1437, 2011, -2007, -1720, 2, 1724, 1150, -285, 863, ...}
		for (i = 0; i < 256; ++i)
		{
			C[i] = -(modq_freeze(C[i] - aB[i] + 4 * W + 1) >> 14);
		}

		for (i = 0; i < 32; ++i)
		{
			r[i] = 0;
		}
		//C= {1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, ...}
		for (i = 0; i < 256; ++i)
		{
			r[i / 8] |= (C[i] << (i & 7));
		}
		//r= 131,48,51
		sk += NTRU_SMALLENCODE_LEN;
		hide(checkcstr, maybek, sk, r);
		result = verify(ct, checkcstr);
		// checkcstr= 79,43,82..
		// maybek= 158,192,154..
		for (i = 0; i < 32; ++i)
		{
			ss[i] = maybek[i] & ~result;
		}

		return result;
	}

	static void crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk, const uint8_t* rnd)
	{
		hide(ct, ss, pk, rnd);
	}

	static void crypto_kem_keypair(uint8_t* pk, uint8_t* sk, uint8_t* k1, uint8_t* k2)
	{
		int16_t G[P];
		int8_t a[P];
		int16_t A[P];

		rq_fromseed(G, k1);

		small_random_weightw(a, k2);

		rq_mult(A, G, a);
		rq_round3(A, A);

		memcpy(pk, k1, 32);
		rq_encoderounded(pk + 32, A);

		small_encode(sk, a);
		memcpy(sk + NTRU_SMALLENCODE_LEN, pk, PUBKEY_SIZE);
	}

	static void Hide(std::vector<byte> &cstr, std::vector<byte> &k, const std::vector<byte> &pk, const std::vector<byte> &r)
	{
		std::array<int16_t, P> G;
		std::array<int16_t, P> A;
		std::array<int16_t, P> B;
		std::array<int16_t, P> C;
		std::array<int8_t, P> b;
		std::vector<byte> k12(64);
		std::vector<byte> k34(64);
		size_t i;
		int16_t x;

		RqFromSeed(G, pk);
		RqDecodeRounded(A, pk);

		Digest::Keccak512 dgt;
		dgt.Compute(r, k12);

		SeededWeightW(b, k12);
		dgt.Update(k12, 32, 32);
		dgt.Finalize(k34, 0);

		RqMult(B, G, b);
		RqRound3(B, B);
		RqMult(C, A, b);

		for (i = 0; i < 256; ++i)
		{
			x = C[i];
			x = ModqSum(x, 2295 * (1 & (r[i / 8] >> (i & 7))));
			x = (((x + 2156) * 114) + 16384) >> 15;
			/* between 0 and 15 */
			C[i] = x;
		}

		memcpy(cstr.data(), (uint8_t*)k34.data(), 32);
		memcpy(k.data(), (uint8_t*)k34.data() + 32, 32);
		RqEncodeRounded(cstr, B);

		const size_t CTOFT = NTRU_RQENCODEROUNDED_LEN + 32;
		for (i = 0; i < 128; ++i)
		{
			cstr[CTOFT + i] = C[2 * i] + (C[(2 * i) + 1] << 4);
		}
	}

	static void hide(uint8_t* cstr, uint8_t* k, const uint8_t* pk, const uint8_t* r)
	{
		int16_t G[P];
		int16_t A[P];
		int16_t B[P];
		int16_t C[P];
		std::vector<int8_t> b(P);
		std::vector<byte> k12(64);
		std::vector<byte> k34(64);
		size_t i;
		int16_t x;

		rq_fromseed(G, pk);
		rq_decoderounded(A, pk + 32);

		Digest::Keccak512 dgt;
		std::vector<byte> tmpR(32);
		std::memcpy((uint8_t*)tmpR.data(), r, 32);
		dgt.Compute(tmpR, k12); 

		small_seeded_weightw((int8_t*)b.data(), (uint8_t*)k12.data()); //b: 4,-1,5/1..
		dgt.Update(k12, 32, 32);
		dgt.Finalize(k34, 0);

		rq_mult(B, G, (int8_t*)b.data());
		rq_round3(B, B);
		rq_mult(C, A, (int8_t*)b.data());

		for (i = 0; i < 256; ++i)
		{
			x = C[i];
			x = modq_sum(x, 2295 * (1 & (r[i / 8] >> (i & 7))));
			x = (((x + 2156) * 114) + 16384) >> 15;
			/* between 0 and 15 */
			C[i] = x;
		}
		//C: 0x013cc264 {14, 15, 10, 11, 2, 11, 1, 6, 1, 1, 5, 2, 12, 5, 12, 6, 6, 10, 8, 10, 8, 5, 6, 7, 4, 2, 0, ...}
		memcpy(cstr, (uint8_t*)k34.data(), 32); //cstr: 
		memcpy(k, (uint8_t*)k34.data() + 32, 32); //k: 

		cstr += 32;
		rq_encoderounded(cstr, B);
		cstr += NTRU_RQENCODEROUNDED_LEN;

		for (i = 0; i < 128; ++i)
		{
			*cstr++ = C[2 * i] + (C[(2 * i) + 1] << 4);
		}
	}

	static void RqDecodeRounded(std::array<int16_t, P> &f, const std::vector<byte> &c)
	{
		uint c0;
		uint c1;
		uint c2;
		uint c3;
		uint f0;
		uint f1;
		uint f2;
		int i;

		for (i = 0; i < P / 3; ++i)
		{
			c0 = c[32 + (i * 4)];
			c1 = c[33 + (i * 4)];
			c2 = c[34 + (i * 4)];
			c3 = c[35 + (i * 4)];
			f2 = (14913081 * c3 + 58254 * c2 + 228 * (c1 + 2)) >> 21;

			c2 += c3 << 8;
			c2 -= (f2 * 9) << 2;
			f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

			c1 += c2 << 8;
			c1 -= (f1 * 3) << 1;
			c0 += c1 << 8;
			f0 = c0;

			f[i * 3] = ModqFreeze(f0 * 3 + Q - QSHIFT);
			f[1 + (i * 3)] = ModqFreeze(f1 * 3 + Q - QSHIFT);
			f[2 + (i * 3)] = ModqFreeze(f2 * 3 + Q - QSHIFT);
		}

		c0 = c[32 + (i * 4)];
		c1 = c[33 + (i * 4)];
		c2 = c[34 + (i * 4)];
		f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;
		c0 += c1 << 8;
		f0 = c0;

		f[i * 3] = ModqFreeze(f0 * 3 + Q - QSHIFT);
		f[1 + (i * 3)] = ModqFreeze(f1 * 3 + Q - QSHIFT);
	}

	static void rq_decoderounded(int16_t* f, const uint8_t* c)
	{
		uint32_t c0;
		uint32_t c1;
		uint32_t c2;
		uint32_t c3;
		uint32_t f0;
		uint32_t f1;
		uint32_t f2;
		int32_t i;

		for (i = 0; i < P / 3; ++i)
		{
			c0 = *c++;
			c1 = *c++;
			c2 = *c++;
			c3 = *c++;

			/* f0 + f1*1536 + f2*1536^2 = c0 + c1*256 + c2*256^2 + c3*256^3
			with each f between 0 and 1530 */

			/* f2 = (64/9)c3 + (1/36)c2 + (1/9216)c1 + (1/2359296)c0 - [0,0.99675]
			claim: 2^21 f2 < x < 2^21(f2+1)
			where x = 14913081*c3 + 58254*c2 + 228*(c1+2)
			proof: x - 2^21 f2 = 456 - (8/9)c0 + (4/9)c1 - (2/9)c2 + (1/9)c3 + 2^21 [0,0.99675]
			at least 456 - (8/9)255 - (2/9)255 > 0
			at most 456 + (4/9)255 + (1/9)255 + 2^21 0.99675 < 2^21 */
			f2 = (14913081 * c3 + 58254 * c2 + 228 * (c1 + 2)) >> 21;

			c2 += c3 << 8;
			c2 -= (f2 * 9) << 2;

			/* f0 + f1*1536 = c0 + c1*256 + c2*256^2
			c2 <= 35 = floor((1530+1530*1536)/256^2)
			f1 = (128/3)c2 + (1/6)c1 + (1/1536)c0 - (1/1536)f0
			claim: 2^21 f1 < x < 2^21(f1+1)
			where x = 89478485*c2 + 349525*c1 + 1365*(c0+1)
			proof: x - 2^21 f1 = 1365 - (1/3)c2 - (1/3)c1 - (1/3)c0 + (4096/3)f0
			at least 1365 - (1/3)35 - (1/3)255 - (1/3)255 > 0
			at most 1365 + (4096/3)1530 < 2^21 */
			f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

			c1 += c2 << 8;
			c1 -= (f1 * 3) << 1;

			c0 += c1 << 8;
			f0 = c0;

			*f++ = modq_freeze(f0 * 3 + Q - QSHIFT);
			*f++ = modq_freeze(f1 * 3 + Q - QSHIFT);
			*f++ = modq_freeze(f2 * 3 + Q - QSHIFT);
		}

		c0 = *c++;
		c1 = *c++;
		c2 = *c++;

		f1 = (89478485 * c2 + 349525 * c1 + 1365 * (c0 + 1)) >> 21;

		c1 += c2 << 8;
		c1 -= (f1 * 3) << 1;

		c0 += c1 << 8;
		f0 = c0;

		*f++ = modq_freeze(f0 * 3 + Q - QSHIFT);
		*f++ = modq_freeze(f1 * 3 + Q - QSHIFT);
	}

	static void RqEncodeRounded(std::vector<byte> &c, const std::array<int16_t, P> &f)
	{
		int32_t f0;
		int32_t f1;
		int32_t f2;
		size_t i;

		for (i = 0; i < P / 3; ++i)
		{
			f0 = f[i * 3] + QSHIFT;
			f1 = f[1 + (i * 3)] + QSHIFT;
			f2 = f[2 + (i * 3)] + QSHIFT;
			f0 = (21846 * f0) >> 16;
			f1 = (21846 * f1) >> 16;
			f2 = (21846 * f2) >> 16;
			/* now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer */
			f2 *= 3;
			f1 += f2 << 9;
			f1 *= 3;
			f0 += f1 << 9;
			c[32 + (i * 4)] = f0; 
			f0 >>= 8;
			c[33 + (i * 4)] = f0;
			f0 >>= 8;
			c[34 + (i * 4)] = f0;
			f0 >>= 8;
			c[35 + (i * 4)] = f0;
		}

		/* using p mod 3 = 2 */
		f0 = f[i * 3] + QSHIFT;
		f1 = f[1 + (i * 3)] + QSHIFT;
		f0 = (21846 * f0) >> 16;
		f1 = (21846 * f1) >> 16;
		f1 *= 3;
		f0 += f1 << 9;
		c[32 + (i * 4)] = f0; 
		f0 >>= 8;
		c[33 + (i * 4)] = f0; 
		f0 >>= 8;
		c[34 + (i * 4)] = f0;
	}

	static void rq_encoderounded(uint8_t* c, const int16_t* f)
	{
		int32_t f0;
		int32_t f1;
		int32_t f2;
		size_t i;

		for (i = 0; i < P / 3; ++i)
		{
			f0 = *f++ + QSHIFT; //4578
			f1 = *f++ + QSHIFT; //1824
			f2 = *f++ + QSHIFT; //1308
			f0 = (21846 * f0) >> 16;
			f1 = (21846 * f1) >> 16;
			f2 = (21846 * f2) >> 16;
			/* now want f0 + f1*1536 + f2*1536^2 as a 32-bit integer */
			f2 *= 3;
			f1 += f2 << 9;
			f1 *= 3;
			f0 += f1 << 9;
			*c++ = f0; f0 >>= 8;//1029588470
			*c++ = f0; f0 >>= 8;//4021829
			*c++ = f0; f0 >>= 8;//15710
			*c++ = f0;//61
		}

		/* using p mod 3 = 2 */
		f0 = *f++ + QSHIFT; //4545
		f1 = *f++ + QSHIFT; //3135
		f0 = (21846 * f0) >> 16; //1515
		f1 = (21846 * f1) >> 16; //1045
		f1 *= 3; //3135
		f0 += f1 << 9;
		*c++ = f0; f0 >>= 8;
		*c++ = f0; f0 >>= 8;
		*c++ = f0;
	}

	static void RqFromSeed(std::array<int16_t, P> &h, const std::vector<byte> &K)
	{
		std::array<uint, P> buf;
		std::vector<byte> btbuf(P * sizeof(uint32_t));
		std::vector<byte> tmpK(32);
		std::vector<byte> n(16, 0);
		size_t i;

		std::memcpy(tmpK.data(), K.data(), 32);

		Drbg::BCG gen(Enumeration::BlockCiphers::AHX);
		gen.Initialize(tmpK, n);
		gen.Generate(btbuf, 0, btbuf.size());
		std::memcpy(buf.data(), btbuf.data(), btbuf.size());

		for (i = 0; i < P; ++i)
		{
			h[i] = ModqFromUL(buf[i]);
		}
	}

	static void rq_fromseed(int16_t* h, const uint8_t* K)
	{
		uint32_t buf[P];
		size_t i;
		std::vector<byte> n(16);

		for (i = 0; i < 16; i++)
		{
			n[i] = 0;
		}

		std::vector<byte> btbuf(P * sizeof(uint32_t));
		Drbg::BCG gen(Enumeration::BlockCiphers::AHX);
		std::vector<byte> tmpK(32);
		std::memcpy(tmpK.data(), K, 32);
		gen.Initialize(tmpK, n);
		gen.Generate(btbuf, 0, btbuf.size());
		std::memcpy(buf, btbuf.data(), btbuf.size());

		/*lint -e534 */
		//aes256_generate((uint8_t*)buf, sizeof buf, n, K);

		for (i = 0; i < P; ++i)
		{
			h[i] = modq_fromuint32(buf[i]);
		}
	}

	static void RqMult(std::array<int16_t, P> &h, const std::array<int16_t, P> &f, const std::array<int8_t, P> &g)
	{
		std::array<int16_t, P + P - 1> fg;
		size_t i;
		size_t j;
		int16_t result;

		for (i = 0; i < P; ++i)
		{
			result = 0;

			for (j = 0; j <= i; ++j)
			{
				result = ModqPlusProduct(result, f[j], g[i - j]);
			}

			fg[i] = result;
		}

		for (i = P; i < P + P - 1; ++i)
		{
			result = 0;

			for (j = i - P + 1; j < P; ++j)
			{
				result = ModqPlusProduct(result, f[j], g[i - j]);
			}

			fg[i] = result;
		}

		for (i = P + P - 2; i >= P; --i)
		{
			fg[i - P] = ModqSum(fg[i - P], fg[i]);
			fg[i - P + 1] = ModqSum(fg[i - P + 1], fg[i]);
		}

		for (i = 0; i < P; ++i)
		{
			h[i] = fg[i];
		}
	}

	static void rq_mult(int16_t* h, const int16_t* f, const int8_t* g)
	{
		int16_t fg[P + P - 1];
		int16_t result;
		size_t i;
		size_t j;

		for (i = 0; i < P; ++i)
		{
			result = 0;
			for (j = 0; j <= i; ++j)
			{
				result = modq_plusproduct(result, f[j], g[i - j]);
			}
			fg[i] = result;
		}

		for (i = P; i < P + P - 1; ++i)
		{
			result = 0;
			for (j = i - P + 1; j < P; ++j)
			{
				result = modq_plusproduct(result, f[j], g[i - j]);
			}
			fg[i] = result;
		}

		for (i = P + P - 2; i >= P; --i)
		{
			fg[i - P] = modq_sum(fg[i - P], fg[i]);
			fg[i - P + 1] = modq_sum(fg[i - P + 1], fg[i]);
		}

		for (i = 0; i < P; ++i)
		{
			h[i] = fg[i];
		}
	}

	static void RqRound3(std::array<int16_t, P> &h, const std::array<int16_t, P> &f)
	{
		int32_t i;

		for (i = 0; i < P; ++i)
		{
			h[i] = ((21846 * (f[i] + 2295) + 32768) >> 16) * 3 - 2295;
		}
	}

	static void rq_round3(int16_t* h, const int16_t* f)
	{
		int32_t i;

		for (i = 0; i < P; ++i)
		{
			h[i] = ((21846 * (f[i] + 2295) + 32768) >> 16) * 3 - 2295;
		}
	}

	static void SeededWeightW(std::array<int8_t, P> &f, const std::vector<byte> &k)
	{
		std::array<int32_t, P> r;
		std::vector<byte> tmpK(32);
		std::vector<byte> tmpR(P * sizeof(int32_t));
		size_t i;

		std::memcpy(tmpK.data(), k.data(), tmpK.size());

		Prng::CSR rng(tmpK);
		rng.GetBytes(tmpR);
		std::memcpy(r.data(), tmpR.data(), tmpR.size());

		for (i = 0; i < P; ++i)
		{
			r[i] ^= 0x80000000;
		}

		for (i = 0; i < W; ++i)
		{
			r[i] &= -2;
		}

		for (i = W; i < P; ++i)
		{
			r[i] = (r[i] & -3) | 1;
		}

		Sort(r.data(), P);

		for (i = 0; i < P; ++i)
		{
			f[i] = ((uint8_t)(r[i] & 3)) - 1;
		}
	}

	static void small_seeded_weightw(int8_t* f, const uint8_t* k)
	{
		int32_t r[P];
		std::vector<byte> tmpK(32);
		std::vector<byte> tmpR(P * sizeof(int32_t));
		size_t i;

		std::memcpy(tmpK.data(), k, tmpK.size());

		Prng::CSR rng(tmpK);
		rng.GetBytes(tmpR);
		std::memcpy(r, tmpR.data(), tmpR.size());

		for (i = 0; i < P; ++i)
		{
			r[i] ^= 0x80000000;
		}

		for (i = 0; i < W; ++i)
		{
			r[i] &= -2;
		}

		for (i = W; i < P; ++i)
		{
			r[i] = (r[i] & -3) | 1;
		}

		sort(r, P);

		for (i = 0; i < P; ++i)
		{
			f[i] = ((uint8_t)(r[i] & 3)) - 1;
		}
	}

	static void small_random_weightw(int8_t* f, uint8_t* k)
	{
		small_seeded_weightw(f, k);
	}

	static void MinMax(int32_t* x, int32_t* y)
	{
		uint32_t xi;
		uint32_t yi;
		uint32_t xy;
		uint32_t c;

		xi = *x;
		yi = *y;
		xy = xi ^ yi;
		c = yi - xi;

		c ^= xy & (c ^ yi);
		c >>= 31;
		c = ~c + 1;
		c &= xy;
		*x = xi ^ c;
		*y = yi ^ c;
	}

	static void minmax(int32_t* x, int32_t* y)
	{
		uint32_t xi;
		uint32_t yi;
		uint32_t xy;
		uint32_t c;

		xi = *x;
		yi = *y;
		xy = xi ^ yi;
		c = yi - xi;

		c ^= xy & (c ^ yi);
		c >>= 31;
		c = ~c + 1;
		c &= xy;
		*x = xi ^ c;
		*y = yi ^ c;
	}

	static void Sort(int32_t* x, int32_t n)
	{
		int32_t top;
		int32_t p;
		int32_t q;
		int32_t i;

		if (n > 1)
		{
			top = 1;

			while (top < n - top)
			{
				top += top;
			}

			for (p = top; p > 0; p >>= 1)
			{
				for (i = 0; i < n - p; ++i)
				{
					if (!(i & p))
					{
						minmax(x + i, x + i + p);
					}
				}

				for (q = top; q > p; q >>= 1)
				{
					for (i = 0; i < n - q; ++i)
					{
						if (!(i & p))
						{
							minmax(x + i + p, x + i + q);
						}
					}
				}
			}
		}
	}

	static void sort(int32_t* x, int32_t n)
	{
		int32_t top;
		int32_t p;
		int32_t q;
		int32_t i;

		if (n < 2)
		{
			return;
		}

		top = 1;

		while (top < n - top)
		{
			top += top;
		}

		for (p = top; p > 0; p >>= 1)
		{
			for (i = 0; i < n - p; ++i)
			{
				if (!(i & p))
				{
					minmax(x + i, x + i + p);
				}
			}

			for (q = top; q > p; q >>= 1)
			{
				for (i = 0; i < n - q; ++i)
				{
					if (!(i & p))
					{
						minmax(x + i + p, x + i + q);
					}
				}
			}
		}
	}

	static void rq_fromseed(std::array<int16_t, P> &h, const std::vector<byte> &K)
	{
		std::vector<uint> buf(P);
		size_t i;

		Prng::CSR rng(K);
		rng.Fill(buf, 0, buf.size());

		for (i = 0; i < P; ++i)
		{
			h[i] = modq_fromuint32(buf[i]);
		}
	}

	static int16_t ModqFreeze(int32_t a)
	{
		/* input between -9000000 and 9000000 output between -2295 and 2295 */
		a -= 4591 * ((228 * a) >> 20);
		a -= 4591 * ((58470 * a + 134217728) >> 28);

		return a;
	}

	static int16_t modq_freeze(int32_t a)
	{
		/* input between -9000000 and 9000000 output between -2295 and 2295 */
		a -= 4591 * ((228 * a) >> 20);
		a -= 4591 * ((58470 * a + 134217728) >> 28);

		return a;
	}

	static int16_t ModqFromUL(uint32_t a)
	{
		/* input between 0 and 4294967295 output = (input % 4591) - 2295 */
		int32_t r;

		r = (a & 524287) + (a >> 19) * 914; /* <= 8010861 */

		return ModqFreeze(r - 2295);
	}

	static int16_t modq_fromuint32(uint32_t a)
	{
		/* input between 0 and 4294967295 output = (input % 4591) - 2295 */
		int32_t r;

		r = (a & 524287) + (a >> 19) * 914; /* <= 8010861 */

		return modq_freeze(r - 2295);
	}

	static int16_t ModqPlusProduct(int16_t a, int16_t b, int16_t c)
	{
		int32_t s = a + (b * c);

		return ModqFreeze(s);
	}

	static int16_t modq_plusproduct(int16_t a, int16_t b, int16_t c)
	{
		int32_t s = a + (b * c);

		return modq_freeze(s);
	}

	static int16_t ModqSum(int16_t a, int16_t b)
	{
		int32_t s = a + b;

		return ModqFreeze(s);
	}

	static int16_t modq_sum(int16_t a, int16_t b)
	{
		int32_t s = a + b;

		return modq_freeze(s);
	}

	static void SmallEncode(std::vector<byte> &c, const std::array<int8_t, P> &f)
	{
		/* all coefficients in -1, 0, 1 */
		size_t i;
		uint8_t c0;

		for (i = 0; i < P / 4; ++i)
		{
			c0 = f[i * 4] + 1;
			c0 += (f[1 + i * 4] + 1) << 2;
			c0 += (f[2 + i * 4] + 1) << 4;
			c0 += (f[3 + i * 4] + 1) << 6;
			c[i] = c0;
		}

		c0 = f[i * 4] + 1;
		c[i] = c0;
	}

	static void small_encode(uint8_t* c, const int8_t* f)
	{
		/* all coefficients in -1, 0, 1 */
		uint8_t c0;
		size_t i;

		for (i = 0; i < P / 4; ++i)
		{
			c0 = *f++ + 1;
			c0 += (*f++ + 1) << 2;
			c0 += (*f++ + 1) << 4;
			c0 += (*f++ + 1) << 6;
			*c++ = c0;
		}

		c0 = *f++ + 1;
		*c++ = c0;
	}

	static void SmallDecode(std::array<int8_t, P> &f, const std::vector<byte> &c)
	{
		uint8_t c0;
		size_t i;

		for (i = 0; i < P / 4; ++i)
		{
			c0 = c[i];
			f[i * 4] = ((uint8_t)(c0 & 3)) - 1; 
			c0 >>= 2;
			f[1 + (i * 4)] = ((uint8_t)(c0 & 3)) - 1;
			c0 >>= 2;
			f[2 + (i * 4)] = ((uint8_t)(c0 & 3)) - 1;
			c0 >>= 2;
			f[3 + (i * 4)] = ((uint8_t)(c0 & 3)) - 1;
		}

		c0 = c[i];
		f[i * 4] = ((uint8_t)(c0 & 3)) - 1;
	}

	static void small_decode(int8_t* f, const uint8_t* c)
	{
		uint8_t c0;
		size_t i;

		for (i = 0; i < P / 4; ++i)
		{
			c0 = *c++;
			*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
			*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
			*f++ = ((uint8_t)(c0 & 3)) - 1; c0 >>= 2;
			*f++ = ((uint8_t)(c0 & 3)) - 1;
		}

		c0 = *c++;
		*f++ = ((uint8_t)(c0 & 3)) - 1;
	}

	static int32_t Verify(const std::vector<byte> &x, const std::vector<byte> &y)
	{
		uint32_t diff = 0;
		size_t i;

		for (i = 0; i < CPRTXT_SIZE; ++i)
		{
			diff |= x[i] ^ y[i];
		}

		return (1 & ((diff - 1) >> 8)) - 1;
	}

	static int32_t verify(const uint8_t* x, const uint8_t* y)
	{
		uint32_t diff = 0;
		size_t i;

		for (i = 0; i < CPRTXT_SIZE; ++i)
		{
			diff |= x[i] ^ y[i];
		}

		return (1 & ((diff - 1) >> 8)) - 1;
	}
};

NAMESPACE_NTRUEND
#endif
