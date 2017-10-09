#ifndef _CEX_POLY_H
#define _CEX_POLY_H

#include "CexDomain.h"
#include "params.h"
#include "IPrng.h"
#include "CMG.h"
#include "SymmetricKey.h"
#include "precomp.h"

#include "PolyMath.h"

//#include <oqs/rand.h>
//#include <oqs/sha3.h>

// TODO:
// Name changes and formatting
// Move as many as possible to PolyMath
// Add remainder to FFTQ12289N1024 class

NAMESPACE_RINGLWE

static const uint32_t QINV = 12287; // -inverse_mod(p,2^18)
static const uint32_t RLOG = 18;

static uint16_t MontgomeryReduce(uint32_t A) // N
{
	uint32_t u = (A * QINV);
	u &= ((1 << RLOG) - 1);
	u *= PARAM_Q;
	A = A + u;

	return A >> 18;
}

static uint16_t BarrettReduce(uint16_t A) // Y
{
	uint32_t u = ((uint32_t) A * 5) >> 16;
	u *= PARAM_Q;
	A -= u;
	return A;
}

static void BitReverse(std::vector<uint16_t> &Poly) // Y
{
	uint32_t r;
	uint16_t tmp;

	for (size_t i = 0; i < PARAM_N; i++)
	{
		r = bitrev_table[i];
		if (i < r) 
		{
			tmp = Poly[i];
			Poly[i] = Poly[r];
			Poly[r] = tmp;
		}
	}
}

static void Mul(std::vector<uint16_t> &Poly, const std::vector<uint16_t> &Factors) // N
{
	for (size_t i = 0; i < PARAM_N; i++) 
		Poly[i] = MontgomeryReduce((Poly[i] * Factors[i]));
}

static void FwdNTT(std::vector<uint16_t> &A, const std::vector<uint16_t> &Omega) // N?
{
	// GS_bo_to_no; omegas need to be in Montgomery domain
	int i, start, j, jTwiddle, distance;
	uint16_t temp, W;

	for (i = 0; i < 10; i += 2)
	{
		// Even level
		distance = (1 << i);
		for (start = 0; start < distance; start++) 
		{
			jTwiddle = 0;
			for (j = start; j < PARAM_N - 1; j += 2 * distance) 
			{
				W = Omega[jTwiddle++];
				temp = A[j];
				A[j] = (temp + A[j + distance]); // Omit reduction (be lazy)
				A[j + distance] = MontgomeryReduce((W * ((uint32_t) temp + 3 * PARAM_Q - A[j + distance])));
			}
		}

		// Odd level
		distance <<= 1;
		for (start = 0; start < distance; start++) 
		{
			jTwiddle = 0;
			for (j = start; j < PARAM_N - 1; j += 2 * distance)
			{
				W = Omega[jTwiddle++];
				temp = A[j];
				A[j] = PolyMath::BarrettReduce((temp + A[j + distance]), PARAM_Q);
				A[j + distance] = MontgomeryReduce((W * ((uint32_t) temp + 3 * PARAM_Q - A[j + distance])));
			}
		}
	}
}

static void FromBytes(std::vector<uint16_t> &R, const std::vector<uint8_t> &A) // Y
{
	for (size_t i = 0; i < PARAM_N / 4; i++)
	{
		R[4 * i + 0] = A[7 * i + 0] | (((uint16_t) A[7 * i + 1] & 0x3f) << 8);
		R[4 * i + 1] = (A[7 * i + 1] >> 6) | (((uint16_t) A[7 * i + 2]) << 2) | (((uint16_t) A[7 * i + 3] & 0x0f) << 10);
		R[4 * i + 2] = (A[7 * i + 3] >> 4) | (((uint16_t) A[7 * i + 4]) << 4) | (((uint16_t) A[7 * i + 5] & 0x03) << 12);
		R[4 * i + 3] = (A[7 * i + 5] >> 2) | (((uint16_t) A[7 * i + 6]) << 6);
	}
}

static void ToBytes(std::vector<uint8_t> &R, const std::vector<uint16_t> &p)  // Y?
{
	uint16_t t0, t1, t2, t3, m;
	int16_t c;

	for (size_t i = 0; i < PARAM_N / 4; i++) 
	{
		t0 = BarrettReduce(p[4 * i + 0]); //Make sure that coefficients have only 14 bits
		t1 = BarrettReduce(p[4 * i + 1]);
		t2 = BarrettReduce(p[4 * i + 2]);
		t3 = BarrettReduce(p[4 * i + 3]);

		m = t0 - PARAM_Q;
		c = m;
		c >>= 15;
		t0 = m ^ ((t0 ^ m) & c); // <Make sure that coefficients are in [0,q]

		m = t1 - PARAM_Q;
		c = m;
		c >>= 15;
		t1 = m ^ ((t1 ^ m) & c); // <Make sure that coefficients are in [0,q]

		m = t2 - PARAM_Q;
		c = m;
		c >>= 15;
		t2 = m ^ ((t2 ^ m) & c); // <Make sure that coefficients are in [0,q]

		m = t3 - PARAM_Q;
		c = m;
		c >>= 15;
		t3 = m ^ ((t3 ^ m) & c); // <Make sure that coefficients are in [0,q]

		R[7 * i + 0] = t0 & 0xff;
		R[7 * i + 1] = (t0 >> 8) | (t1 << 6);
		R[7 * i + 2] = (t1 >> 2);
		R[7 * i + 3] = (t1 >> 10) | (t2 << 4);
		R[7 * i + 4] = (t2 >> 4);
		R[7 * i + 5] = (t2 >> 12) | (t3 << 2);
		R[7 * i + 6] = (t3 >> 6);
	}
}

static void PolyUniform(std::vector<uint16_t> &A, const std::vector<uint8_t> &Seed) // N
{
	size_t ctr = 0;
	size_t pos = 0;
	uint16_t val;

	Drbg::CMG eng(Enumeration::BlockCiphers::Rijndael);
	size_t bufLen = 2 * PARAM_N * sizeof(uint16_t);
	if (bufLen >= eng.ParallelProfile().ParallelMinimumSize())
	{
		bufLen -= (bufLen % eng.ParallelProfile().ParallelMinimumSize());
		eng.ParallelProfile().ParallelBlockSize() = bufLen;
	}
	eng.Initialize(Seed);
	std::vector<uint8_t> buf(bufLen);
	eng.Generate(buf, 0, buf.size());

	while (ctr < PARAM_N) 
	{
		val = (buf[pos] | ((uint16_t) buf[pos + 1] << 8)) & 0x3fff; // 16393 - Specialized for q = 12889
		if (val < PARAM_Q) 
			A[ctr++] = val;

		pos += 2;
		if (pos >= buf.size())
		{
			eng.Generate(buf, 0, buf.size());
			pos = 0;
		}
	}
}

static void GetNoise(std::vector<uint16_t> &R, Prng::IPrng* Rand) // N
{
#if PARAM_K != 16
#error "GetNoise in poly.c only supports k=16"
#endif

	std::vector<uint8_t> buf(4 * PARAM_N);
	uint32_t t, d, a, b;

	Rand->GetBytes(buf);

	for (size_t i = 0; i < PARAM_N; i++) 
	{
		t = buf[i];
		d = 0;

		for (size_t j = 0; j < 8; j++)
			d += (t >> j) & 0x01010101;
		
		a = ((d >> 8) & 0xff) + (d & 0xff);
		b = (d >> 24) + ((d >> 16) & 0xff);
		R[i] = a + PARAM_Q - b;
	}
}

static void PolyPointwise(std::vector<uint16_t> &R, const std::vector<uint16_t> &A, const std::vector<uint16_t> &B)  // N
{
	uint16_t t;

	for (size_t i = 0; i < PARAM_N; i++)
	{
		t = MontgomeryReduce(3186 * B[i]); // t is now in Montgomery domain
		R[i] = MontgomeryReduce(A[i] * t); // R[i] is back in normal domain
	}
}

static void Add(std::vector<uint16_t> &R, const std::vector<uint16_t> &A, const std::vector<uint16_t> &B)  // Y
{
	for (size_t i = 0; i < PARAM_N; i++)
		R[i] = BarrettReduce(A[i] + B[i]);
}

static void PolyNTT(std::vector<uint16_t> &R)  // N
{
	Mul(R, psis_bitrev_montgomery);
	FwdNTT(R, omegas_montgomery);
}

static void PolyInvNTT(std::vector<uint16_t> &R)  // N
{
	BitReverse(R);
	FwdNTT(R, omegas_inv_montgomery);
	Mul(R, psis_inv_montgomery);
}

//Error Correction:

static int32_t Abs(int32_t V)  // Y
{
	int32_t mask = V >> 31;
	return (V ^ mask) - mask;
}

static int32_t F(int32_t &V0, int32_t &V1, int32_t X) // N
{
	int32_t xit, t, r, b;

	// Next 6 lines compute t = x/PARAM_Q;
	b = X * 2730;
	t = b >> 25;
	b = X - t * 12289;
	b = 12288 - b;
	b >>= 31;
	t -= b;

	r = t & 1;
	xit = (t >> 1);
	// v0 = round(x/(2*PARAM_Q))
	V0 = xit + r;

	t -= 1;
	r = t & 1;
	V1 = (t >> 1) + r;

	return Abs(X - (V0 * 2 * PARAM_Q));
}

static int32_t G(int32_t X) // N
{
	int32_t t, c, b;

	// Next 6 lines compute t = x/(4*PARAM_Q);
	b = X * 2730;
	t = b >> 27;
	b = X - t * 49156;
	b = 49155 - b;
	b >>= 31;
	t -= b;

	c = t & 1;
	// t = round(x/(8*PARAM_Q))
	t = (t >> 1) + c;
	t *= 8 * PARAM_Q;

	return Abs(t - X);
}

static int16_t LdDecode(int32_t Xi0, int32_t Xi1, int32_t Xi2, int32_t Xi3) // N
{
	int32_t t;

	t = G(Xi0);
	t += G(Xi1);
	t += G(Xi2);
	t += G(Xi3);
	t -= 8 * PARAM_Q;
	t >>= 31;

	return t & 1;
}

static void HelpRec(std::vector<uint16_t> &C, const std::vector<uint16_t> &V, Prng::IPrng* Rand) // N
{
	std::vector<int32_t> v0(4); 
	std::vector<int32_t> v1(4);
	std::vector<uint32_t> v_tmp(4); 
	int32_t k;

	unsigned char rbit;
	std::vector<uint8_t> rnd(32);
	int i;

	Rand->GetBytes(rnd);

	for (i = 0; i < 256; i++) 
	{
		rbit = (rnd[i >> 3] >> (i & 7)) & 1;

		k = F(v0[0], v1[0], 8 * V[0 + i] + 4 * rbit);
		k += F(v0[1], v1[1], 8 * V[256 + i] + 4 * rbit);
		k += F(v0[2], v1[2], 8 * V[512 + i] + 4 * rbit);
		k += F(v0[3], v1[3], 8 * V[768 + i] + 4 * rbit);

		k = (2 * PARAM_Q - 1 - k) >> 31;

		v_tmp[0] = ((~k) & v0[0]) ^ (k & v1[0]);
		v_tmp[1] = ((~k) & v0[1]) ^ (k & v1[1]);
		v_tmp[2] = ((~k) & v0[2]) ^ (k & v1[2]);
		v_tmp[3] = ((~k) & v0[3]) ^ (k & v1[3]);

		C[0 + i] = (v_tmp[0] - v_tmp[3]) & 3;
		C[256 + i] = (v_tmp[1] - v_tmp[3]) & 3;
		C[512 + i] = (v_tmp[2] - v_tmp[3]) & 3;
		C[768 + i] = (-k + 2 * v_tmp[3]) & 3;
	}
}

static void Rec(std::vector<uint8_t> &key, const std::vector<uint16_t> &V, const std::vector<uint16_t> &C) // N
{
	int i;
	int32_t tmp[4];

	for (i = 0; i < 32; i++)
		key[i] = 0;

	for (i = 0; i < 256; i++)
	{
		tmp[0] = 16 * PARAM_Q + 8 * (int32_t) V[0 + i] - PARAM_Q * (2 * C[0 + i] + C[768 + i]);
		tmp[1] = 16 * PARAM_Q + 8 * (int32_t) V[256 + i] - PARAM_Q * (2 * C[256 + i] + C[768 + i]);
		tmp[2] = 16 * PARAM_Q + 8 * (int32_t) V[512 + i] - PARAM_Q * (2 * C[512 + i] + C[768 + i]);
		tmp[3] = 16 * PARAM_Q + 8 * (int32_t) V[768 + i] - PARAM_Q * (C[768 + i]);

		key[i >> 3] |= LdDecode(tmp[0], tmp[1], tmp[2], tmp[3]) << (i & 7);
	}
}

NAMESPACE_RINGLWEEND
#endif
