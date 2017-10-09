#ifndef NEWHOPE_H
#define NEWHOPE_H

#include "CexDomain.h"
#include "params.h"
#include "poly.h"
#include "IPrng.h"

NAMESPACE_RINGLWE

static void EncodeA(std::vector<uint8_t> &R, const std::vector<uint16_t> &Pk, const std::vector<uint8_t> &Seed) 
{
	ToBytes(R, Pk);

	for (size_t i = 0; i < NEWHOPE_SEEDBYTES; i++)
		R[POLY_BYTES + i] = Seed[i];
}

static void DecodeA(std::vector<uint16_t> &Pk, std::vector<uint8_t> &Seed, std::vector<uint8_t> &R) 
{
	FromBytes(Pk, R);

	for (size_t i = 0; i < NEWHOPE_SEEDBYTES; i++)
		Seed[i] = R[POLY_BYTES + i];
}

static void EncodeB(std::vector<uint8_t> &R, const std::vector<uint16_t> &B, const std::vector<uint16_t> &C) 
{
	ToBytes(R, B);

	for (size_t i = 0; i < PARAM_N / 4; i++)
		R[POLY_BYTES + i] = C[4 * i] | (C[4 * i + 1] << 2) | (C[4 * i + 2] << 4) | (C[4 * i + 3] << 6);
}

static void DecodeB(std::vector<uint16_t> &B, std::vector<uint16_t> &C, std::vector<uint8_t> &R)
{
	FromBytes(B, R);

	for (size_t i = 0; i < PARAM_N / 4; i++)
	{
		C[4 * i + 0] = R[POLY_BYTES + i] & 0x03;
		C[4 * i + 1] = (R[POLY_BYTES + i] >> 2) & 0x03;
		C[4 * i + 2] = (R[POLY_BYTES + i] >> 4) & 0x03;
		C[4 * i + 3] = (R[POLY_BYTES + i] >> 6);
	}
}

static void GenA(std::vector<uint16_t> &A, const std::vector<uint8_t> &Seed) 
{
	PolyUniform(A, Seed);
}

// API FUNCTIONS

static void KeyGen(std::vector<uint8_t> &Send, std::vector<uint16_t> &Sk, Prng::IPrng* Rand)
{
	std::vector<uint16_t> a(PARAM_N);
	std::vector<uint16_t> e(PARAM_N);
	std::vector<uint16_t> r(PARAM_N);
	std::vector<uint16_t> pk(PARAM_N);
	std::vector<uint8_t> seed(NEWHOPE_SEEDBYTES);
	Rand->GetBytes(seed);

	GenA(a, seed);
	GetNoise(Sk, Rand);
	PolyNTT(Sk);
	GetNoise(e, Rand);
	PolyNTT(e);
	PolyPointwise(r, Sk, a);
	Add(pk, e, r);
	EncodeA(Send, pk, seed);
}

static void SharedB(std::vector<uint8_t> &SharedKey, std::vector<uint8_t> &Send, std::vector<uint8_t> &Received, Prng::IPrng *Rand) 
{
	std::vector<uint16_t> sp(PARAM_N);
	std::vector<uint16_t> ep(PARAM_N);
	std::vector<uint16_t> v(PARAM_N);
	std::vector<uint16_t> a(PARAM_N);
	std::vector<uint16_t> pka(PARAM_N);
	std::vector<uint16_t> c(PARAM_N);
	std::vector<uint16_t> epp(PARAM_N);
	std::vector<uint16_t> bp(PARAM_N);
	std::vector<uint8_t> seed(NEWHOPE_SEEDBYTES);

	DecodeA(pka, seed, Received); // get pub key a
	GenA(a, seed);

	GetNoise(sp, Rand); // gen pri key b
	PolyNTT(sp);
	GetNoise(ep, Rand);
	PolyNTT(ep);

	PolyPointwise(bp, a, sp); // mix the two
	Add(bp, bp, ep);

	PolyPointwise(v, pka, sp);
	PolyInvNTT(v);

	GetNoise(epp, Rand); // get b pub key
	Add(v, v, epp);

	HelpRec(c, v, Rand);
	EncodeB(Send, bp, c);
	Rec(SharedKey, v, c);

#ifndef STATISTICAL_TEST
//	OQS_SHA3_sha3256(SharedKey, SharedKey, 32); // TODO: add digest
#endif
}

static void SharedA(std::vector<uint8_t> &SharedKey, const std::vector<uint16_t> &Sk, std::vector<uint8_t> &Received) 
{
	std::vector<uint16_t> v(PARAM_N);
	std::vector<uint16_t> bp(PARAM_N);
	std::vector<uint16_t> c(PARAM_N);

	DecodeB(bp, c, Received);
	PolyPointwise(v, Sk, bp);
	PolyInvNTT(v);
	Rec(SharedKey, v, c);

#ifndef STATISTICAL_TEST
//	OQS_SHA3_sha3256(SharedKey, SharedKey, 32); // TODO: add digest
#endif
}

NAMESPACE_RINGLWEEND
#endif
