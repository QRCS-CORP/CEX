#include "FFTQ40961N1024.h"
#include "BCG.h"
#include <future>
#include "MemUtils.h"
#include "PFMQ40961N1024.h"
#include "PolyMath.h"

#if defined(__AVX512__)
#	include "UInt512.h"
#elif defined(__AVX2__)
#	include "UInt256.h"
#elif defined(__AVX__)
#	include "UInt128.h"
#endif

NAMESPACE_RINGLWE

// *** NOTE: This a non-functioning prototype and not to be used! *** //

//~~~Constant Tables~~~//

const std::string FFTQ40961N1024::Name = "Q40961N1024";

const std::vector<ushort> FFTQ40961N1024::OmegasMontgomery = {}; // TODO: ?

const std::vector<ushort> FFTQ40961N1024::OmegasInvMontgomery = {}; // TODO: ?

const std::vector<ushort> FFTQ40961N1024::PsisBitrevMontgomery = {}; // TODO: ?

const std::vector<ushort> FFTQ40961N1024::PsisInvMontgomery = {}; // TODO: ?

//~~~Public Functions~~~//

void FFTQ40961N1024::DecodeA(std::vector<ushort> &Pk, std::vector<byte> &Seed, const std::vector<byte> &R)
{
	FromBytes(Pk, R);
	Utility::MemUtils::Copy(R, POLY_BYTES, Seed, 0, SEED_BYTES);
}

void FFTQ40961N1024::DecodeB(std::vector<ushort> &B, std::vector<ushort> &C, const std::vector<byte> &R)
{
	FromBytes(B, R);

	for (size_t i = 0; i < N / 4; i++)
	{
		C[4 * i + 0] = R[POLY_BYTES + i] & 0x03;
		C[4 * i + 1] = (R[POLY_BYTES + i] >> 2) & 0x03;
		C[4 * i + 2] = (R[POLY_BYTES + i] >> 4) & 0x03;
		C[4 * i + 3] = (R[POLY_BYTES + i] >> 6);
	}
}

void FFTQ40961N1024::EncodeA(std::vector<byte> &R, const std::vector<ushort> &Pk, const std::vector<byte> &Seed)
{
	ToBytes(R, Pk);
	Utility::MemUtils::Copy(Seed, 0, R, POLY_BYTES, SEED_BYTES);
}

void FFTQ40961N1024::EncodeB(std::vector<byte> &R, const std::vector<ushort> &B, const std::vector<ushort> &C)
{
	ToBytes(R, B);

	for (size_t i = 0; i < N / 4; i++)
		R[POLY_BYTES + i] = C[4 * i] | (C[4 * i + 1] << 2) | (C[4 * i + 2] << 4) | (C[4 * i + 3] << 6);
}

void FFTQ40961N1024::GenA(std::vector<ushort> &A, const std::vector<byte> &Seed, bool Parallel)
{
	PolyUniform(A, Seed, Parallel);
}

void FFTQ40961N1024::KeyGen(std::vector<byte> &Send, std::vector<ushort> &Sk, Prng::IPrng* Rng, bool Parallel)
{
	std::vector<ushort> a(N);
	std::vector<ushort> e(N);
	std::vector<ushort> r(N);
	std::vector<ushort> pk(N);
	std::vector<byte> seed(SEED_BYTES);
	std::vector<byte> buf1(4 * N);
	std::vector<byte> buf2(4 * N);

	Rng->GetBytes(buf1);
	Rng->GetBytes(buf2);
	Rng->GetBytes(seed);

	if (Parallel)
	{
		auto fut1 = std::async(std::launch::async, [&a, &seed, Parallel]()
		{
			GenA(a, seed, Parallel);
		});
		auto fut2 = std::async(std::launch::async, [&Sk, &buf1]()
		{
			PolyGetNoise(Sk, buf1);
			PolyNTT(Sk);
		});
		auto fut3 = std::async(std::launch::async, [&e, &buf2]()
		{
			PolyGetNoise(e, buf2);
			PolyNTT(e);
		});

		fut1.get();
		fut2.get();
		fut3.get();
	}
	else
	{
		GenA(a, seed, Parallel);

		PolyGetNoise(Sk, buf1);
		PolyNTT(Sk);

		PolyGetNoise(e, buf2);
		PolyNTT(e);
	}

	PolyPointwise(r, Sk, a);
	PolyAdd(pk, e, r);
	EncodeA(Send, pk, seed);
}

void FFTQ40961N1024::SharedA(std::vector<byte> &SharedKey, const std::vector<ushort> &Sk, const std::vector<byte> &Received, Digest::IDigest* Digest)
{
	std::vector<ushort> v(N);
	std::vector<ushort> bp(N);
	std::vector<ushort> c(N);

	DecodeB(bp, c, Received);
	PolyPointwise(v, Sk, bp);
	InvNTT(v);
	Rec(SharedKey, v, c);

	Digest->Update(SharedKey, 0, SharedKey.size());
	Digest->Finalize(SharedKey, 0);
}

void FFTQ40961N1024::SharedB(std::vector<byte> &SharedKey, std::vector<byte> &Send, const std::vector<byte> &Received, Prng::IPrng *Rng, Digest::IDigest* Digest, bool Parallel)
{
	std::vector<ushort> sp(N);
	std::vector<ushort> ep(N);
	std::vector<ushort> v(N);
	std::vector<ushort> a(N);
	std::vector<ushort> pka(N);
	std::vector<ushort> c(N);
	std::vector<ushort> epp(N);
	std::vector<ushort> bp(N);
	std::vector<ushort> tbp(N);
	std::vector<byte> seed(SEED_BYTES);
	std::vector<byte> buf1(4 * N);
	std::vector<byte> buf2(4 * N);

	DecodeA(pka, seed, Received);
	Rng->GetBytes(buf1);
	Rng->GetBytes(buf2);

	if (Parallel)
	{
		auto fut1 = std::async(std::launch::async, [&a, &seed, Parallel]()
		{
			GenA(a, seed, Parallel);
		});
		auto fut2 = std::async(std::launch::async, [&sp, &buf1]()
		{
			PolyGetNoise(sp, buf1);
			PolyNTT(sp);
		});
		auto fut3 = std::async(std::launch::async, [&ep, &buf2]()
		{
			PolyGetNoise(ep, buf2);
			PolyNTT(ep);
		});

		fut1.get();
		fut2.get();
		fut3.get();
	}
	else
	{
		GenA(a, seed, Parallel);

		PolyGetNoise(sp, buf1);
		PolyNTT(sp);

		PolyGetNoise(ep, buf2);
		PolyNTT(ep);
	}

	PolyPointwise(bp, a, sp);
	PolyAdd(tbp, bp, ep);

	PolyPointwise(v, pka, sp);
	InvNTT(v);
	Rng->GetBytes(buf1);
	PolyGetNoise(epp, buf1);
	PolyAdd(v, v, epp);

	Rng->GetBytes(seed);
	HelpRec(c, v, seed);
	EncodeB(Send, tbp, c);
	Rec(SharedKey, v, c);

	Digest->Update(SharedKey, 0, SharedKey.size());
	Digest->Finalize(SharedKey, 0);
}

//~~~Private Functions~~~//

ushort FFTQ40961N1024::BarrettReduce(ushort A)
{
	uint u = ((uint)A * 5) >> 16;
	u *= Q;
	A -= u;

	return A;
}

void FFTQ40961N1024::FromBytes(std::vector<ushort> &R, const std::vector<byte> &A)
{
	for (size_t i = 0; i < R.size() / 4; ++i)
	{
		R[4 * i + 0] = A[7 * i + 0] | (((ushort)A[7 * i + 1] & 0x3f) << 8);
		R[4 * i + 1] = (A[7 * i + 1] >> 6) | (((ushort)A[7 * i + 2]) << 2) | (((ushort)A[7 * i + 3] & 0x0f) << 10);
		R[4 * i + 2] = (A[7 * i + 3] >> 4) | (((ushort)A[7 * i + 4]) << 4) | (((ushort)A[7 * i + 5] & 0x03) << 12);
		R[4 * i + 3] = (A[7 * i + 5] >> 2) | (((ushort)A[7 * i + 6]) << 6);
	}
}

void FFTQ40961N1024::FwdNTT(std::vector<ushort> &A, const std::vector<ushort> &Omega)
{
	// TODO?: this could be vectorized, but would require some unrolling..
	int i, start, j, jTwiddle, distance;
	ushort temp, W;

	// GS_bo_to_no; omegas need to be in Montgomery domain
	for (i = 0; i < 10; i += 2)
	{
		// Even level
		distance = (1 << i);

		for (start = 0; start < distance; start++)
		{
			jTwiddle = 0;
			for (j = start; j < N - 1; j += 2 * distance)
			{
				W = Omega[jTwiddle++];
				temp = A[j];
				A[j] = (temp + A[j + distance]); // Omit reduction (be lazy)
				A[j + distance] = MontgomeryReduce(W * (((uint)temp + (3 * Q)) - A[j + distance]));
			}
		}

		// Odd level
		distance <<= 1;
		for (start = 0; start < distance; start++)
		{
			jTwiddle = 0;
			for (j = start; j < N - 1; j += 2 * distance)
			{
				W = Omega[jTwiddle++];
				temp = A[j];
				A[j] = BarrettReduce((temp + A[j + distance]));
				A[j + distance] = MontgomeryReduce(W * (((uint)temp + (3 * Q)) - A[j + distance]));
			}
		}
	}
	}

void FFTQ40961N1024::HelpRec(std::vector<ushort> &C, const std::vector<ushort> &V, std::vector<byte> &Random)
{
#if defined(__AVX512__)
	PFMQ40961N1024::HelpRec<Numeric::UInt512>(C, V, Random, Q);
#elif defined(__AVX2__)
	PFMQ40961N1024::HelpRec<Numeric::UInt256>(C, V, Random, Q);
#elif defined(__AVX__)
	PFMQ40961N1024::HelpRec<Numeric::UInt128>(C, V, Random, Q);
#else
	PFMQ40961N1024::HelpRec<int>(C, V, Random, Q);
#endif
}

void FFTQ40961N1024::InvNTT(std::vector<ushort> &R)
{
	Utility::PolyMath::BitReverse(R);
	FwdNTT(R, OmegasInvMontgomery);
	PolyMul(R, PsisInvMontgomery);
}

ushort FFTQ40961N1024::MontgomeryReduce(uint A)
{
	uint u = (A * QINV);
	u &= ((1 << RLOG) - 1);
	u *= Q;
	A = A + u;

	return A >> 18;
}

void FFTQ40961N1024::PolyAdd(std::vector<ushort> &R, const std::vector<ushort> &A, const std::vector<ushort> &B)
{
	for (size_t i = 0; i < R.size(); ++i)
		R[i] = BarrettReduce(A[i] + B[i]);
}

void FFTQ40961N1024::PolyGetNoise(std::vector<ushort> &R, std::vector<byte> &Random)
{
#if defined(__AVX512__)
	PFMQ40961N1024::GetNoise<Numeric::UInt512>(R, Random, Q);
#elif defined(__AVX2__)
	PFMQ40961N1024::GetNoise<Numeric::UInt256>(R, Random, Q);
#elif defined(__AVX__)
	PFMQ40961N1024::GetNoise<Numeric::UInt128>(R, Random, Q);
#else
	PFMQ40961N1024::GetNoise<uint>(R, Random, Q);
#endif
}

void FFTQ40961N1024::PolyMul(std::vector<ushort> &Poly, const std::vector<ushort> &Factors)
{
	for (size_t i = 0; i < Poly.size(); ++i)
		Poly[i] = MontgomeryReduce((Poly[i] * Factors[i]));
}

void FFTQ40961N1024::PolyNTT(std::vector<ushort> &R)
{
	PolyMul(R, PsisBitrevMontgomery);
	FwdNTT(R, OmegasMontgomery);
}

void FFTQ40961N1024::PolyPointwise(std::vector<ushort> &R, const std::vector<ushort> &A, const std::vector<ushort> &B)
{
	ushort t;

	for (size_t i = 0; i < N; i++)
	{
		// t is now in Montgomery domain
		t = MontgomeryReduce(3186 * B[i]); // TODO: ?
		// R[i] is back in normal domain
		R[i] = MontgomeryReduce(A[i] * t);
	}
}

void FFTQ40961N1024::PolyUniform(std::vector<ushort> &A, const std::vector<byte> &Seed, bool Parallel)
{
	size_t ctr = 0;
	size_t pos = 0;
	ushort val;
	size_t bufLen = 2 * N * sizeof(ushort);

	// AES128/CTR-BE generator
	Drbg::BCG eng(Enumeration::BlockCiphers::Rijndael);

	if (Parallel)
	{
		if (bufLen >= eng.ParallelProfile().ParallelMinimumSize())
		{
			bufLen -= (bufLen % eng.ParallelProfile().ParallelMinimumSize());
			eng.ParallelProfile().ParallelBlockSize() = bufLen;
		}
	}
	else
	{
		eng.ParallelProfile().IsParallel() = false;
	}

	eng.Initialize(Seed);
	std::vector<byte> buf(bufLen);
	eng.Generate(buf, 0, buf.size());

	while (ctr < N)
	{
		// 0x3fff/16393 - Specialized for q = 12889
		val = (buf[pos] | ((ushort)buf[pos + 1] << 8)) & 0x3fff; // TODO: ?
		if (val < Q)
			A[ctr++] = val;

		pos += 2;
		if (pos >= buf.size())
		{
			eng.Generate(buf, 0, buf.size());
			pos = 0;
		}
	}
}

void FFTQ40961N1024::Rec(std::vector<byte> &Key, const std::vector<ushort> &V, const std::vector<ushort> &C)
{
#if defined(__AVX512__)
	PFMQ40961N1024::Rec<Numeric::UInt512>(Key, V, C, Q);
#elif defined(__AVX2__)
	PFMQ40961N1024::Rec<Numeric::UInt256>(Key, V, C, Q);
#elif defined(__AVX__)
	PFMQ40961N1024::Rec<Numeric::UInt128>(Key, V, C, Q);
#else
	PFMQ40961N1024::Rec<int>(Key, V, C, Q);
#endif
}

void FFTQ40961N1024::ToBytes(std::vector<byte> &R, const std::vector<ushort> &Poly)
{
	ushort t0, t1, t2, t3, m;
	short c;

	for (size_t i = 0; i < Poly.size() / 4; i++)
	{
		// make sure that coefficients have only 14 bits
		t0 = BarrettReduce(Poly[4 * i + 0]);
		t1 = BarrettReduce(Poly[4 * i + 1]);
		t2 = BarrettReduce(Poly[4 * i + 2]);
		t3 = BarrettReduce(Poly[4 * i + 3]);

		// make sure that coefficients are in [0,q]
		m = t0 - Q;
		c = m;
		c >>= 15;
		t0 = m ^ ((t0 ^ m) & c);
		m = t1 - Q;
		c = m;
		c >>= 15;
		t1 = m ^ ((t1 ^ m) & c);
		m = t2 - Q;
		c = m;
		c >>= 15;
		t2 = m ^ ((t2 ^ m) & c);
		m = t3 - Q;
		c = m;
		c >>= 15;
		t3 = m ^ ((t3 ^ m) & c);

		R[7 * i + 0] = t0 & 0xff;
		R[7 * i + 1] = (t0 >> 8) | (t1 << 6);
		R[7 * i + 2] = (t1 >> 2);
		R[7 * i + 3] = (t1 >> 10) | (t2 << 4);
		R[7 * i + 4] = (t2 >> 4);
		R[7 * i + 5] = (t2 >> 12) | (t3 << 2);
		R[7 * i + 6] = (t3 >> 6);
	}
}

NAMESPACE_RINGLWEEND
