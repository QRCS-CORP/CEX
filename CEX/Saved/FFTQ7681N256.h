#ifndef _CEX_FFTQ12289_H
#define _CEX_FFTQ12289_H

#include "CexDomain.h"
#include "IntUtils.h"
#include "IPrng.h"
#include "MemUtils.h"
#include "PolyMath.h"
#include "RLWEKeyPair.h"
#include "RLWEPrivateKey.h"
#include "RLWEPublicKey.h"

NAMESPACE_RINGLWE

/// <summary>
/// 
/// </summary>
class FFTQ7681N256
{
private:

	static const int QBY2 = 3840; // Encipher
	static const int QBY4 = 1920;
	static const int QBY4_TIMES3 = 5760;
	static const int FWD_CONST1 = 5118; // FwdNTT
	static const int FWD_CONST2 = 1065; // FwdNTT
	static const int INVCONST1 = 2880; // InvNTT
	static const int INVCONST2 = 3383; // InvNTT
	static const int INVCONST3 = 2481; // InvNTT
	static const int SCALING = 7651; // InvNTT
	static const int HAMMING_TABLE_SIZE = 8; // KnuthYaoSingleNumber (small)
	static const int PMAT_MAX_COL = 109; // KnuthYaoSingleNumber (both)
	static const int KN_DISTANCE1_MASK = 7; // KnuthYaoSingleNumber (both)
	static const int KN_DISTANCE2_MASK = 15; // KnuthYaoSingleNumber (both)
	static const int NEW_RND_BOTTOM = 1; // KnuthYaoSingleNumber (both)
	static const int NEW_RND_LARGE = 32 - 9; // KnuthYaoSingleNumber (both)
	static const int NEW_RND_MID = 32 - 6; // KnuthYaoSingleNumber (both)

	Prng::IPrng* m_rndGenerator;
	ushort primrt_omega_table[8] = { 7680,4298,6468,849,2138,3654,1714,5118 };
	ushort primrt_inv_omega_table[7] = { 7680,3383,5756,1728,7584,6569,6601 };

	byte lut1[256] = // KnuthYaoSmallSingleNumber, KnuthYaoSingleNumber
	{
		3,4,1,2,2,8,6,1,3,0,1,9,2,5,5,4,3,4,1,1,2,7,6,11,3,0,1,4,2,4,5,2,3,4,1,2,2,8,6,0,3,0,1,7,2,5,
		5,12,3,4,1,1,2,7,6,9,3,0,1,3,2,4,5,19,3,4,1,2,2,8,6,1,3,0,1,9,2,5,5,0,3,4,1,1,2,7,6,10,3,0,1,
		4,2,4,5,17,3,4,1,2,2,8,6,0,3,0,1,7,2,5,5,8,3,4,1,1,2,7,6,6,3,0,1,3,2,4,5,21,3,4,1,2,2,8,6,1,
		3,0,1,9,2,5,5,4,3,4,1,1,2,7,6,11,3,0,1,4,2,4,5,16,3,4,1,2,2,8,6,0,3,0,1,7,2,5,5,10,3,4,1,1,2,
		7,6,9,3,0,1,3,2,4,5,20,3,4,1,2,2,8,6,1,3,0,1,9,2,5,5,0,3,4,1,1,2,7,6,10,3,0,1,4,2,4,5,18,3,4,
		1,2,2,8,6,0,3,0,1,7,2,5,5,7,3,4,1,1,2,7,6,6,3,0,1,3,2,4,5,22 
	};

	byte lut2[224] = // KnuthYaoSmallSingleNumber, KnuthYaoSingleNumber
	{
		13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,13,10,7,6,7,6,7,6,7,6,7,6,
		7,6,7,6,7,6,7,6,7,6,7,6,7,6,7,6,7,6,7,6,7,6,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,5,4,0,14,0,12,
		0,14,0,12,0,14,0,12,0,14,0,12,0,14,0,12,0,14,0,12,0,14,0,12,0,14,0,12,11,8,10,3,11,8,10,3,11,8,10,3,11,8,10,3,11,8,10,
		3,11,8,10,3,11,8,10,3,11,8,10,3,15,8,10,1,13,6,9,16,15,8,10,1,13,6,9,14,15,8,10,1,13,6,9,16,15,8,10,1,13,6,9,14,13,14,
		7,35,11,0,0,39,12,7,6,37,9,33,17,41,13,8,7,36,11,32,0,40,12,4,6,38,9,34,15,42 
	};

	uint pmat_cols_small_low2[96] = 
	{ 
		388697, 61898, 735029, 1827984, 90835, 3806095, 6691108, 2935960, 12945421, 28568525, 3210654, 48767208, 16573744, 125916607, 72293821, 194429505,
		151121284, 293488680, 409973800, 564029604, 831569570, 1557025050, 1665606779, 2457231006, 610122653, 3777752934, 2824776995, 1961497217, 3774769494, 2504584397, 375812815, 1179964722, 
		118525731, 3587291686, 933817073, 790620719, 666896237, 3054471770, 4025728199, 2311598504, 4001600372, 18287413, 431859238, 386648341, 2865711183, 2193001056, 879136978, 3755515272, 
		3027306685, 2105184250, 3767100803, 2422537634, 3546375370, 854226919, 1231318387, 2442556162, 3172751346, 3914369751, 2810198103, 2171449999, 3050259270, 698423236, 583750470, 3513591151, 
		3813875465,3101913469, 1109666353, 1237942877, 3992491021, 3153069412, 3875863403, 85509522, 1610972899, 3991997174, 884082284, 847230089, 633423750, 3943696550, 1797094335, 562330178, 
		731587459, 349044622, 3613052414, 2199722836, 4039471985, 3316520954, 402856197, 2120698321, 3953201766, 1934940481, 2746892350, 4232178428, 317690021, 3599046439, 2276896413, 2345760036 
	};

	uint pmat_cols_small_high2[96] = 
	{ 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0, 0, 512, 0, 0, 1536, 1536, 3072, 3584, 
		5632, 1024, 512, 12800, 11776, 19968, 2048, 8704, 33280, 10752, 55296, 81920, 126464, 2048, 233472, 167936,
		444416, 180224, 59904, 537600, 27136, 86528, 1435136, 831488, 460800, 2417152, 1606656, 898048, 829440, 5262848, 4853760, 6870528, 
		9718784, 14221824, 1589248, 22264832, 11726336, 23811072, 38793216, 9927168, 30364160, 11720192, 89426432, 13959680, 68004352, 223820288, 101885440, 75010048, 
		104050688, 297858048, 204479488, 519882240, 400561152, 728174592, 992103424, 573408768, 1519038976, 584817152, 348388864, 216653312, 3563907072, 1151563264, 2583073280, 2136579584 
	};

public:

	static const int N = 256;
	static const int Q = 7681;

	FFTQ7681N256(Prng::IPrng* Rng)
		:
		m_rndGenerator(Rng)
	{
	}

	void Decrypt(Key::Asymmetric::RLWEPrivateKey* PrivateKey, std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		std::vector<ushort> lmsg(N);
		std::vector<ushort> cpt1(N);
		std::vector<ushort> cpt2(N);

		size_t nLen = N * sizeof(ushort);
		Utility::MemUtils::Copy<byte>(Input, InOffset, cpt1, 0, nLen);
		Utility::MemUtils::Copy<byte>(Input, InOffset + nLen, cpt2, 0, nLen);
		Decipher(cpt1, cpt2, PrivateKey->C());
		QDecode(cpt1);
		ArrangeFinal(cpt1, lmsg);
		std::vector<byte> dec = Decode(lmsg);
		Utility::MemUtils::Copy<byte>(dec, 0, Output, OutOffset, dec.size());
	}

	void Encrypt(Key::Asymmetric::RLWEPublicKey* PublicKey, std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		std::vector<ushort> lmsg(N);
		std::vector<ushort> cpt1(N);
		std::vector<ushort> cpt2(N);

		// bit encoding
		lmsg = Encode(Input);
		// reverse msg
		BitReverse(lmsg);

		size_t pLen = PublicKey->P().size() / 2;
		std::vector<ushort> pubA(pLen / sizeof(ushort));
		std::vector<ushort> pubP(pLen / sizeof(ushort));
		Utility::MemUtils::Copy<byte>(PublicKey->P(), 0, pubA, 0, pLen);
		Utility::MemUtils::Copy<byte>(PublicKey->P(), pLen, pubP, 0, pLen);

		// pub a + p, message m, ciphertest c1 + c2
		Encipher(pubA, cpt1, cpt2, lmsg, pubP);
		Utility::MemUtils::Copy<ushort>(cpt1, 0, Output, OutOffset, cpt1.size() * sizeof(ushort));
		Utility::MemUtils::Copy<ushort>(cpt2, 0, Output, OutOffset + cpt2.size() * sizeof(ushort), cpt2.size() * sizeof(ushort));
	}

	Key::Asymmetric::RLWEKeyPair* Generate()
	{
		std::vector<ushort> pubA(N);
		std::vector<ushort> pubP(N);
		std::vector<ushort> priR2(N);
		KeyGen(pubA, pubP, priR2);

		size_t nLen = N * sizeof(ushort);
		std::vector<byte> p(nLen * 2);
		Utility::IntUtils::LeToBlock<ushort>(pubA, 0, p, 0, nLen);
		Utility::IntUtils::LeToBlock<ushort>(pubP, 0, p, nLen, nLen);
		Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(N, Q, p);
		Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(N, Q, priR2);

		return new Key::Asymmetric::RLWEKeyPair(sk, pk, std::vector<byte>(0));
	}

private:

	void ArrangeFinal(std::vector<ushort> &Input, std::vector<ushort> &Output)
	{
		const size_t HN = N / 2;

		for (size_t i = 0; i < HN; i += 2)
		{
			Output[i] = Input[2 * i];
			Output[i + 1] = Input[2 * (i + 1)];
		}

		for (size_t i = 0; i < HN; i += 2)
		{
			Output[i + HN] = Input[2 * i + 1];
			Output[i + 1 + HN] = Input[2 * (i + 1) + 1];
		}
	}

	void BitReverse(std::vector<ushort> &A)
	{
		uint bit1, bit2, bit3, bit4, bit5, bit6, bit7, bit8;
		uint q1, r1, q2, r2;
		ushort swpidx, temp;

		for (uint i = 0; i < N; ++i)
		{
			bit1 = i % 2;
			bit2 = (i >> 1) % 2;
			bit3 = (i >> 2) % 2;
			bit4 = (i >> 3) % 2;
			bit5 = (i >> 4) % 2;
			bit6 = (i >> 5) % 2;
			bit7 = (i >> 6) % 2;
			bit8 = (i >> 7) % 2;

			//swpidx = bit1 * 256 + bit2 * 128 + bit3 * 64 + bit4 * 32 + bit5 * 16 + bit6 * 8 + bit7 * 4 + bit8 * 2 + (i >> 8) % 2;
			//swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + bit8;
			swpidx = bit1 * (N >> 1) + bit2 * (N >> 2) + bit3 * (N >> 3) + bit4 * (N >> 4) + bit5 * (N >> 5) + bit6 * (N >> 6) + bit7 * (N >> 7) + bit8 + (i >> 8) % 2;

			q1 = i / 2;
			r1 = i % 2;
			q2 = swpidx / 2;
			r2 = swpidx % 2;

			if (swpidx > i)
			{
				if (r2 == 0)
				{
					temp = A[2 * q2];
					if (r1 == 0)
					{
						A[2 * q2] = A[2 * q1];
						A[2 * q1] = temp;
					}
					else
					{
						A[2 * q2] = A[2 * q1 + 1];
						A[2 * q1 + 1] = temp;
					}
				}
				else
				{
					temp = A[2 * q2 + 1];
					if (r1 == 0)
					{
						A[2 * q2 + 1] = A[2 * q1];
						A[2 * q1] = temp;
					}
					else
					{
						A[2 * q2 + 1] = A[2 * q1 + 1];
						A[2 * q1 + 1] = temp;
					}
				}
			}
		}
	}

	void Decipher(std::vector<ushort> &C1, std::vector<ushort> &C2, const std::vector<ushort> &R2)
	{
		// c1 <-- c1*r2
		PolyMath::Mul(C1, C1, R2, Q);
		// c1 <-- c1*r2 + c2
		PolyMath::Add(C1, C1, C2, Q);

		InvNTT(C1);
	}

	std::vector<byte> Decode(std::vector<ushort> &A)
	{
		std::vector<byte> dec(A.size() / 8);

		for (size_t i = 0, j = 0; i < dec.size(); ++i, j += 8)
		{
			dec[i] = (byte)(
				(A[j]) << 7 |
				(A[j + 1]) << 6 |
				(A[j + 2]) << 5 |
				(A[j + 3]) << 4 |
				(A[j + 4]) << 3 |
				(A[j + 5]) << 2 |
				(A[j + 6]) << 1 |
				A[j + 7]);

		}

		return dec;
	}

	void Encipher(std::vector<ushort> &A, std::vector<ushort> &C1, std::vector<ushort> &C2, std::vector<ushort> &Message, std::vector<ushort> &P)
	{
		std::vector<ushort> e1(N);
		std::vector<ushort> e2(N);
		std::vector<ushort> e3(N);
		std::vector<ushort> encM(N);

		// encode message
		for (size_t i = 0; i < N; ++i) 
			encM[i] = Message[i] * QBY2;

		KnuthYao(e1);
		KnuthYao(e2);
		KnuthYao(e3);
		// e3 <-- e3 + m
		PolyMath::Add(e3, e3, encM, Q);

		FwdNTT(e1);
		FwdNTT(e2);
		FwdNTT(e3);

		// m <-- a*e1
		// c1 <-- a*e1
		PolyMath::Mul(C1, A, e1, Q);
		// c1 <-- e2 + a*e1(tmp_m);
		PolyMath::Add(C1, e2, C1, Q);
		// c2 <-- p*e1
		PolyMath::Mul(C2, P, e1, Q);
		 // c2<-- e3 + p*e1
		PolyMath::Add(C2, e3, C2, Q);

		Rearrange(C1);
		Rearrange(C2);
	}

	std::vector<ushort> Encode(std::vector<byte> &A)
	{
		std::vector<ushort> enc(A.size() * 8);

		for (size_t i = 0, j = 0; i < A.size(); ++i, j += 8)
		{
			enc[j] = (ushort)A[i] >> 7 & 1;
			enc[j + 1] = (ushort)A[i] >> 6 & 1;
			enc[j + 2] = (ushort)A[i] >> 5 & 1;
			enc[j + 3] = (ushort)A[i] >> 4 & 1;
			enc[j + 4] = (ushort)A[i] >> 3 & 1;
			enc[j + 5] = (ushort)A[i] >> 2 & 1;
			enc[j + 6] = (ushort)A[i] >> 1 & 1;
			enc[j + 7] = (ushort)A[i] & 1;
		}

		return enc;
	}

	void FwdNTT(std::vector<ushort> &A)
	{
		uint u1, t1, u2, t2;
		uint primrt, omega;
		size_t i = 0;

		for (size_t mi = 2; mi <= N / 2; mi = 2 * mi)
		{
			primrt = primrt_omega_table[i];
			omega = primrt_omega_table[i + 1];
			++i;

			for (size_t j = 0; j < mi; j += 2)
			{
				for (size_t k = 0; k < N; k = k + 2 * mi)
				{
					u1 = A[j + k];
					t1 = PolyMath::Mod(omega * A[j + k + 1], Q);
					u2 = A[j + k + mi];
					t2 = PolyMath::Mod(omega * A[j + k + mi + 1], Q);
					A[j + k] = PolyMath::Mod(u1 + t1, Q);
					A[j + k + 1] = PolyMath::Mod(u2 + t2, Q);
					A[j + k + mi] = PolyMath::Mod(u1 - t1, Q);
					A[j + k + mi + 1] = PolyMath::Mod(u2 - t2, Q);
				}

				omega = omega * primrt;
				omega = PolyMath::Mod(omega, Q);
			}
		}

		primrt = FWD_CONST1;
		omega = FWD_CONST2;
		for (size_t j = 0; j < N / 2; ++j)
		{
			t1 = omega * A[2 * j + 1];
			t1 = PolyMath::Mod(t1, Q);
			u1 = A[2 * j];
			A[2 * j] = PolyMath::Mod(u1 + t1, Q);
			A[2 * j + 1] = PolyMath::Mod(u1 - t1, Q);

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, Q);
		}
	}

	void GenA(std::vector<ushort> &A)
	{
		int rnd;

		for (size_t i = 0; i < N / 2; ++i) 
		{
			rnd = (int)GetRand();
			A[2 * i] = PolyMath::Mod(rnd & 0xffff, Q);
			A[2 * i + 1] = PolyMath::Mod((rnd >> 16), Q);
		}

		FwdNTT(A);
	}

	void GenR1(std::vector<ushort> &R1)
	{
		KnuthYao(R1);
		FwdNTT(R1);
	}

	void GenR2(std::vector<ushort> &R2)
	{
		ushort rnd, bit, sign;

		for (size_t i = 0; i < N;) 
		{
			rnd = (ushort)GetRand();

			for (size_t j = 0; j < 16; j++)
			{
				bit = rnd & 1;
				sign = (rnd >> 1) & 1;

				if (sign == 1 && bit == 1)
					bit = (Q - 1);

				R2[i] = bit;
				i++;
				rnd = rnd >> 2;
			}
		}

		FwdNTT(R2);
	}

	uint GetRand()
	{
		uint rnd = m_rndGenerator->Next();
		// set the least significant bit
		rnd |= 0x80000000;

		return rnd;
	}

	void InvNTT(std::vector<ushort> &A)
	{
		uint u1, t1, u2, t2;
		uint omega;
		uint primrt = 0;
		size_t sm = 2;

		for (size_t i = 0; i < 7; ++i)
		{
			primrt = primrt_inv_omega_table[i];
			omega = 1;
			for (size_t j = 0; j < sm / 2; ++j)
			{
				for (size_t k = 0; k < N / 2; k = k + sm)
				{
					t1 = omega * A[2 * (k + j) + 1];
					t1 = PolyMath::Mod(t1, Q);
					u1 = A[2 * (k + j)];
					t2 = omega * A[2 * (k + j + sm / 2) + 1];
					t2 = PolyMath::Mod(t2, Q);
					u2 = A[2 * (k + j + sm / 2)];

					A[2 * (k + j)] = PolyMath::Mod(u1 + t1, Q);
					A[2 * (k + j + sm / 2)] = PolyMath::Mod(u1 - t1, Q);
					A[2 * (k + j) + 1] = PolyMath::Mod(u2 + t2, Q);
					A[2 * (k + j + sm / 2) + 1] = PolyMath::Mod(u2 - t2, Q);
				}
				omega = omega * primrt;
				omega = PolyMath::Mod(omega, Q);
			}
			sm *= 2;
		}

		primrt = INVCONST1;
		omega = 1;
		for (size_t j = 0; j < N;)
		{
			u1 = A[j];
			++j;
			t1 = omega * A[j];
			t1 = PolyMath::Mod(t1, Q);
			A[j - 1] = PolyMath::Mod(u1 + t1, Q);
			A[j] = PolyMath::Mod(u1 - t1, Q);
			++j;

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, Q);
		}

		uint omega2 = INVCONST2;
		primrt = INVCONST3;
		omega = 1;
		for (size_t j = 0; j < N;)
		{
			A[j] = PolyMath::Mod(omega * A[j], Q);
			A[j] = PolyMath::Mod(A[j] * SCALING, Q);
			++j;
			A[j] = PolyMath::Mod(omega2 * A[j], Q);
			A[j] = PolyMath::Mod(A[j] * SCALING, Q);
			++j;

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, Q);
			omega2 = omega2 * primrt;
			omega2 = PolyMath::Mod(omega2, Q);
		}
	}

	void KeyGen(std::vector<ushort> &A, std::vector<ushort> &P, std::vector<ushort> &R2)
	{
		GenA(A);
		GenR1(P);
		GenR2(R2);

		std::vector<ushort> tmpA(N);
		// a = a*r2
		PolyMath::Mul(tmpA, A, R2, Q);
		// p = p-a*r2
		PolyMath::Sub(P, P, tmpA, Q);
		Rearrange(R2);
	}

	void KnuthYao(std::vector<ushort> &A)
	{
		uint32_t rnd = GetRand();

		for (size_t i = 0; i < N / 2; i++) 
		{
			A[2 * i + 1] = KnuthYaoSingleNumber(rnd);
			A[2 * i] = KnuthYaoSingleNumber(rnd);
		}
	}

	uint32_t KnuthYaoSingleNumber(uint32_t &Rand)
	{
		int dist, row, column, index, sample, smsb;
		uint high, low;

		index = Rand & 0xff;
		Rand >>= 8;
		sample = lut1[index]; // M elements in lut1
		smsb = sample & 16;

		if (smsb == 0) // lookup was successful
		{
			if (Rand == NEW_RND_BOTTOM)
				Rand = GetRand();

			sample = sample & 0xf;
			if (Rand & 1)
				sample = (Q - sample); // 9th bit in Rand is the sign

			Rand >>= 1;
			// We know that in the next call we will need 8 bits!
			if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
				Rand = GetRand();

			return sample;
		}
		else 
		{
			if (PolyMath::Clz(Rand) > (NEW_RND_MID)) 
				Rand = GetRand();

			dist = sample & KN_DISTANCE1_MASK;
			index = (Rand & 0x1f) + 32 * dist;
			Rand >>= 5;
			if (Rand == NEW_RND_BOTTOM)
				Rand = GetRand();

			sample = lut2[index]; // 224 elements in lut2
			smsb = sample & 32;
			if (smsb == 0) // lookup was successful
			{
				sample = sample & 31;
				if (Rand & 1)
					sample = (Q - sample); // 9th bit in Rand is the sign

				Rand >>= 1;
				if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
					Rand = GetRand();

				return sample;
			}
			else 
			{
				// Real knuth-yao
				dist = sample & KN_DISTANCE2_MASK;

				// NB: Need to update PMAT_MAX_COL!
				for (column = 0; column < PMAT_MAX_COL; column++) 
				{
					dist = dist * 2 + (Rand & 1);
					Rand >>= 1;
					if (Rand == NEW_RND_BOTTOM)
						Rand = GetRand();

					low = pmat_cols_small_low2[column];

					// Assume that HAMMING_TABLE_SIZE<7 and therefore column<7
					// pmat_cols_small_high only contains a value when column=8 (Real column 20)
					// This means that it must be inside the high part
					// for(row=(54-32); row>=0; row--)
					for (row = (31); row >= 0; row--) 
					{
						dist = dist - (low >> 31); // subtract the most significant bit
						low = low << 1;
						if (dist == -1) 
						{
							if (Rand & 1)
								sample = (Q - row);
							else
								sample = row;

							Rand >>= 1;
							if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
								Rand = GetRand();

							return sample;
						}
					}
				}

				for (column = HAMMING_TABLE_SIZE; (column < (109 - 13)); column++) 
				{
					high = pmat_cols_small_high2[column];
					low = pmat_cols_small_low2[column];
					dist = dist * 2 + (Rand & 1);
					Rand >>= 1;

					if (Rand == NEW_RND_BOTTOM)
						Rand = GetRand();// GR?

					for (row = 54; row >= 32; row--) 
					{
						dist = dist - (high >> 31); // subtract the most significant bit
						high = high << 1;

						if (dist == -1) 
						{
							if (Rand & 1)
								sample = (Q - row);
							else
								sample = row;

							Rand >>= 1;
							if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
								Rand = GetRand();// GR?

							return sample;
						}
					}

					for (row = (31); row >= 0; row--) 
					{
						dist = dist - (low >> 31); // subtract the most significant bit
						low = low << 1;
						if (dist == -1) 
						{
							if (Rand & 1)
								sample = (Q - row);
							else
								sample = row;

							Rand >>= 1;
							if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
								Rand = GetRand();// GR?

							return sample;
						}
					}
				}
			}
		}

		return -1;
	}

	void QDecode(std::vector<ushort> &C1)
	{
		for (size_t i = 0; i < N; ++i)
		{
			if ((C1[i] > QBY4) && (C1[i] < QBY4_TIMES3))
				C1[i] = 1;
			else
				C1[i] = 0;
		}
	}

	void Rearrange(std::vector<ushort> &A)
	{
		uint bit1, bit2, bit3, bit4, bit5, bit6, bit7;
		uint swpidx;
		ushort u1, u2;

		for (uint i = 1; i < N / 2; ++i)
		{
			bit1 = i % 2;
			bit2 = (i >> 1) % 2;
			bit3 = (i >> 2) % 2;
			bit4 = (i >> 3) % 2;
			bit5 = (i >> 4) % 2;
			bit6 = (i >> 5) % 2;
			bit7 = (i >> 6) % 2;

			//swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + (i >> 7) % 2;
			//swpidx = bit1 * 64 + bit2 * 32 + bit3 * 16 + bit4 * 8 + bit5 * 4 + bit6 * 2 + bit7;
			swpidx = bit1 * (N >> 2) + bit2 * (N >> 3) + bit3 * (N >> 4) + bit4 * (N >> 5) + bit5 * (N >> 6) + bit6 * (N >> 7) + ((N != 256) ? bit7 * 2 + (i >> 7) % 2 : bit7);

			if (swpidx > i)
			{
				u1 = A[2 * i];
				u2 = A[2 * i + 1];
				A[2 * i] = A[2 * swpidx];
				A[2 * i + 1] = A[2 * swpidx + 1];
				A[2 * swpidx] = u1;
				A[2 * swpidx + 1] = u2;
			}
		}
	}

};

NAMESPACE_RINGLWEEND
#endif