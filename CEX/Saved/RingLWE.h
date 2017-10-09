#ifndef _CEX_RINGLWE_H
#define _CEX_RINGLWE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "PrngFromName.h"
#include "RLWEKeyPair.h"
#include "RLWEParams.h"
#include "RLWEPrivateKey.h"
#include "RLWEPublicKey.h"
//#include "FFTQ7681N256.h"
#include "NTTQ7681N256.h"
#include "NTTQ12289N512.h"
#include "RLWEParamSet.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PolyMath.h"

NAMESPACE_RINGLWE

using Enumeration::RLWEParams;
using Key::Asymmetric::RLWEPrivateKey;
using Key::Asymmetric::RLWEPublicKey;

class RingLWE : public IAsymmetricCipher
{
private:
	static const int NEW_RND_BOTTOM = 1;
	static const int NEW_RND_LARGE = 32 - 9;
	static const int NEW_RND_MID = 32 - 6;

	static const std::string CLASS_NAME;
	IPrng* m_rndGenerator;
	bool m_isEncryption;
	bool m_isInitialized;
	size_t m_maxMessageSize;
	RLWEParams m_paramSetType;
	IAsymmetricKeyPair* m_keyPair;
	RLWEParamSet m_paramSet;
	RLWEPrivateKey* m_privateKey;
	RLWEPublicKey* m_publicKey;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	RingLWE(RLWEParams ParamSet = RLWEParams::N512Q12289, Prngs PrngType = Prngs::CMR)
		:
		m_isEncryption(false),
		m_isInitialized(false),
		m_maxMessageSize(0),
		m_paramSet(GetParams(ParamSet)),
		m_paramSetType(ParamSet),
		m_rndGenerator(Helper::PrngFromName::GetInstance(PrngType))
	{
	}

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	RingLWE(RLWEParams ParamSet, IPrng* Prng)
		:
		m_isEncryption(false),
		m_isInitialized(false),
		m_maxMessageSize(0),
		m_paramSet(GetParams(ParamSet)),
		m_paramSetType(ParamSet),
		m_rndGenerator(Prng)
	{
	}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~RingLWE() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The cipher type-name
	/// </summary>
	virtual const AsymmetricEngines Enumeral()
	{
		return AsymmetricEngines::RingLWE;
	}

	/// <summary>
	/// Get: The cipher is initialized for encryption
	/// </summary>
	virtual const bool IsEncryption()
	{
		return m_isEncryption;
	}

	/// <summary>
	/// Get: The cipher has been initialized with a key
	/// </summary>
	virtual const bool IsInitialized()
	{
		return m_isInitialized;
	}

	/// <summary>
	/// Get: The maximum number of bytes the cipher can encrypt or decrypt
	/// </summary>
	virtual const size_t MaxMessageSize()
	{
		return m_maxMessageSize;
	}

	/// <summary>
	/// Get: The ciphers name
	/// </summary>
	virtual const std::string Name()
	{
		return CLASS_NAME;
	}

	/// <summary>
	/// Get: 
	/// </summary>
	const size_t Paramaters()
	{
		return m_maxMessageSize;
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the cipher for encryption or decryption
	/// </summary>
	/// 
	/// <param name="Encryption">Initialize the cipher for encryption or decryption</param>
	/// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the Public (encrypt) and/or Private (decryption) key</param>
	virtual void Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair)
	{
		if (Encryption)
			m_publicKey = (RLWEPublicKey*)KeyPair->PublicKey();
		else
			m_privateKey = (RLWEPrivateKey*)KeyPair->PrivateKey();

		m_isEncryption = Encryption;
		m_isInitialized = true;
	}

	/// <summary>
	/// Decrypt an encrypted cipher-text
	/// </summary>
	/// 
	/// <param name="Input">The input cipher-text</param>
	/// <param name="InOffset">The starting position within the input array</param>
	/// <param name="Output">The output plain-text</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	void Decrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		std::vector<ushort> lmsg(m_paramSet.N);
		std::vector<ushort> cpt1(m_paramSet.N);
		std::vector<ushort> cpt2(m_paramSet.N);
		RLWEPrivateKey* priK = (RLWEPrivateKey*)m_privateKey;

		size_t nLen = m_paramSet.N * sizeof(ushort);
		Utility::MemUtils::Copy<byte>(Input, InOffset, cpt1, 0, nLen);
		Utility::MemUtils::Copy<byte>(Input, InOffset + nLen, cpt2, 0, nLen);
		Decipher(cpt1, cpt2, priK->C());
		QDecode(cpt1);
		ArrangeFinal(cpt1, lmsg);
		std::vector<byte> dec = Decode(lmsg);
		Utility::MemUtils::Copy<byte>(dec, 0, Output, OutOffset, dec.size());
	}

	/// <summary>
	/// Encrypt a plain-text message
	/// </summary>
	/// 
	/// <param name="Input">The input plain-text</param>
	/// <param name="InOffset">The starting position within the input array</param>
	/// <param name="Output">The output cipher-text</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	void Encrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		std::vector<ushort> lmsg(m_paramSet.N);
		std::vector<ushort> cpt1(m_paramSet.N);
		std::vector<ushort> cpt2(m_paramSet.N);
		RLWEPublicKey* pubK = (RLWEPublicKey*)m_publicKey;

		// bit encoding
		lmsg = Encode(Input);
		// reverse msg
		BitReverse(lmsg);

		size_t pLen = pubK->P().size() / 2;
		std::vector<ushort> pubA(pLen / sizeof(ushort));
		std::vector<ushort> pubP(pLen / sizeof(ushort));
		Utility::MemUtils::Copy<byte>(pubK->P(), 0, pubA, 0, pLen);
		Utility::MemUtils::Copy<byte>(pubK->P(), pLen, pubP, 0, pLen);

		// pub a + p, message m, ciphertest c1 + c2
		Encipher(pubA, cpt1, cpt2, lmsg, pubP);
		Utility::MemUtils::Copy<ushort>(cpt1, 0, Output, OutOffset, cpt1.size() * sizeof(ushort));
		Utility::MemUtils::Copy<ushort>(cpt2, 0, Output, OutOffset + cpt2.size() * sizeof(ushort), cpt2.size() * sizeof(ushort));
	}

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	IAsymmetricKeyPair* Generate()
	{
		std::vector<ushort> pubA(m_paramSet.N);
		std::vector<ushort> pubP(m_paramSet.N);
		std::vector<ushort> priR2(m_paramSet.N);
		KeyGen(pubA, pubP, priR2);

		size_t nLen = m_paramSet.N * sizeof(ushort);
		std::vector<byte> p(nLen * 2);
		Utility::IntUtils::LeToBlock<ushort>(pubA, 0, p, 0, nLen);
		Utility::IntUtils::LeToBlock<ushort>(pubP, 0, p, nLen, nLen);
		Key::Asymmetric::RLWEPublicKey* pk = new Key::Asymmetric::RLWEPublicKey(m_paramSet.N, m_paramSet.Q, p);
		Key::Asymmetric::RLWEPrivateKey* sk = new Key::Asymmetric::RLWEPrivateKey(m_paramSet.N, m_paramSet.Q, priR2);

		return new Key::Asymmetric::RLWEKeyPair(sk, pk, std::vector<byte>(0));
	}

private:

	RLWEParamSet GetParams(RLWEParams ParamSet)
	{
		RLWEParamSet params;

		switch (ParamSet)
		{
			case RLWEParams::N256Q768:
			{
				NTTQ7681N256 tmp;
				params.FWD_CONST1 = tmp.FWD_CONST1;
				params.FWD_CONST2 = tmp.FWD_CONST2;
				params.HAMMING_TABLE_SIZE = tmp.HAMMING_TABLE_SIZE;
				params.INVCONST1 = tmp.INVCONST1;
				params.INVCONST2 = tmp.INVCONST2;
				params.INVCONST3 = tmp.INVCONST3;
				params.KN_DISTANCE1_MASK = tmp.KN_DISTANCE1_MASK;
				params.KN_DISTANCE2_MASK = tmp.KN_DISTANCE2_MASK;
				params.Lut1 = tmp.Lut1;
				params.Lut2 = tmp.Lut2;
				params.N = tmp.N;
				params.PmatColsSmallHigh = tmp.PmatColsSmallHigh;
				params.PmatColsSmallLow = tmp.PmatColsSmallLow;
				params.PMAT_MAX_COL = tmp.PMAT_MAX_COL;
				params.PrimeRtInvOmegaTable = tmp.PrimeRtInvOmegaTable;
				params.PrimeRtOmegaTable = tmp.PrimeRtOmegaTable;
				params.Q = tmp.Q;
				params.QBY2 = tmp.QBY2;
				params.QBY4 = tmp.QBY4;
				params.QBY4_TIMES3 = tmp.QBY4_TIMES3;
				params.SCALING = tmp.SCALING;

				break;
			}
			case RLWEParams::N512Q12289:
			{
				NTTQ12289N512 tmp;
				params.FWD_CONST1 = tmp.FWD_CONST1;
				params.FWD_CONST2 = tmp.FWD_CONST2;
				params.HAMMING_TABLE_SIZE = tmp.HAMMING_TABLE_SIZE;
				params.INVCONST1 = tmp.INVCONST1;
				params.INVCONST2 = tmp.INVCONST2;
				params.INVCONST3 = tmp.INVCONST3;
				params.KN_DISTANCE1_MASK = tmp.KN_DISTANCE1_MASK;
				params.KN_DISTANCE2_MASK = tmp.KN_DISTANCE2_MASK;
				params.Lut1 = tmp.Lut1;
				params.Lut2 = tmp.Lut2;
				params.N = tmp.N;
				params.PmatColsSmallHigh = tmp.PmatColsSmallHigh;
				params.PmatColsSmallLow = tmp.PmatColsSmallLow;
				params.PMAT_MAX_COL = tmp.PMAT_MAX_COL;
				params.PrimeRtInvOmegaTable = tmp.PrimeRtInvOmegaTable;
				params.PrimeRtOmegaTable = tmp.PrimeRtOmegaTable;
				params.Q = tmp.Q;
				params.QBY2 = tmp.QBY2;
				params.QBY4 = tmp.QBY4;
				params.QBY4_TIMES3 = tmp.QBY4_TIMES3;
				params.SCALING = tmp.SCALING;

				break;
			}
		}

		return params;
	}

	void ArrangeFinal(std::vector<ushort> &Input, std::vector<ushort> &Output)
	{
		const size_t HN = m_paramSet.N / 2;

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
		const int N = m_paramSet.N;

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

			if (N == 256)
				swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + bit8;
			else
				swpidx = bit1 * 256 + bit2 * 128 + bit3 * 64 + bit4 * 32 + bit5 * 16 + bit6 * 8 + bit7 * 4 + bit8 * 2 + (i >> 8) % 2;
			//swpidx = bit1 * 256 + bit2 * 128 + bit3 * 64 + bit4 * 32 + bit5 * 16 + bit6 * 8 + bit7 * 4 + bit8 * 2 + (i >> 8) % 2;
			//swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + bit8;
			//swpidx = bit1 * (N >> 1) + bit2 * (N >> 2) + bit3 * (N >> 3) + bit4 * (N >> 4) + bit5 * (N >> 5) + bit6 * (N >> 6) + bit7 * (N >> 7) + bit8 + (i >> 8) % 2;

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
		PolyMath::Mul(C1, C1, R2, m_paramSet.Q);
		// c1 <-- c1*r2 + c2
		PolyMath::Add(C1, C1, C2, m_paramSet.Q);

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
		std::vector<ushort> e1(m_paramSet.N);
		std::vector<ushort> e2(m_paramSet.N);
		std::vector<ushort> e3(m_paramSet.N);
		std::vector<ushort> encM(m_paramSet.N);

		// encode message
		for (size_t i = 0; i < m_paramSet.N; ++i)
			encM[i] = Message[i] * m_paramSet.QBY2;

		KnuthYao(e1);
		KnuthYao(e2);
		KnuthYao(e3);
		// e3 <-- e3 + m
		PolyMath::Add(e3, e3, encM, m_paramSet.Q);

		FwdNTT(e1);
		FwdNTT(e2);
		FwdNTT(e3);

		// m <-- a*e1
		// c1 <-- a*e1
		PolyMath::Mul(C1, A, e1, m_paramSet.Q);
		// c1 <-- e2 + a*e1(tmp_m);
		PolyMath::Add(C1, e2, C1, m_paramSet.Q);
		// c2 <-- p*e1
		PolyMath::Mul(C2, P, e1, m_paramSet.Q);
		// c2<-- e3 + p*e1
		PolyMath::Add(C2, e3, C2, m_paramSet.Q);

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

		for (size_t mi = 2; mi <= m_paramSet.N / 2; mi = 2 * mi)
		{
			primrt = m_paramSet.PrimeRtOmegaTable[i];
			omega = m_paramSet.PrimeRtOmegaTable[i + 1];
			++i;

			for (size_t j = 0; j < mi; j += 2)
			{
				for (size_t k = 0; k < m_paramSet.N; k = k + 2 * mi)
				{
					u1 = A[j + k];
					t1 = PolyMath::Mod(omega * A[j + k + 1], m_paramSet.Q);
					u2 = A[j + k + mi];
					t2 = PolyMath::Mod(omega * A[j + k + mi + 1], m_paramSet.Q);
					A[j + k] = PolyMath::Mod(u1 + t1, m_paramSet.Q);
					A[j + k + 1] = PolyMath::Mod(u2 + t2, m_paramSet.Q);
					A[j + k + mi] = PolyMath::Mod(u1 - t1, m_paramSet.Q);
					A[j + k + mi + 1] = PolyMath::Mod(u2 - t2, m_paramSet.Q);
				}

				omega = omega * primrt;
				omega = PolyMath::Mod(omega, m_paramSet.Q);
			}
		}

		primrt = m_paramSet.FWD_CONST1;
		omega = m_paramSet.FWD_CONST2;
		for (size_t j = 0; j < m_paramSet.N / 2; ++j)
		{
			t1 = omega * A[2 * j + 1];
			t1 = PolyMath::Mod(t1, m_paramSet.Q);
			u1 = A[2 * j];
			A[2 * j] = PolyMath::Mod(u1 + t1, m_paramSet.Q);
			A[2 * j + 1] = PolyMath::Mod(u1 - t1, m_paramSet.Q);

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, m_paramSet.Q);
		}
	}

	void GenA(std::vector<ushort> &A)
	{
		int rnd;

		for (size_t i = 0; i < m_paramSet.N / 2; ++i)
		{
			rnd = (int)GetRand();
			A[2 * i] = PolyMath::Mod(rnd & 0xffff, m_paramSet.Q);
			A[2 * i + 1] = PolyMath::Mod((rnd >> 16), m_paramSet.Q);
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

		for (size_t i = 0; i < m_paramSet.N;)
		{
			rnd = (ushort)GetRand();

			for (size_t j = 0; j < 16; j++)
			{
				bit = rnd & 1;
				sign = (rnd >> 1) & 1;

				if (sign == 1 && bit == 1)
					bit = (m_paramSet.Q - 1);

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
			primrt = m_paramSet.PrimeRtInvOmegaTable[i];
			omega = 1;
			for (size_t j = 0; j < sm / 2; ++j)
			{
				for (size_t k = 0; k < m_paramSet.N / 2; k = k + sm)
				{
					t1 = omega * A[2 * (k + j) + 1];
					t1 = PolyMath::Mod(t1, m_paramSet.Q);
					u1 = A[2 * (k + j)];
					t2 = omega * A[2 * (k + j + sm / 2) + 1];
					t2 = PolyMath::Mod(t2, m_paramSet.Q);
					u2 = A[2 * (k + j + sm / 2)];

					A[2 * (k + j)] = PolyMath::Mod(u1 + t1, m_paramSet.Q);
					A[2 * (k + j + sm / 2)] = PolyMath::Mod(u1 - t1, m_paramSet.Q);
					A[2 * (k + j) + 1] = PolyMath::Mod(u2 + t2, m_paramSet.Q);
					A[2 * (k + j + sm / 2) + 1] = PolyMath::Mod(u2 - t2, m_paramSet.Q);
				}
				omega = omega * primrt;
				omega = PolyMath::Mod(omega, m_paramSet.Q);
			}
			sm *= 2;
		}

		primrt = m_paramSet.INVCONST1;
		omega = 1;
		for (size_t j = 0; j < m_paramSet.N;)
		{
			u1 = A[j];
			++j;
			t1 = omega * A[j];
			t1 = PolyMath::Mod(t1, m_paramSet.Q);
			A[j - 1] = PolyMath::Mod(u1 + t1, m_paramSet.Q);
			A[j] = PolyMath::Mod(u1 - t1, m_paramSet.Q);
			++j;

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, m_paramSet.Q);
		}

		uint omega2 = m_paramSet.INVCONST2;
		primrt = m_paramSet.INVCONST3;
		omega = 1;
		for (size_t j = 0; j < m_paramSet.N;)
		{
			A[j] = PolyMath::Mod(omega * A[j], m_paramSet.Q);
			A[j] = PolyMath::Mod(A[j] * m_paramSet.SCALING, m_paramSet.Q);
			++j;
			A[j] = PolyMath::Mod(omega2 * A[j], m_paramSet.Q);
			A[j] = PolyMath::Mod(A[j] * m_paramSet.SCALING, m_paramSet.Q);
			++j;

			omega = omega * primrt;
			omega = PolyMath::Mod(omega, m_paramSet.Q);
			omega2 = omega2 * primrt;
			omega2 = PolyMath::Mod(omega2, m_paramSet.Q);
		}
	}

	void KeyGen(std::vector<ushort> &A, std::vector<ushort> &P, std::vector<ushort> &R2)
	{
		GenA(A);
		GenR1(P);
		GenR2(R2);

		std::vector<ushort> tmpA(m_paramSet.N);
		// a = a*r2
		PolyMath::Mul(tmpA, A, R2, m_paramSet.Q);
		// p = p-a*r2
		PolyMath::Sub(P, P, tmpA, m_paramSet.Q);
		Rearrange(R2);
	}

	void KnuthYao(std::vector<ushort> &A)
	{
		uint32_t rnd = GetRand();

		for (size_t i = 0; i < m_paramSet.N / 2; i++)
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
		sample = m_paramSet.Lut1[index]; // M elements in lut1
		smsb = sample & 16;

		if (smsb == 0) // lookup was successful
		{
			if (Rand == NEW_RND_BOTTOM)
				Rand = GetRand();

			sample = sample & 0xf;
			if (Rand & 1)
				sample = (m_paramSet.Q - sample); // 9th bit in Rand is the sign

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

			dist = sample & m_paramSet.KN_DISTANCE1_MASK;
			index = (Rand & 0x1f) + 32 * dist;
			Rand >>= 5;
			if (Rand == NEW_RND_BOTTOM)
				Rand = GetRand();

			sample = m_paramSet.Lut2[index]; // 224 elements in lut2
			smsb = sample & 32;
			if (smsb == 0) // lookup was successful
			{
				sample = sample & 31;
				if (Rand & 1)
					sample = (m_paramSet.Q - sample); // 9th bit in Rand is the sign

				Rand >>= 1;
				if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
					Rand = GetRand();

				return sample;
			}
			else
			{
				// Real knuth-yao
				dist = sample & m_paramSet.KN_DISTANCE2_MASK;

				// NB: Need to update PMAT_MAX_COL!
				for (column = 0; column < m_paramSet.PMAT_MAX_COL; column++)
				{
					dist = dist * 2 + (Rand & 1);
					Rand >>= 1;
					if (Rand == NEW_RND_BOTTOM)
						Rand = GetRand();

					low = m_paramSet.PmatColsSmallLow[column];

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
								sample = (m_paramSet.Q - row);
							else
								sample = row;

							Rand >>= 1;
							if (PolyMath::Clz(Rand) > (NEW_RND_LARGE))
								Rand = GetRand();

							return sample;
						}
					}
				}

				for (column = m_paramSet.HAMMING_TABLE_SIZE; (column < (109 - 13)); column++)
				{
					high = m_paramSet.PmatColsSmallHigh[column];
					low = m_paramSet.PmatColsSmallLow[column];
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
								sample = (m_paramSet.Q - row);
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
								sample = (m_paramSet.Q - row);
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
		for (size_t i = 0; i < m_paramSet.N; ++i)
		{
			if ((C1[i] > m_paramSet.QBY4) && (C1[i] < m_paramSet.QBY4_TIMES3))
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
		const int N = m_paramSet.N;

		for (uint i = 1; i < N / 2; ++i)
		{
			bit1 = i % 2;
			bit2 = (i >> 1) % 2;
			bit3 = (i >> 2) % 2;
			bit4 = (i >> 3) % 2;
			bit5 = (i >> 4) % 2;
			bit6 = (i >> 5) % 2;
			bit7 = (i >> 6) % 2;

			if (N == 256)
				swpidx = bit1 * 64 + bit2 * 32 + bit3 * 16 + bit4 * 8 + bit5 * 4 + bit6 * 2 + bit7;
			else
				swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + (i >> 7) % 2;
			//swpidx = bit1 * 128 + bit2 * 64 + bit3 * 32 + bit4 * 16 + bit5 * 8 + bit6 * 4 + bit7 * 2 + (i >> 7) % 2;
			//swpidx = bit1 * 64 + bit2 * 32 + bit3 * 16 + bit4 * 8 + bit5 * 4 + bit6 * 2 + bit7;
			//swpidx = bit1 * (N >> 2) + bit2 * (N >> 3) + bit3 * (N >> 4) + bit4 * (N >> 5) + bit5 * (N >> 6) + bit6 * (N >> 7) + ((N != 256) ? bit7 * 2 + (i >> 7) % 2 : bit7);

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
