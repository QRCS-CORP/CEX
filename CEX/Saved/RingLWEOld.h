#ifndef _CEX_RINGLWE_H
#define _CEX_RINGLWE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "PrngFromName.h"
#include "RLWEKeyPair.h"
#include "RLWEParams.h"
#include "RLWEPrivateKey.h"
#include "RLWEPublicKey.h"
#include "RLWEParamSet.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "PolyMath.h"
#include "NTTN512Q25601.h"

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
	std::vector<byte> Decrypt(std::vector<byte> &Input)
	{
		std::vector<byte> k(0);
		return k;
	}

	/// <summary>
	/// Encrypt a plain-text message
	/// </summary>
	/// 
	/// <param name="Input">The input plain-text</param>
	/// <param name="InOffset">The starting position within the input array</param>
	/// <param name="Output">The output cipher-text</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	std::vector<byte> Encrypt(std::vector<byte> &Input)
	{
		std::vector<byte> k(0);
		return k;
	}

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	IAsymmetricKeyPair* Generate()
	{
		NTTN512Q25601 ntt(m_rndGenerator);
		/*Exclusively For Alice*/
		RINGELT s_alice[2 * 512]; /* Alice's Private Key */
		uint64_t mu_alice[8]; /* Alice's recovered mu */
		/*Exclusively For Bob*/
		uint64_t mu_bob[8]; /* Bob's version of mu */
		/*Information that gets shared by Alice and Bob*/
		RINGELT b_alice[512]; /* Alice's Public Key */
		RINGELT u[512]; /* Bob's Ring Element from Encapsulation */
		uint64_t cr_v[8]; /* Cross Rounding of v */

		ntt.KEM1_Generate(s_alice, b_alice);

		ntt.KEM1_Encapsulate(u, cr_v, mu_bob, b_alice);

		ntt.KEM1_Decapsulate(mu_alice, u, s_alice + 512, cr_v);

		int i, flag = 1;
		for (i = 0; i < 8; ++i) flag &= (mu_alice[i] == mu_bob[i]);
		if (flag) 
		{
			printf("Successful Key Agreement!\n");
		}
		else 
		{
			printf("Failure in Key Agreement :-(\n");
			for (i = 0; i < 8; ++i) 
				printf("%PRIu64\t", mu_alice[i]);

			printf("\n");
			for (i = 0; i < 8; ++i) 
				printf("%PRIu64\t", mu_bob[i]);

			printf("\n");

			//exit(-1);
		}

		printf("Alice's version of mu\n");
		for (i = 0; i < 8; ++i)
			printf("%lu ", mu_alice[i]);
		printf("\n\n");

		printf("Bob's version of mu\n");
		for (i = 0; i < 8; ++i)
			printf("%lu ", mu_bob[i]);

		/*NTTN512Q25601 ntt(m_rndGenerator);
		uint_fast16_t s[1024];
		uint_fast16_t b[512];
		ntt.KEM1_Generate(s, b);

		uint_fast16_t u[512];
		uint64_t cr_v[8];
		uint64_t mu[8];
		ntt.KEM1_Encapsulate(u, cr_v, mu, b);

		uint64_t mu2[8];
		ntt.KEM1_Decapsulate(mu2, u, s, cr_v);*/

		return NULL;
	}

private:

	RLWEParamSet GetParams(RLWEParams ParamSet)
	{
		RLWEParamSet params;

		/*switch (ParamSet)
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
		}*/

		return params;
	}
};

NAMESPACE_RINGLWEEND
#endif
