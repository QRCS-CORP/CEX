#include "NTRUTest.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/NTRU.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Enumeration::AsymmetricKeyTypes;
	using Enumeration::AsymmetricPrimitives;
	using Enumeration::AsymmetricTransforms;
	using Exception::CryptoAsymmetricException;
	using Test::NistRng;
	using Asymmetric::Encrypt::NTRU::NTRU;
	using Enumeration::NTRUParameters;
	using Prng::SecureRandom;

	const std::string NTRUTest::CLASSNAME = "NTRUTest";
	const std::string NTRUTest::DESCRIPTION = "NTRU key generation, encryption, and decryption tests..";
	const std::string NTRUTest::SUCCESS = "SUCCESS! NTRU tests have executed succesfully.";

	NTRUTest::NTRUTest()
		:
		m_progressEvent()
	{
	}

	NTRUTest::~NTRUTest()
	{
	}

	const std::string NTRUTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &NTRUTest::Progress()
	{
		return m_progressEvent;
	}

	std::string NTRUTest::Run()
	{
		try
		{
			Initialize();

			Kat();
			OnProgress(std::string("ModuleLWETest: Passed cipher-text and shared-secret known answer tests.."));

			Authentication();
			OnProgress(std::string("NTRUTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("NTRUTest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("NTRUTest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("NTRUTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("NTRUTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("NTRUTest: Passed encryption and decryption stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void NTRUTest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);
		cpr1.Initialize(kp1->PrivateKey());

		if (!cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("L-Prime Message authentication integrity test failed! -NA1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: NTRUS2SQ4591N761
		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);
		cpr2.Initialize(kp2->PrivateKey());

		if (!cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("S-Prime Message authentication test failed! -NA2"));
		}
	}

	void NTRUTest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr1.Name(), std::string("L-Prime Cipher text integrity test failed! -NC1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: NTRUS2SQ4591N761
		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr2.Name(), std::string("S-Prime Cipher text integrity test failed! -NC2"));
		}

		delete kp2;
	}

	void NTRUTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			NTRU cpr(NTRUParameters::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -NE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			NTRU cpr(NTRUParameters::None, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -NE2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			NTRU cpr(NTRUParameters::None, Enumeration::Prngs::BCR);
			Asymmetric::Encrypt::RLWE::RingLWE cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			cpr.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -NE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void NTRUTest::Kat()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);
		NistRng gen;

		// NTRUS1LQ4591N761

		gen.Initialize(m_cprseed);

		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();
		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, ssk1);
		cpr1.Initialize(kp1->PrivateKey());

		if (!cpr1.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -NK1"));
		}

		if (ssk1 != ssk2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -NK2"));
		}

		if (ssk1 != m_sskexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secret does not match expected! -NK3"));
		}

		if (cpt != m_cptexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Cipher-text arrays do not match! -NK4"));
		}

		// NTRUS2SQ4591N761

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);
		gen.Initialize(m_cprseed);

		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761, &gen);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Failed authentication test! -NK5"));
		}

		if (ssk1 != ssk2)
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Shared secrets do not match! -NK6"));
		}

		if (ssk1 != m_sskexp[1])
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Shared secret does not match expected! -NK7"));
		}

		if (cpt != m_cptexp[1])
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Cipher-text arrays do not match! -NK8"));
		}
	}

	void NTRUTest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> p1 = kp1->PublicKey()->Polynomial();
		p1[0] += 1;
		p1[1] += 1;
		AsymmetricKey* pk1 = new AsymmetricKey(p1, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(NTRUParameters::NTRUS1LQ4591N761));
		cpr1.Initialize(pk1);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr1.Name(), std::string("Public key integrity test failed! -NP1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: NTRUS2SQ4591N761
		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> p2 = kp2->PublicKey()->Polynomial();
		p2[0] += 1;
		p2[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(p2, AsymmetricPrimitives::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(NTRUParameters::NTRUS2SQ4591N761));
		cpr2.Initialize(pk2);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -NP2"));
		}

		delete kp2;
	}

	void NTRUTest::Serialization()
	{
		SecureVector<byte> skey(0);

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -NR1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Public key serialization test has failed! -NR2"));
			}
		}

		skey.clear();
		skey.resize(0);

		// test param 2: NTRUS2SQ4591N761
		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr2.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Private key serialization test has failed! -NR3"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Public key serialization test has failed! -NR4"));
			}
		}
	}

	void NTRUTest::Stress()
	{
		// test encapsulate/decapsulate with LPrime configuration
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -NS1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("L-Prime Stress test has failed! -NS2"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// test param 2: NTRUS2SQ4591N761
		NTRU cpr2(NTRUParameters::NTRUS2SQ4591N761);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test authentication has failed! -NS3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("S-PrimeStress test has failed! -NS4"));
			}
		}
	}

	void NTRUTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> cprcpt =
		{
			std::string("9F5705C11979DE1F574BC3755BDF872FC218690E8092B6D764C968393D119DDB9AB0CDBA25CB16465617592F2256E0E5D9E2A61993BE4049E4266CE93E500386"
				"39F976110549E8BC0F4F08F980FB71950815F99DCC100AAFE5FB454874C7350CA326448B4185AF1DE66C2C0A9129C9CDAEB126EBA1A0A5067CF0380A4640F1F0"
				"D8C8A95BC01D458F4149C979BD"),
			std::string("056DACA18318D82849759ED3C816C45821186E6AA763A018C5A40AA29593A6C312A30CE36FB3C30BC4E2A4AFD1C7B065"
				"14E9FE59678A0F2A14F09B0645F9EC980D406790DE6775781E3136A248D4588D60344F73CB4E3C567DE64BBE588C7C54"
				"9A9E3585EF98A5F55C3B9BAD7418932CB8966EC08B28B3A2A30B5C9067DFC854935DD0410D19BB24BF7086C0BCAB2DD0"
				"A69D25A15B5A685936855F05BFA7CA9CF9E58557B3AE8D4EBC8853B32FD52AD1DF66D6576CB69D58CFC8915BCC9D1C10"
				"1602430E3F44F48135F4370B0959B02E891F597C5BFBD340154BA8E9233DE6CE1FAF"),
			std::string("9583F9C0E887851BE079E0AEF65CC7F6C11482AA537E99EAD8865C3B5E65821468C4687CDF017C9FCF2B318238A97519"
				"9D05E7FE51034585B26B54F3E3E99C410BCDC090A736BDBFC34C400402A9860E39438DEA312379EFE4DAE5CFCD7280CA"
				"978F8A96B96397C02B8518D11615FFA8B26D74A85406138199E6F4B8B4A683FB966398F5EDAC38557D73A127816B0644"
				"3BDE6524A936C2C0DA8EFDDDB3850F522F0A26FC3DC3BCBBFFB32A0AD0FD156A8F3192D45B10B48647C546F8C5DB3F0D"
				"1AEAA192D88493AE6C1F1E9C253342551094F5643697600DCB99758E6D06375DCA20005FEBABBDC3A894CF676EB51992")
		};
		HexConverter::Decode(cprcpt, 3, m_cptexp);

		const std::vector<std::string> cprexp =
		{
			std::string("9DF29F0FC955C8A1280752039E090DC1A27E5A829D435CEC247EB347AB897A67"),
			std::string("179C2314367D02DCC0CF1C1CCF7055FB870CB26F529BBD4A393D6603FE70AE95"),
			std::string("DD1A7EC5E1026D5A77210F1374219018FC1C6CFD6BADF848A860C4749424D344")
		};
		HexConverter::Decode(cprexp, 3, m_sskexp);

		const std::string cprseed =
		{
			std::string("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"),
		};
		HexConverter::Decode(cprseed, m_cprseed);

		/*lint -restore */
	}

	void NTRUTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
