#include "NTRUTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/NTRU.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Asymmetric;
	using namespace Asymmetric::Encrypt::NTRU;
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

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
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

	void NTRUTest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> p1 = kp1->PublicKey()->P();
		p1[0] += 1;
		p1[1] += 1;
		AsymmetricKey* pk1 = new AsymmetricKey(AsymmetricEngines::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(NTRUParameters::NTRUS1LQ4591N761), p1);
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
		std::vector<byte> p2 = kp2->PublicKey()->P();
		p2[0] += 1;
		p2[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(AsymmetricEngines::NTRU, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(NTRUParameters::NTRUS2SQ4591N761), p2);
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
		std::vector<byte> skey(0);

		// test param 1: NTRUS1LQ4591N761
		NTRU cpr1(NTRUParameters::NTRUS1LQ4591N761);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* priK1 = kp->PrivateKey();
			skey = priK1->ToBytes();
			AsymmetricKey priK2(skey);

			if (priK1->P() != priK2.P() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -NR1"));
			}

			AsymmetricKey* pubK1 = kp->PublicKey();
			skey = pubK1->ToBytes();
			AsymmetricKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
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
			AsymmetricKey* priK1 = kp->PrivateKey();
			skey = priK1->ToBytes();
			AsymmetricKey priK2(skey);

			if (priK1->P() != priK2.P() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Private key serialization test has failed! -NR3"));
			}

			AsymmetricKey* pubK1 = kp->PublicKey();
			skey = pubK1->ToBytes();
			AsymmetricKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
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

	void NTRUTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
