#include "RingLWETest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/RHX.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using namespace Asymmetric;
	using namespace Asymmetric::Encrypt::RLWE;
	using Enumeration::RLWEParameters;
	using Prng::SecureRandom;

	const std::string RingLWETest::CLASSNAME = "RingLWETest";
	const std::string RingLWETest::DESCRIPTION = "RingLWE key generation, encryption, and decryption tests..";
	const std::string RingLWETest::SUCCESS = "SUCCESS! RingLWE tests have executed succesfully.";

	RingLWETest::RingLWETest()
		:
		m_progressEvent()
	{
	}

	RingLWETest::~RingLWETest()
	{
	}

	const std::string RingLWETest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RingLWETest::Progress()
	{
		return m_progressEvent;
	}

	std::string RingLWETest::Run()
	{
		try
		{
			Authentication();
			OnProgress(std::string("RingLWETest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("RingLWETest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("RingLWETest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("RingLWETest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("RingLWETest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("RingLWETest: Passed encryption and decryption stress tests.."));

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

	void RingLWETest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		SecureRandom gen;

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(RLWEParameters::RLWES1Q12289N1024);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -RA1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(RLWEParameters::RLWES2Q12289N2048);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -RA2"));
		}

		delete kp2;
	}

	void RingLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(RLWEParameters::RLWES1Q12289N1024);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr1.Name(), std::string("Cipher text integrity test failed! -RC1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(RLWEParameters::RLWES2Q12289N2048);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr2.Name(), std::string("Cipher text integrity test failed! -RC2"));
		}

		delete kp2;
	}

	void RingLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			RingLWE cpr(RLWEParameters::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE1"));
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
			RingLWE cpr(RLWEParameters::RLWES1Q12289N1024, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE2"));
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
			RingLWE cpra(RLWEParameters::RLWES1Q12289N1024, Enumeration::Prngs::BCR);
			Asymmetric::Encrypt::MLWE::ModuleLWE cpr;
			// create an invalid key set
			AsymmetricKeyPair* kp = cpr.Generate();
			cpra.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RingLWETest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(RLWEParameters::RLWES1Q12289N1024);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> pk1 = kp1->PublicKey()->Polynomial();
		pk1[0] += 1;
		pk1[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(RLWEParameters::RLWES1Q12289N1024));
		cpr1.Initialize(pk2);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr1.Name(), std::string("Public key integrity test failed! -RP1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(RLWEParameters::RLWES2Q12289N2048);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> pk3 = kp2->PublicKey()->Polynomial();
		pk3[0] += 1;
		pk3[1] += 1;
		AsymmetricKey* pk4 = new AsymmetricKey(pk3, AsymmetricPrimitives::RingLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(RLWEParameters::RLWES2Q12289N2048));
		cpr2.Initialize(pk4);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -RP2"));
		}

		delete kp2;
	}

	void RingLWETest::Serialization()
	{
		SecureVector<byte> skey(0);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(RLWEParameters::RLWES1Q12289N1024);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -RS1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), std::string("RLWE"), std::string("Public key serialization test has failed! -RS2"));
			}
		}

		skey.resize(0);

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(RLWEParameters::RLWES2Q12289N2048);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr2.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Private key serialization test has failed! -RS1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Public key serialization test has failed! -RS2"));
			}
		}
	}

	void RingLWETest::Stress()
	{
		std::vector<byte> msg(128);
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(RLWEParameters::RLWES1Q12289N1024);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			gen.Generate(msg);
			AsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);
			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -RR1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -RR2"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(RLWEParameters::RLWES2Q12289N2048);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			gen.Generate(msg);
			AsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test authentication has failed! -RR3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test has failed! -RR4"));
			}
		}
	}

	void RingLWETest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
