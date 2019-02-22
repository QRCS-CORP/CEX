#include "ModuleLWETest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using namespace Asymmetric;
	using namespace Asymmetric::Encrypt::MLWE;
	using Enumeration::MLWEParameters;
	using Prng::SecureRandom;

	const std::string ModuleLWETest::CLASSNAME = "ModuleLWETest";
	const std::string ModuleLWETest::DESCRIPTION = "ModuleLWE key generation, encryption, and decryption tests..";
	const std::string ModuleLWETest::SUCCESS = "SUCCESS! ModuleLWE tests have executed succesfully.";

	ModuleLWETest::ModuleLWETest()
		:
		m_progressEvent()
	{
	}

	ModuleLWETest::~ModuleLWETest()
	{
	}

	const std::string ModuleLWETest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ModuleLWETest::Progress()
	{
		return m_progressEvent;
	}

	std::string ModuleLWETest::Run()
	{
		try
		{
			Authentication();
			OnProgress(std::string("ModuleLWETest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("ModuleLWETest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("ModuleLWETest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("ModuleLWETest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("ModuleLWETest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("ModuleLWETest: Passed encryption and decryption stress tests.."));

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

	void ModuleLWETest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		SecureRandom gen;

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -MA1"));
		}

		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpt.resize(0);

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpt.resize(0);

		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr3.Name(), std::string("Message authentication test failed! -MA3"));
		}

		delete kp3;
	}

	void ModuleLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr1.Name(), std::string("Cipher text integrity test failed! -MC1"));
		}

		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpt.resize(0);

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr2.Name(), std::string("Cipher text integrity test failed! -MC2"));
		}

		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpt.resize(0);

		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr3.Name(), std::string("Cipher text integrity test failed! -MC3"));
		}

		delete kp3;
	}

	void ModuleLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			ModuleLWE cpr(MLWEParameters::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME1"));
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
			ModuleLWE cpr(MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME2"));
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
			ModuleLWE cpr(MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::BCR);
			Asymmetric::Encrypt::RLWE::RingLWE cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			cpr.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ModuleLWETest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> pk1 = kp1->PublicKey()->Polynomial();
		pk1[0] += 1;
		pk1[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES2Q7681N256));
		cpr1.Initialize(pk2);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr1.Name(), std::string("Public key integrity test failed! -MP1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> pk3 = kp2->PublicKey()->Polynomial();
		pk3[0] += 1;
		pk3[1] += 1;
		AsymmetricKey* pk4 = new AsymmetricKey(pk3, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES3Q7681N256));
		cpr2.Initialize(pk4);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -MP2"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		// alter public key
		std::vector<byte> pk5 = kp3->PublicKey()->Polynomial();
		pk5[0] += 1;
		pk5[1] += 1;
		AsymmetricKey* pk6 = new AsymmetricKey(pk5, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES4Q7681N256));
		cpr3.Initialize(pk6);
		cpr3.Encapsulate(cpt, sec1);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr3.Name(), std::string("Public key integrity test failed! -MP3"));
		}

		delete kp3;
	}

	void ModuleLWETest::Serialization()
	{
		SecureVector<byte> skey(0);

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -MR1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Public key serialization test has failed! -MR2"));
			}
		}

		skey.clear();
		skey.resize(0);

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{

			AsymmetricKeyPair* kp = cpr2.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Private key serialization test has failed! -MR3"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Public key serialization test has failed! -MR4"));
			}
		}

		skey.clear();
		skey.resize(0);

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr3.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr3.Name(), std::string("Private key serialization test has failed! -MR5"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr3.Name(), std::string("Public key serialization test has failed! -MR6"));
			}
		}
	}

	void ModuleLWETest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		SecureRandom gen;

		ModuleLWE cpr1(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -MT1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -MT2"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test authentication has failed! -MT3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test has failed! -MT4"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr3.Generate();

			cpr3.Initialize(kp->PublicKey());
			cpr3.Encapsulate(cpt, sec1);

			cpr3.Initialize(kp->PrivateKey());

			if (!cpr3.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test authentication has failed! -MT5"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test has failed! -MT6"));
			}
		}
	}

	void ModuleLWETest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
