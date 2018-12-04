#include "ModuleLWETest.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/MLWEKeyPair.h"
#include "../CEX/MLWEPrivateKey.h"
#include "../CEX/MLWEPublicKey.h"
#include "../CEX/RingLWE.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::MLWE;

	const std::string ModuleLWETest::DESCRIPTION = "ModuleLWE key generation, encryption, and decryption tests..";
	const std::string ModuleLWETest::FAILURE = "FAILURE! ";
	const std::string ModuleLWETest::SUCCESS = "SUCCESS! ModuleLWE tests have executed succesfully.";

	ModuleLWETest::ModuleLWETest()
		:
		m_progressEvent(),
		m_rngPtr(new Prng::BCR)
	{
	}

	ModuleLWETest::~ModuleLWETest()
	{
		delete m_rngPtr;
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
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(FAILURE + std::string(" : Unknown Error"));
		}
	}

	void ModuleLWETest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		ModuleLWE cpr(Enumeration::MLWEParameters::MLWES3Q7681N256, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWE"), std::string("Message authentication test failed! -MA1"));
		}

		delete kp;
	}

	void ModuleLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		ModuleLWE cpr(Enumeration::MLWEParameters::MLWES3Q7681N256, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWE"), std::string("Cipher-text integrity test failed! -MC1"));
		}

		delete kp;
	}

	void ModuleLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			ModuleLWE cpr(Enumeration::MLWEParameters::None, m_rngPtr);

			throw TestException(std::string("ModuleLWE"), std::string("Exception handling failure! -ME1"));
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
			ModuleLWE cpr(Enumeration::MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::None);

			throw TestException(std::string("ModuleLWE"), std::string("Exception handling failure! -ME2"));
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
			ModuleLWE cpra(Enumeration::MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::BCR);
			Cipher::Asymmetric::RLWE::RingLWE cprb;
			// create an invalid key set
			IAsymmetricKeyPair* kp = cprb.Generate();
			cpra.Initialize(kp->PrivateKey());

			throw TestException(std::string("ModuleLWE"), std::string("Exception handling failure! -ME3"));
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

		ModuleLWE cpr(Enumeration::MLWEParameters::MLWES3Q7681N256, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> pk1 = ((MLWEPublicKey*)kp->PublicKey())->P();
		pk1[0] += 1;
		pk1[1] += 1;
		MLWEPublicKey* pk2 = new MLWEPublicKey(Enumeration::MLWEParameters::MLWES3Q7681N256, pk1);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWE"), std::string("Public-key integrity test failed! -MP1"));
		}

		delete kp;
	}

	void ModuleLWETest::Serialization()
	{
		std::vector<byte> skey;
		ModuleLWE cpr(Enumeration::MLWEParameters::MLWES4Q7681N256, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{

			IAsymmetricKeyPair* kp = cpr.Generate();
			MLWEPrivateKey* priK1 = (MLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			MLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("ModuleLWE"), std::string("Private key serialization test has failed! -MR1"));
			}

			MLWEPublicKey* pubK1 = (MLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			MLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException(std::string("ModuleLWE"), std::string("Public key serialization test has failed! -MR2"));
			}
		}
	}

	void ModuleLWETest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		ModuleLWE cpr1(Enumeration::MLWEParameters::MLWES3Q7681N256, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test authentication has failed! -MT1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test has failed! -MT2"));
			}
		}

		ModuleLWE cpr2(Enumeration::MLWEParameters::MLWES3Q7681N256, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test authentication has failed! -MT3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test has failed! -MT4"));
			}
		}

		ModuleLWE cpr3(Enumeration::MLWEParameters::MLWES4Q7681N256, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr3.Generate();

			cpr3.Initialize(kp->PublicKey());
			cpr3.Encapsulate(cpt, sec1);

			cpr3.Initialize(kp->PrivateKey());

			if (!cpr3.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test authentication has failed! -MT5"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWE"), std::string("Stress test has failed! -MT6"));
			}
		}
	}

	void ModuleLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
