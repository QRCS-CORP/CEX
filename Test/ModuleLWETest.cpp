#include "ModuleLWETest.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/MLWEKeyPair.h"
#include "../CEX/MLWEPrivateKey.h"
#include "../CEX/MLWEPublicKey.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"

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

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWETest: Message authentication test failed!"));
		}

		delete kp;
	}

	void ModuleLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K2, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWETest: Cipher-text integrity test failed!"));
		}

		delete kp;
	}

	void ModuleLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			ModuleLWE cpr(Enumeration::MLWEParams::None, m_rngPtr);

			throw TestException(std::string("ModuleLWE"), std::string("Exception: Exception handling failure! -ME1"));
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
			ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, Enumeration::Prngs::None);

			throw TestException(std::string("ModuleLWE"), std::string("Exception: Exception handling failure! -ME2"));
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
			ModuleLWE cpra(Enumeration::MLWEParams::Q7681N256K3, Enumeration::Prngs::BCR);
			Cipher::Asymmetric::RLWE::RingLWE cprb;
			// create an invalid key set
			IAsymmetricKeyPair* kp = cprb.Generate();
			cpra.Initialize(kp->PrivateKey());

			throw TestException(std::string("ModuleLWE"), std::string("Exception: Exception handling failure! -ME3"));
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

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> pk1 = ((MLWEPublicKey*)kp->PublicKey())->P();
		pk1[0] += 1;
		pk1[1] += 1;
		MLWEPublicKey* pk2 = new MLWEPublicKey(Enumeration::MLWEParams::Q7681N256K3, pk1);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("ModuleLWETest: Public-key integrity test failed!"));
		}

		delete kp;
	}

	void ModuleLWETest::Serialization()
	{
		std::vector<byte> skey;
		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K4, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{

			IAsymmetricKeyPair* kp = cpr.Generate();
			MLWEPrivateKey* priK1 = (MLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			MLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("ModuleLWETest: Private key serialization test has failed!"));
			}

			MLWEPublicKey* pubK1 = (MLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			MLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException(std::string("ModuleLWETest: Public key serialization test has failed!"));
			}
		}
	}

	void ModuleLWETest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		ModuleLWE cpr1(Enumeration::MLWEParams::Q7681N256K2, m_rngPtr);

		for (size_t i = 0; i < 33; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWETest: Stress test authentication has failed!"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWETest: Stress test has failed!"));
			}
		}

		ModuleLWE cpr2(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);

		for (size_t i = 0; i < 33; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWETest: Stress test authentication has failed!"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWETest: Stress test has failed!"));
			}
		}

		ModuleLWE cpr3(Enumeration::MLWEParams::Q7681N256K4, m_rngPtr);

		for (size_t i = 0; i < 34; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr3.Generate();

			cpr3.Initialize(kp->PublicKey());
			cpr3.Encapsulate(cpt, sec1);

			cpr3.Initialize(kp->PrivateKey());

			if (!cpr3.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("ModuleLWETest: Stress test authentication has failed!"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("ModuleLWETest: Stress test has failed!"));
			}
		}
	}

	void ModuleLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
