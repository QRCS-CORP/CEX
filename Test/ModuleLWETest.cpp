#include "ModuleLWETest.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/MLWEKeyPair.h"
#include "../CEX/MLWEPrivateKey.h"
#include "../CEX/MLWEPublicKey.h"
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
			CipherTextIntegrity();
			OnProgress(std::string("ModuleLWETest: Passed cipher-text integrity test.."));
			MessageAuthentication();
			OnProgress(std::string("ModuleLWETest: Passed message authentication test.."));
			PublicKeyIntegrity();
			OnProgress(std::string("ModuleLWETest: Passed public key integrity test.."));
			StressLoop();
			OnProgress(std::string("ModuleLWETest: Passed encryption and decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("ModuleLWETest: Passed key serialization tests.."));

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

	void ModuleLWETest::CipherTextIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K2, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("ModuleLWETest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void ModuleLWETest::MessageAuthentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("ModuleLWETest: Message authentication test failed!");
		}

		delete kp;
	}

	void ModuleLWETest::PublicKeyIntegrity()
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
			throw TestException("ModuleLWETest: Public-key integrity test failed!");
		}

		delete kp;
	}

	void ModuleLWETest::SerializationCompare()
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
				throw TestException("ModuleLWETest: Private key serialization test has failed!");
			}

			MLWEPublicKey* pubK1 = (MLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			MLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException("ModuleLWETest: Public key serialization test has failed!");
			}
		}
	}

	void ModuleLWETest::StressLoop()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			IAsymmetricKeyPair* kp = cpr.Generate();

			cpr.Initialize(kp->PublicKey());
			cpr.Encapsulate(cpt, sec1);

			cpr.Initialize(kp->PrivateKey());

			if (!cpr.Decapsulate(cpt, sec2))
			{
				throw TestException("ModuleLWETest: Stress test authentication has failed!");
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("ModuleLWETest: Stress test has failed!");
			}
		}
	}

	void ModuleLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
