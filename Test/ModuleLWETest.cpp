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
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K2, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(true, kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(false, kp->PrivateKey());
		cpr.Decapsulate(cpt, sec2);

		delete kp;

		if (sec1 == sec2)
		{
			throw TestException("ModuleLWETest: Cipher-text integrity test failed!");
		}
	}

	void ModuleLWETest::MessageAuthentication()
	{
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(128);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(true, kp->PublicKey());
		enc = cpr.Encrypt(msg);

		// alter ciphertext
		m_rngPtr->GetBytes(enc, 0, 4);

		cpr.Initialize(false, kp->PrivateKey());

		try
		{
			dec = cpr.Decrypt(enc);
		}
		catch (Exception::CryptoAuthenticationFailure)
		{
			// passed
			delete kp;
			return;
		}

		throw TestException("ModuleLWETest: Message authentication test failed!");
	}

	void ModuleLWETest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		ModuleLWE cpr(Enumeration::MLWEParams::Q7681N256K3, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> p2 = ((MLWEPublicKey*)kp->PublicKey())->P();
		p2[0] += 1;
		p2[1] += 1;
		MLWEPublicKey* pk2 = new MLWEPublicKey(Enumeration::MLWEParams::Q7681N256K3, p2);
		cpr.Initialize(true, pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(false, kp->PrivateKey());
		cpr.Decapsulate(cpt, sec2);

		if (sec1 == sec2)
		{
			throw TestException("ModuleLWETest: PublicKey integrity test failed!");
		}

		delete kp;
		delete pk2;
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
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(32);

		// test encrypt/decrypt api
		ModuleLWE cpr1(Enumeration::MLWEParams::Q7681N256K4, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			m_rngPtr->GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(true, kp->PublicKey());
			enc = cpr1.Encrypt(msg);

			cpr1.Initialize(false, kp->PrivateKey());
			dec = cpr1.Decrypt(enc);

			delete kp;

			if (dec != msg)
			{
				throw TestException("ModuleLWETest: Stress test has failed!");
			}
		}

		// test encapsulate/decapsulate
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);
		ModuleLWE cpr2(Enumeration::MLWEParams::Q7681N256K4, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(true, kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(false, kp->PrivateKey());
			cpr2.Decapsulate(cpt, sec2);

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
