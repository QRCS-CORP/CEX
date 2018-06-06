#include "RingLWETest.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/RHX.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RLWEKeyPair.h"
#include "../CEX/RLWEPrivateKey.h"
#include "../CEX/RLWEPublicKey.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::RLWE;

	const std::string RingLWETest::DESCRIPTION = "RingLWE key generation, encryption, and decryption tests..";
	const std::string RingLWETest::FAILURE = "FAILURE! ";
	const std::string RingLWETest::SUCCESS = "SUCCESS! RingLWE tests have executed succesfully.";

	RingLWETest::RingLWETest()
		:
		m_progressEvent(),
		m_rngPtr(new Prng::BCR)
	{
	}

	RingLWETest::~RingLWETest()
	{
		delete m_rngPtr;
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
			CipherTextIntegrity();
			OnProgress(std::string("RingLWETest: Passed cipher-text integrity test.."));
			MessageAuthentication();
			OnProgress(std::string("RingLWETest: Passed message authentication test.."));
			PublicKeyIntegrity();
			OnProgress(std::string("RingLWETest: Passed public key integrity test.."));
			StressLoop();
			OnProgress(std::string("RingLWETest: Passed encryption and decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("RingLWETest: Passed key serialization tests.."));

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

	void RingLWETest::CipherTextIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("RingLWETest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void RingLWETest::MessageAuthentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("RingLWETest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void RingLWETest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> pk1 = ((RLWEPublicKey*)kp->PublicKey())->P();
		pk1[0] += 1;
		pk1[1] += 1;
		RLWEPublicKey* pk2 = new RLWEPublicKey(Enumeration::RLWEParams::Q12289N1024, pk1);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("RingLWETest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void RingLWETest::SerializationCompare()
	{
		std::vector<byte> skey;
		RingLWE asyCpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			IAsymmetricKeyPair* kp = asyCpr.Generate();
			RLWEPrivateKey* priK1 = (RLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			RLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException("RingLWETest: Private key serialization test has failed!");
			}

			RLWEPublicKey* pubK1 = (RLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			RLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException("RingLWETest: Public key serialization test has failed!");
			}
		}
	}

	void RingLWETest::StressLoop()
	{
		std::vector<byte> msg(128);
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		RingLWE cpr1(Enumeration::RLWEParams::Q12289N1024, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			m_rngPtr->GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());
			cpr1.Decapsulate(cpt, sec2);

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("RingLWETest: Stress test has failed!");
			}
		}
	}

	void RingLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
