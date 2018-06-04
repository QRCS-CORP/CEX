#include "NTRUTest.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/NTRU.h"
#include "../CEX/NTRUKeyPair.h"
#include "../CEX/NTRUPrivateKey.h"
#include "../CEX/NTRUPublicKey.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::NTRU;

	const std::string NTRUTest::DESCRIPTION = "NTRU key generation, encryption, and decryption tests..";
	const std::string NTRUTest::FAILURE = "FAILURE! ";
	const std::string NTRUTest::SUCCESS = "SUCCESS! NTRU tests have executed succesfully.";

	NTRUTest::NTRUTest()
		:
		m_progressEvent(),
		m_rngPtr(new Prng::BCR)
	{
	}

	NTRUTest::~NTRUTest()
	{
		delete m_rngPtr;
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
			CipherTextIntegrity();
			OnProgress(std::string("NTRUTest: Passed cipher-text integrity test.."));
			MessageAuthentication();
			OnProgress(std::string("NTRUTest: Passed message authentication test.."));
			PublicKeyIntegrity();
			OnProgress(std::string("NTRUTest: Passed public key integrity test.."));
			StressLoop();
			OnProgress(std::string("NTRUTest: Passed encryption and decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("NTRUTest: Passed key serialization tests.."));

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

	void NTRUTest::CipherTextIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void NTRUTest::MessageAuthentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void NTRUTest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> p2 = ((NTRUPublicKey*)kp->PublicKey())->P();
		p2[0] += 1;
		p2[1] += 1;
		NTRUPublicKey* pk2 = new NTRUPublicKey(Enumeration::NTRUParams::LQ4591N761, p2);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: Cipher-text integrity test failed!");
		}

		delete kp;
	}

	void NTRUTest::SerializationCompare()
	{
		std::vector<byte> skey;
		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{

			IAsymmetricKeyPair* kp = cpr.Generate();
			NTRUPrivateKey* priK1 = (NTRUPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			NTRUPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException("NTRUTest: Private key serialization test has failed!");
			}

			NTRUPublicKey* pubK1 = (NTRUPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			NTRUPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException("NTRUTest: Public key serialization test has failed!");
			}
		}
	}

	void NTRUTest::StressLoop()
	{
		// test encapsulate/decapsulate
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);

		for (size_t i = 0; i < 100; ++i)
		{
			IAsymmetricKeyPair* kp = cpr.Generate();

			cpr.Initialize(kp->PublicKey());
			cpr.Encapsulate(cpt, sec1);

			cpr.Initialize(kp->PrivateKey());
			cpr.Decapsulate(cpt, sec2);

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("NTRUTest: Stress test has failed!");
			}
		}
	}

	void NTRUTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
