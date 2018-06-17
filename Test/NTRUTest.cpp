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

		// LPrime
		NTRU cpr1(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: L-Prime Cipher-text integrity test failed!");
		}

		delete kp1;

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// SPrime
		NTRU cpr2(Enumeration::NTRUParams::SQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: S-Prime Cipher-text integrity test failed!");
		}

		delete kp2;
	}

	void NTRUTest::MessageAuthentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// LPrime
		NTRU cpr1(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: L-Prime Message authentication integrity test failed!");
		}

		delete kp1;

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// SPrime
		NTRU cpr2(Enumeration::NTRUParams::SQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: S-Prime Message authentication test failed!");
		}
	}

	void NTRUTest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// LPrime
		NTRU cpr1(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> p1 = ((NTRUPublicKey*)kp1->PublicKey())->P();
		p1[0] += 1;
		p1[1] += 1;
		NTRUPublicKey* pk1 = new NTRUPublicKey(Enumeration::NTRUParams::LQ4591N761, p1);
		cpr1.Initialize(pk1);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: Public-key integrity test failed!");
		}

		delete kp1;

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// SPrime
		NTRU cpr2(Enumeration::NTRUParams::SQ4591N761, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> p2 = ((NTRUPublicKey*)kp2->PublicKey())->P();
		p2[0] += 1;
		p2[1] += 1;
		NTRUPublicKey* pk2 = new NTRUPublicKey(Enumeration::NTRUParams::SQ4591N761, p2);
		cpr2.Initialize(pk2);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException("NTRUTest: Public-key integrity test failed!");
		}

		delete kp2;
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
		// test encapsulate/decapsulate with LPrime configuration
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// LPrime
		NTRU cpr1(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);

		for (size_t i = 0; i < 50; ++i)
		{
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException("NTRUTest: Stress test authentication has failed!");
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("NTRUTest: L-Prime Stress test has failed!");
			}
		}

		// SPrime
		NTRU cpr2(Enumeration::NTRUParams::SQ4591N761, m_rngPtr);

		for (size_t i = 0; i < 50; ++i)
		{
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException("NTRUTest: Stress test authentication has failed!");
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("NTRUTest: S-PrimeStress test has failed!");
			}
		}
	}

	void NTRUTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
