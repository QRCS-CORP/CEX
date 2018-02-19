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
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);
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
			throw TestException("RingLWETest: Cipher-text integrity test failed!");
		}
	}

	void RingLWETest::MessageAuthentication()
	{
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(128);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);
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

		throw TestException("RingLWETest: Message authentication test failed!");
	}

	void RingLWETest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		RingLWE cpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> p2 = ((RLWEPublicKey*)kp->PublicKey())->P();
		m_rngPtr->GetBytes(p2, 0, 4);
		RLWEPublicKey* pk2 = new RLWEPublicKey(Enumeration::RLWEParams::Q12289N1024, p2);
		cpr.Initialize(true, pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(false, kp->PrivateKey());
		cpr.Decapsulate(cpt, sec2);

		if (sec1 == sec2)
		{
			throw TestException("RingLWETest: PublicKey integrity test failed!");
		}

		delete kp;
		delete pk2;
	}

	void RingLWETest::SerializationCompare()
	{
		std::vector<byte> skey;
		RingLWE asyCpr(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);

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
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(128);

		// Q12289N1024 parameter
		RingLWE cpr1(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);

		// test encrypt/decrypt api
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
				throw TestException("RingLWETest: Stress test has failed!");
			}
		}

		// Q12289N512 parameter
		RingLWE cpr2(Enumeration::RLWEParams::Q12289N512, m_rngPtr, false);

		// test encrypt/decrypt api
		for (size_t i = 0; i < 100; ++i)
		{
			m_rngPtr->GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(true, kp->PublicKey());
			enc = cpr2.Encrypt(msg);

			cpr2.Initialize(false, kp->PrivateKey());
			dec = cpr2.Decrypt(enc);

			delete kp;

			if (dec != msg)
			{
				throw TestException("RingLWETest: Stress test has failed!");
			}
		}

		// test encapsulate/decapsulate api
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		// Q12289N1024 parameter
		RingLWE cpr3(Enumeration::RLWEParams::Q12289N1024, m_rngPtr, false);

		for (size_t i = 0; i < 100; ++i)
		{
			m_rngPtr->GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr3.Generate();

			cpr3.Initialize(true, kp->PublicKey());
			cpr3.Encapsulate(cpt, sec1);

			cpr3.Initialize(false, kp->PrivateKey());
			cpr3.Decapsulate(cpt, sec2);

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("RingLWETest: Stress test has failed!");
			}
		}

		// Q12289N512 parameter
		RingLWE cpr4(Enumeration::RLWEParams::Q12289N512, m_rngPtr, false);

		for (size_t i = 0; i < 100; ++i)
		{
			m_rngPtr->GetBytes(msg);
			IAsymmetricKeyPair* kp = cpr4.Generate();

			cpr4.Initialize(true, kp->PublicKey());
			cpr4.Encapsulate(cpt, sec1);

			cpr4.Initialize(false, kp->PrivateKey());
			cpr4.Decapsulate(cpt, sec2);

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
