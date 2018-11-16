#include "NTRUTest.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/NTRU.h"
#include "../CEX/NTRUKeyPair.h"
#include "../CEX/NTRUPrivateKey.h"
#include "../CEX/NTRUPublicKey.h"
#include "../CEX/RingLWE.h"
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
			Authentication();
			OnProgress(std::string("NTRUTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("NTRUTest: Passed cipher-text integrity test.."));
			PublicKey();
			OnProgress(std::string("NTRUTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("NTRUTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("NTRUTest: Passed encryption and decryption stress tests.."));

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

	void NTRUTest::Authentication()
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
			throw TestException(std::string("NTRU"), std::string("L-Prime Message authentication integrity test failed! -NA1"));
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
			throw TestException(std::string("NTRU"), std::string("S-Prime Message authentication test failed! -NA2"));
		}
	}

	void NTRUTest::CipherText()
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
			throw TestException(std::string("NTRU"), std::string("L-Prime Cipher-text integrity test failed! -NC1"));
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
			throw TestException(std::string("NTRU"), std::string("S-Prime Cipher-text integrity test failed! -NC2"));
		}

		delete kp2;
	}

	void NTRUTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			NTRU cpr(Enumeration::NTRUParams::None, m_rngPtr);

			throw TestException(std::string("NTRU"), std::string("Exception handling failure! -NE1"));
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
			NTRU cpr(Enumeration::NTRUParams::None, Enumeration::Prngs::None);

			throw TestException(std::string("NTRU"), std::string("Exception handling failure! -NE2"));
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
			NTRU cpra(Enumeration::NTRUParams::None, Enumeration::Prngs::BCR);
			Cipher::Asymmetric::RLWE::RingLWE cprb;
			// create an invalid key set
			IAsymmetricKeyPair* kp = cprb.Generate();
			cpra.Initialize(kp->PrivateKey());

			throw TestException(std::string("NTRU"), std::string("Exception handling failure! -NE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void NTRUTest::PublicKey()
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
			throw TestException(std::string("NTRU"), std::string("Public key integrity test failed! -NP1"));
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
			throw TestException(std::string("NTRU"), std::string("Public key integrity test failed! -NP2"));
		}

		delete kp2;
	}

	void NTRUTest::Serialization()
	{
		std::vector<byte> skey;
		NTRU cpr(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			IAsymmetricKeyPair* kp = cpr.Generate();
			NTRUPrivateKey* priK1 = (NTRUPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			NTRUPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("NTRU"), std::string("Private key serialization test has failed! -NR1"));
			}

			NTRUPublicKey* pubK1 = (NTRUPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			NTRUPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException(std::string("NTRU"), std::string("Public key serialization test has failed! -NR2"));
			}
		}
	}

	void NTRUTest::Stress()
	{
		// test encapsulate/decapsulate with LPrime configuration
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// LPrime
		NTRU cpr1(Enumeration::NTRUParams::LQ4591N761, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("NTRU"), std::string("Stress test authentication has failed! -NS1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("NTRU"), std::string("L-Prime Stress test has failed! -NS2"));
			}
		}

		// SPrime
		NTRU cpr2(Enumeration::NTRUParams::SQ4591N761, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			m_rngPtr->Generate(sec1);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("NTRU"), std::string("Stress test authentication has failed! -NS3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("NTRU"), std::string("S-PrimeStress test has failed! -NS4"));
			}
		}
	}

	void NTRUTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
