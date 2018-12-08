#include "RingLWETest.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/IntUtils.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/RHX.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RLWEKeyPair.h"
#include "../CEX/RLWEPrivateKey.h"
#include "../CEX/RLWEPublicKey.h"

namespace Test
{
	using Enumeration::RLWEParameters;
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
			Authentication();
			OnProgress(std::string("RingLWETest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("RingLWETest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("RingLWETest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("RingLWETest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("RingLWETest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("RingLWETest: Passed encryption and decryption stress tests.."));

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

	void RingLWETest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(Enumeration::RLWEParameters::RLWES1Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Message authentication test failed! -RA1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(Enumeration::RLWEParameters::RLWES2Q12289N2048, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Message authentication test failed! -RA2"));
		}

		delete kp2;
	}

	void RingLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(Enumeration::RLWEParameters::RLWES1Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Cipher-text integrity test failed! -RC1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(Enumeration::RLWEParameters::RLWES2Q12289N2048, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Cipher-text integrity test failed! -RC2"));
		}

		delete kp2;
	}

	void RingLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			RingLWE cpr(Enumeration::RLWEParameters::None, m_rngPtr);

			throw TestException(std::string("RLWE"), std::string("Exception handling failure! -RE1"));
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
			RingLWE cpr(Enumeration::RLWEParameters::RLWES1Q12289N1024, Enumeration::Prngs::None);

			throw TestException(std::string("RLWE"), std::string("Exception handling failure! -RE2"));
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
			RingLWE cpra(Enumeration::RLWEParameters::RLWES1Q12289N1024, Enumeration::Prngs::BCR);
			Cipher::Asymmetric::MLWE::ModuleLWE cprb;
			// create an invalid key set
			IAsymmetricKeyPair* kp = cprb.Generate();
			cpra.Initialize(kp->PrivateKey());

			throw TestException(std::string("RLWE"), std::string("Exception handling failure! -RE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RingLWETest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(Enumeration::RLWEParameters::RLWES1Q12289N1024, m_rngPtr);
		IAsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> pk1 = ((RLWEPublicKey*)kp1->PublicKey())->P();
		pk1[0] += 1;
		pk1[1] += 1;
		RLWEPublicKey* pk2 = new RLWEPublicKey(Enumeration::RLWEParameters::RLWES1Q12289N1024, pk1);
		cpr1.Initialize(pk2);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Public key integrity test failed! -RP1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(Enumeration::RLWEParameters::RLWES2Q12289N2048, m_rngPtr);
		IAsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> pk3 = ((RLWEPublicKey*)kp2->PublicKey())->P();
		pk3[0] += 1;
		pk3[1] += 1;
		RLWEPublicKey* pk4 = new RLWEPublicKey(Enumeration::RLWEParameters::RLWES2Q12289N2048, pk3);
		cpr2.Initialize(pk4);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("RLWE"), std::string("Public key integrity test failed! -RP2"));
		}

		delete kp2;
	}

	void RingLWETest::Serialization()
	{
		std::vector<byte> skey(0);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(Enumeration::RLWEParameters::RLWES1Q12289N1024, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			IAsymmetricKeyPair* kp = cpr1.Generate();
			RLWEPrivateKey* priK1 = (RLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			RLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("RLWE"), std::string("Private key serialization test has failed! -RS1"));
			}

			RLWEPublicKey* pubK1 = (RLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			RLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException(std::string("RLWE"), std::string("Public key serialization test has failed! -RS2"));
			}
		}

		skey.resize(0);

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(Enumeration::RLWEParameters::RLWES2Q12289N2048, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			IAsymmetricKeyPair* kp = cpr2.Generate();
			RLWEPrivateKey* priK1 = (RLWEPrivateKey*)kp->PrivateKey();
			skey = priK1->ToBytes();
			RLWEPrivateKey priK2(skey);

			if (priK1->R() != priK2.R() || priK1->Parameters() != priK2.Parameters())
			{
				throw TestException(std::string("RLWE"), std::string("Private key serialization test has failed! -RS1"));
			}

			RLWEPublicKey* pubK1 = (RLWEPublicKey*)kp->PublicKey();
			skey = pubK1->ToBytes();
			RLWEPublicKey pubK2(skey);

			if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
			{
				throw TestException(std::string("RLWE"), std::string("Public key serialization test has failed! -RS2"));
			}
		}
	}

	void RingLWETest::Stress()
	{
		std::vector<byte> msg(128);
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: RLWES1Q12289N1024
		RingLWE cpr1(Enumeration::RLWEParameters::RLWES1Q12289N1024, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			m_rngPtr->Generate(msg);
			IAsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);
			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("RLWE"), std::string("Stress test authentication has failed! -RR1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("RLWE"), std::string("Stress test has failed! -RR2"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		// test param 2: RLWES2Q12289N2048
		RingLWE cpr2(Enumeration::RLWEParameters::RLWES2Q12289N2048, m_rngPtr);

		for (size_t i = 0; i < TEST_CYCLES / 2; ++i)
		{
			m_rngPtr->Generate(msg);
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("RLWE"), std::string("Stress test authentication has failed! -RR3"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("RLWE"), std::string("Stress test has failed! -RR4"));
			}
		}
	}

	void RingLWETest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
