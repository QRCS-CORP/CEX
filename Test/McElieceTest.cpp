#include "McElieceTest.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/McEliece.h"
#include "../CEX/MPKCKeyPair.h"
#include "../CEX/MPKCPrivateKey.h"
#include "../CEX/MPKCPublicKey.h"
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using namespace Cipher::Asymmetric::MPKC;

	const std::string McElieceTest::DESCRIPTION = "McEliece key generation, encryption, and decryption tests.";
	const std::string McElieceTest::FAILURE = "FAILURE! ";
	const std::string McElieceTest::SUCCESS = "SUCCESS! McEliece tests have executed succesfully.";

	McElieceTest::McElieceTest()
		:
		m_progressEvent(),
		m_rngPtr(new Prng::BCR)
	{
	}

	McElieceTest::~McElieceTest()
	{
		delete m_rngPtr;
	}

	const std::string McElieceTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &McElieceTest::Progress()
	{
		return m_progressEvent;
	}

	std::string McElieceTest::Run()
	{
		try
		{
			CipherTextIntegrity();
			OnProgress(std::string("McElieceTest: Passed cipher-text integrity test.."));
			MessageAuthentication();
			OnProgress(std::string("McElieceTest: Passed message authentication test.."));
			PublicKeyIntegrity();
			OnProgress(std::string("McElieceTest: Passed public key integrity test.."));
			StressLoop();
			OnProgress(std::string("McElieceTest: Passed encryption and decryption stress tests.."));
			SerializationCompare();
			OnProgress(std::string("McElieceTest: Passed key serialization tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void McElieceTest::CipherTextIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("McElieceTest: Cipher-text integrity test failed!");
		}
			
		delete kp;
	}

	void McElieceTest::MessageAuthentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("McElieceTest: Message authentication test failed!");
		}

		delete kp;
	}

	void McElieceTest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> pk1 = ((MPKCPublicKey*)kp->PublicKey())->P();
		pk1[0] += 1;
		pk1[1] += 1;

		MPKCPublicKey* pk2 = new MPKCPublicKey(Enumeration::MPKCParams::M12T62, pk1);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException("McElieceTest: Public-key integrity test failed!");
		}

		delete kp;
	}

	void McElieceTest::SerializationCompare()
	{
		std::vector<byte> pkey;
		std::vector<byte> skey;

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();
		MPKCPrivateKey* priK1 = (MPKCPrivateKey*)kp->PrivateKey();
		skey = priK1->ToBytes();
		MPKCPrivateKey priK2(skey);

		if (priK1->S() != priK2.S() || priK1->Parameters() != priK2.Parameters())
		{
			throw TestException("McElieceTest: Private key serialization test has failed!");
		}

		MPKCPublicKey* pubK1 = (MPKCPublicKey*)kp->PublicKey();
		pkey = pubK1->ToBytes();
		MPKCPublicKey pubK2(pkey);

		if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
		{
			throw TestException("McElieceTest: Public key serialization test has failed!");
		}

		delete kp;
		delete priK1;
		delete pubK1;
	}

	void McElieceTest::StressLoop()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);

		for (size_t i = 0; i < 10; ++i)
		{
			IAsymmetricKeyPair* kp = cpr.Generate();

			cpr.Initialize(kp->PublicKey());
			cpr.Encapsulate(cpt, sec1);

			cpr.Initialize(kp->PrivateKey());

			if (!cpr.Decapsulate(cpt, sec2))
			{
				throw TestException("McElieceTest: Stress test authentication has failed!");
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException("McElieceTest: Stress test has failed!");
			}
		}
	}

	void McElieceTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
