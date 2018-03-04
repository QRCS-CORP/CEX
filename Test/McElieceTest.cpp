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
	using namespace Cipher::Asymmetric::McEliece;

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
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(true, kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		m_rngPtr->GetBytes(cpt, 0, 4);

		cpr.Initialize(false, kp->PrivateKey());

		try
		{
			cpr.Decapsulate(cpt, sec2);
		}
		catch (Exception::CryptoAuthenticationFailure)
		{
			// passed
			delete kp;
			return;
		}

		throw TestException("McElieceTest: Cipher-text integrity test failed!");
	}

	void McElieceTest::MessageAuthentication()
	{
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(128);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
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

		throw TestException("McElieceTest: Message authentication test failed!");
	}

	void McElieceTest::PublicKeyIntegrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);

		McEliece cpr(Enumeration::MPKCParams::M12T62, m_rngPtr);
		IAsymmetricKeyPair* kp = cpr.Generate();

		// alter public key (proportionate to large pk)
		std::vector<byte> p2 = ((MPKCPublicKey*)kp->PublicKey())->P();
		m_rngPtr->GetBytes(p2, 0, 4096);
		MPKCPublicKey* pk2 = new MPKCPublicKey(Enumeration::MPKCParams::M12T62, p2);
		cpr.Initialize(true, pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(false, kp->PrivateKey());

		try
		{
			cpr.Decapsulate(cpt, sec2);
		} 
		catch (Exception::CryptoAsymmetricException)
		{
		}
		catch (Exception::CryptoAuthenticationFailure)
		{
		}

		if (sec1 == sec2)
		{
			throw TestException("McElieceTest: PublicKey integrity test failed!");
		}
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
		std::vector<byte> enc;
		std::vector<byte> dec(128);
		std::vector<byte> msg(128);

		const std::vector<byte> test1(32);
		std::vector<byte> test2(32, (byte)255);
		std::memcpy((byte*)test1.data(), test2.data(), 32);

		McEliece cpr1(Enumeration::MPKCParams::M12T62, m_rngPtr);

		// test the encrypt/decrypt api
		for (size_t i = 0; i < 10; ++i)
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
				throw TestException("McElieceTest: Stress test has failed!");
			}
		}

		std::vector<byte> cpt(0);
		std::vector<byte> sec1(0);
		std::vector<byte> sec2(0);
		McEliece cpr2(Enumeration::MPKCParams::M12T62, m_rngPtr);

		for (size_t i = 0; i < 10; ++i)
		{
			IAsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(true, kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(false, kp->PrivateKey());
			cpr2.Decapsulate(cpt, sec2);

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
