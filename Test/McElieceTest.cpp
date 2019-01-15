#include "McElieceTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/McEliece.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Asymmetric;
	using namespace Asymmetric::Encrypt::MPKC;
	using Enumeration::MPKCParameters;
	using Prng::SecureRandom;

	const std::string McElieceTest::CLASSNAME = "McElieceTest";
	const std::string McElieceTest::DESCRIPTION = "McEliece key generation, encryption, and decryption tests.";
	const std::string McElieceTest::SUCCESS = "SUCCESS! McEliece tests have executed succesfully.";

	McElieceTest::McElieceTest()
		:
		m_progressEvent()
	{
	}

	McElieceTest::~McElieceTest()
	{
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
			Authentication();
			OnProgress(std::string("McElieceTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("McElieceTest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("McElieceTest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("McElieceTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("McElieceTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("McElieceTest: Passed encryption and decryption stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void McElieceTest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		SecureRandom gen;
		McEliece cpr(MPKCParameters::MPKCS1M12T62);
		AsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr.Name(), std::string("Message authentication test failed! -MA1"));
		}

		delete kp;
	}

	void McElieceTest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;
		McEliece cpr(MPKCParameters::MPKCS1M12T62);
		AsymmetricKeyPair* kp = cpr.Generate();

		cpr.Initialize(kp->PublicKey());
		cpr.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr.Name(), std::string("Cipher text integrity test failed! -MC1"));
		}
			
		delete kp;
	}

	void McElieceTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			McEliece cpr(MPKCParameters::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME1"));
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
			McEliece cpr(MPKCParameters::MPKCS1M12T62, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME2"));
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
			McEliece cpr(MPKCParameters::MPKCS1M12T62, Enumeration::Prngs::BCR);
			Asymmetric::Encrypt::RLWE::RingLWE cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			cpr.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void McElieceTest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		McEliece cpr(MPKCParameters::MPKCS1M12T62);
		AsymmetricKeyPair* kp = cpr.Generate();

		// alter public key
		std::vector<byte> pk1 = kp->PublicKey()->P();
		pk1[0] += 1;
		pk1[1] += 1;

		AsymmetricKey* pk2 = new AsymmetricKey(AsymmetricEngines::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MPKCParameters::MPKCS1M12T62), pk1);
		cpr.Initialize(pk2);
		cpr.Encapsulate(cpt, sec1);

		cpr.Initialize(kp->PrivateKey());

		if (cpr.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr.Name(), std::string("Public key integrity test failed! -MP1"));
		}

		delete kp;
	}

	void McElieceTest::Serialization()
	{
		std::vector<byte> pkey;
		std::vector<byte> skey;

		McEliece cpr(MPKCParameters::MPKCS1M12T62);
		AsymmetricKeyPair* kp = cpr.Generate();
		AsymmetricKey* priK1 = kp->PrivateKey();
		skey = priK1->ToBytes();
		AsymmetricKey priK2(skey);

		if (priK1->P() != priK2.P() || priK1->Parameters() != priK2.Parameters())
		{
			throw TestException(std::string("Serialization"), cpr.Name(), std::string("Private key serialization test has failed! -MR1"));
		}

		AsymmetricKey* pubK1 = kp->PublicKey();
		pkey = pubK1->ToBytes();
		AsymmetricKey pubK2(pkey);

		if (pubK1->P() != pubK2.P() || pubK1->Parameters() != pubK2.Parameters())
		{
			throw TestException(std::string("Serialization"), cpr.Name(), std::string("Public key serialization test has failed! -MR2"));
		}

		delete kp;
		delete priK1;
		delete pubK1;
	}

	void McElieceTest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;
		McEliece cpr(MPKCParameters::MPKCS1M12T62);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr.Generate();
			cpr.Initialize(kp->PublicKey());
			cpr.Encapsulate(cpt, sec1);

			cpr.Initialize(kp->PrivateKey());

			if (!cpr.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr.Name(), std::string("Stress test authentication has failed! -MS1"));
			}

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr.Name(), std::string("Stress test has failed! -MS2"));
			}
		}
	}

	void McElieceTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
