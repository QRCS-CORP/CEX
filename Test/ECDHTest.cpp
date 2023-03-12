#include "ECDHTest.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/ECDH.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Encrypt::ECDH::ECDH;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Enumeration::ECDHParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Prng::SecureRandom;
	using CEX::Tools::IntegerTools;
	using Test::NistRng;

	const std::string ECDHTest::CLASSNAME = "ECDHTest";
	const std::string ECDHTest::DESCRIPTION = "ECDH key generation, encryption, and decryption tests..";
	const std::string ECDHTest::SUCCESS = "SUCCESS! ECDH tests have executed succesfully.";

	ECDHTest::ECDHTest()
		:
		m_pubexp(0),
		m_priexp(0),
		m_rngseed(0),
		m_sskexp(0),
		m_progressEvent()
	{
	}

	ECDHTest::~ECDHTest()
	{
		IntegerTools::Clear(m_priexp);
		IntegerTools::Clear(m_pubexp);
		IntegerTools::Clear(m_rngseed);
		IntegerTools::Clear(m_sskexp);
	}

	const std::string ECDHTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ECDHTest::Progress()
	{
		return m_progressEvent;
	}

	std::string ECDHTest::Run()
	{
		try
		{
			Initialize();

			Authentication();
			OnProgress(std::string("ECDHTest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("ECDHTest: Passed exception handling test.."));
			Integrity();
			OnProgress(std::string("ECDHTest: Passed ciphertext, shared-secret, public and private key known answer tests.."));
			Kat();
			OnProgress(std::string("ECDHTest: Passed shared-secret known answer tests.."));
			PublicKey();
			OnProgress(std::string("ECDHTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("ECDHTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("ECDHTest: Passed encryption and decryption stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void ECDHTest::Authentication()
	{
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		ECDH cpr2(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr1.KeyExchange(kp2->PublicKey(), kp1->PrivateKey(), sec1);
		cpr2.KeyExchange(kp1->PublicKey(), kp2->PrivateKey(), sec2);

		if (sec1 != sec2)
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -EA1"));
		}

		delete kp1;
		delete kp2;
	}

	void ECDHTest::Integrity()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp1 = cpr1.Generate(m_rngseed[0]);

		if (kp1->PublicKey()->Polynomial() != m_pubexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Public key does not match expected! -MI1"));
		}

		if (kp1->PrivateKey()->Polynomial() != m_priexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Private key does not match expected! -MI2"));
		}

		delete kp1;
	}

	void ECDHTest::Kat()
	{
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp1 = cpr1.Generate(m_rngseed[0]);

		if (kp1->PublicKey()->Polynomial() != m_pubexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The public key does not match the expected answer! -EK1"));
		}

		if (kp1->PrivateKey()->Polynomial() != m_priexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The private key does not match the expected answer! -EK2"));
		}

		ECDH cpr2(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp2 = cpr2.Generate(m_rngseed[1]);

		if (kp2->PublicKey()->Polynomial() != m_pubexp[1])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The public key does not match the expected answer! -EK3"));
		}

		if (kp2->PrivateKey()->Polynomial() != m_priexp[1])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The private key does not match the expected answer! -EK4"));
		}

		cpr1.KeyExchange(kp2->PublicKey(), kp1->PrivateKey(), sec1);
		cpr2.KeyExchange(kp1->PublicKey(), kp2->PrivateKey(), sec2);

		if (sec1 != sec2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The shared secret is not equal! -EK5"));
		}

		if (sec1 != m_sskexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("The shared secret does not match the expected answer! -EK5"));
		}

		delete kp1;
		delete kp2;
	}

	void ECDHTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			ECDH cpr(ECDHParameters::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -EE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ECDHTest::PublicKey()
	{
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		// test param 1: ECDHS2EC25519S
		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		ECDH cpr2(ECDHParameters::ECDHS2EC25519S);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<uint8_t> plm = kp1->PublicKey()->Polynomial();
		plm[0] += 1;
		plm[1] += 1;
		AsymmetricKey* pk = new AsymmetricKey(plm, AsymmetricPrimitives::ECDH, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(ECDHParameters::ECDHS2EC25519S));

		cpr1.KeyExchange(pk, kp1->PrivateKey(), sec1);
		cpr2.KeyExchange(kp1->PublicKey(), kp2->PrivateKey(), sec2);

		if (sec1 == sec2)
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Altered public key produces same secret! -EA1"));
		}

		delete kp1;
		delete kp2;
		delete pk;
	}

	void ECDHTest::Serialization()
	{
		SecureVector<uint8_t> skey(0);
		size_t i;

		// test param 1: ECDHS2EC25519S
		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -ER1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Public key serialization test has failed! -ER2"));
			}

			delete kp;
			delete prik2;
			delete pubk2;
		}

		skey.clear();
	}

	void ECDHTest::Stress()
	{
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);
		std::vector<uint8_t> seed1(32);
		std::vector<uint8_t> seed2(32);
		SecureRandom gen;
		size_t i;

		ECDH cpr1(ECDHParameters::ECDHS2EC25519S);
		ECDH cpr2(ECDHParameters::ECDHS2EC25519S);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			gen.Generate(seed1);
			gen.Generate(seed2);

			AsymmetricKeyPair* kp1 = cpr1.Generate(seed1);
			AsymmetricKeyPair* kp2 = cpr2.Generate(seed2);

			cpr1.KeyExchange(kp2->PublicKey(), kp1->PrivateKey(), sec1);
			cpr2.KeyExchange(kp1->PublicKey(), kp2->PrivateKey(), sec2);

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("The stress test has failed! -ES1"));
			}

			delete kp1;
			delete kp2;
		}
	}

	void ECDHTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> pubexp =
		{
			std::string("4701D08488451F545A409FB58AE3E58581CA40AC3F7F114698CD71DEAC73CA01"),
			std::string("5730800AB340FCB18CE5111EDA9D705F91388B41E4544CBD103BA5942DB2233E")
		};
		HexConverter::Decode(pubexp, 2, m_pubexp);

		const std::vector<std::string> priexp =
		{
			std::string("3D94EEA49C580AEF816935762BE049559D6D1440DEDE12E6A125F1841FFF8E6F"
				"0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("887AF58A36202E05C4C1CFEC5BF6C61FAD66BCA851536004074B31F1B56E4AC9"
				"0000000000000000000000000000000000000000000000000000000000000000")
		};
		HexConverter::Decode(priexp, 2, m_priexp);

		const std::vector<std::string> sskexp =
		{
			std::string("F6F92EFB32945AFF683324A1C984C5001F46AAEA513F3453138D740B3A604B7D"),
			std::string("F6F92EFB32945AFF683324A1C984C5001F46AAEA513F3453138D740B3A604B7D")
		};
		HexConverter::Decode(sskexp, 2, m_sskexp);

		const std::vector<std::string> rngseed =
		{
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")
		};
		HexConverter::Decode(rngseed, 2, m_rngseed);

		/*lint -restore */
	}

	void ECDHTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
