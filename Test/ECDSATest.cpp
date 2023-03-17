#include "ECDSATest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/ECDSA.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Kyber.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Sign::ECDSA::ECDSA;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Enumeration::ECDSAParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Prng::SecureRandom;
	using CEX::Tools::IntegerTools;

	const std::string ECDSATest::CLASSNAME = "ECDSATest";
	const std::string ECDSATest::DESCRIPTION = "ECDSATest key generation, signature generation, and verification tests..";
	const std::string ECDSATest::SUCCESS = "SUCCESS! ECDSATest tests have executed succesfully.";

	ECDSATest::ECDSATest()
		:
		m_msgexp(0),
		m_pubexp(0),
		m_priexp(0),
		m_rngseed(0),
		m_sigexp(0),
		m_progressEvent()
	{
	}

	ECDSATest::~ECDSATest()
	{
		IntegerTools::Clear(m_msgexp);
		IntegerTools::Clear(m_pubexp);
		IntegerTools::Clear(m_priexp);
		IntegerTools::Clear(m_rngseed);
		IntegerTools::Clear(m_sigexp);
	}

	const std::string ECDSATest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ECDSATest::Progress()
	{
		return m_progressEvent;
	}

	std::string ECDSATest::Run()
	{
		try
		{
			Initialize();

			Integrity();
			OnProgress(std::string("ECDSATest: Passed signature, message verification, public and private key known answer tests.."));
			Kat();
			OnProgress(std::string("ECDSATest: Passed signature cipher-text and message verification known answer tests.."));
			Authentication();
			OnProgress(std::string("ECDSATest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("ECDSATest: Passed exception handling test.."));
			PrivateKey();
			OnProgress(std::string("ECDSATest: Passed private key integrity test.."));
			PublicKey();
			OnProgress(std::string("ECDSATest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("ECDSATest: Passed key serialization tests.."));
			Signature();
			OnProgress(std::string("ECDSATest: Passed signature tamper test.."));
			Stress();
			OnProgress(std::string("ECDSATest: Passed encryption and decryption stress tests.."));

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
			throw TestException(CLASSNAME, std::string("Unknown Function"), std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void ECDSATest::Authentication()
	{
		ECDSA sgn1(ECDSAParameters::ECDSAS2P25519S);
		ECDSA sgn2(ECDSAParameters::ECDSAS2P25519S);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);
		SecureRandom rnd;
		bool ret;

		rnd.Generate(msg1);

		AsymmetricKeyPair* kp = sgn1.Generate();
		sgn1.Initialize(kp->PrivateKey());
		sgn1.Sign(msg1, sig);
		sgn2.Initialize(kp->PublicKey());
		ret = sgn2.Verify(sig, msg2);

		if (msg1 != msg2)
		{
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -DA1"));
		}
		if (ret != true)
		{
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -DA1"));
		}
	}

	void ECDSATest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			ECDSA sgn(ECDSAParameters::None);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// invalid prng type
		try
		{
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// null prng
		try
		{
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S, nullptr);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test sign without initialization
		try
		{
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
			sgn.Sign(msg, sig);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE4"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test verify without initialization
		try
		{
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
			sgn.Verify(sig, msg);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE5"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization with invalid key
		try
		{
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
			Asymmetric::Encrypt::MLWE::Kyber cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			sgn.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE6"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization with wrong key
		try
		{
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
			AsymmetricKeyPair* kp = sgn.Generate();
			sgn.Initialize(kp->PublicKey());
			sgn.Sign(msg, sig);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -DE7"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ECDSATest::Integrity()
	{
		std::vector<uint8_t> msg(0);
		std::vector<uint8_t> sig(0);

		ECDSA sgn1(ECDSAParameters::ECDSAS2P25519S);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn1.Generate(m_rngseed[0]);

		// verify private and public keys
		if (kp->PublicKey()->Polynomial() != m_pubexp[4])
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Public key does not match expected! -DI1"));
		}

		if (kp->PrivateKey()->Polynomial() != m_priexp[4])
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Private key does not match expected! -DI2"));
		}

		delete kp;
	}

	void ECDSATest::Kat()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> msg(0);
		std::vector<uint8_t> sig(0);
		size_t i;

		ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate(m_rngseed[0]);

		if (kp->PrivateKey()->Polynomial() != m_priexp[4])
		{
			throw TestException(std::string("Kat"), sgn.Name(), std::string("Private key generated doesn not match expected! -EK1"));
		}

		if (kp->PublicKey()->Polynomial() != m_pubexp[4])
		{
			throw TestException(std::string("Kat"), sgn.Name(), std::string("Public key generated doesn not match expecte! -EK2"));
		}

		for (i = 0; i < 3; ++i)
		{
			AsymmetricKey* pri = new AsymmetricKey(m_priexp[i], AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(ECDSAParameters::ECDSAS2P25519S));
			
			// initialize and sign
			sgn.Initialize(pri);
			sgn.Sign(m_msgexp[i], sig);

			if (sig != m_sigexp[i])
			{
				throw TestException(std::string("Kat"), sgn.Name(), std::string("Signature does not match expected! -EK3"));
			}

			delete pri;

			AsymmetricKey* pub = new AsymmetricKey(m_pubexp[i], AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(ECDSAParameters::ECDSAS2P25519S));

			// initialize and verify
			sgn.Initialize(pub);

			// verify and test for expected message
			if (!sgn.Verify(sig, msg))
			{
				throw TestException(std::string("Kat"), sgn.Name(), std::string("Failed signature verification test! -EK4"));
			}

			if (msg != m_msgexp[i])
			{
				throw TestException(std::string("Kat"), sgn.Name(), std::string("Messages does not match expected! -EK5"));
			}

			delete pub;
		}
	}

	void ECDSATest::PrivateKey()
	{
		SecureRandom gen;
		ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);
		size_t i;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// generate a random message
			gen.Generate(msg1);
			// create the key-pair
			AsymmetricKeyPair* kp = sgn.Generate();

			// alter the private key
			std::vector<uint8_t> skv = kp->PrivateKey()->Polynomial();
			skv[skv.size() - 1] ^= 1U;

			AsymmetricKey* sk = new AsymmetricKey(skv, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(ECDSAParameters::ECDSAS2P25519S));

			// sign the message with altered key
			sgn.Initialize(sk);
			sgn.Sign(msg1, sig);

			sgn.Initialize(kp->PublicKey());

			// test for sign fail-over
			if (sgn.Verify(sig, msg2))
			{
				throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -DS1"));
			}

			delete kp;
			delete sk;
		}
	}

	void ECDSATest::PublicKey()
	{
		SecureRandom gen;
		ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> seed(32);
		std::vector<uint8_t> sig(0);
		size_t i;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// generate a random message
			gen.Generate(msg1);
			// create the key-pair
			AsymmetricKeyPair* kp = sgn.Generate();

			// alter public key
			std::vector<uint8_t> pkv = kp->PublicKey()->Polynomial();
			pkv[pkv.size() - 1] ^= 1U;

			AsymmetricKey* pk = new AsymmetricKey(pkv, AsymmetricPrimitives::ECDSA, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(ECDSAParameters::ECDSAS2P25519S));

			// sign the message
			sgn.Initialize(kp->PrivateKey());
			sgn.Sign(msg1, sig);

			// initialize verify with altered key
			sgn.Initialize(pk);

			// test for sign fail-over
			if (sgn.Verify(sig, msg2))
			{
				throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -DP1"));
			}

			delete kp;
			delete pk;
		}
	}

	void ECDSATest::Serialization()
	{
		ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
		SecureVector<uint8_t> skey(0);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			// test private key serialization
			AsymmetricKeyPair* kp = sgn.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			// compare the serialized/deserialized keys
			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Private key serialization test has failed! -DR1"));
			}

			delete prik1;
			delete prik2;

			// public key serialization
			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Public key serialization test has failed! -DR2"));
			}

			delete pubk1;
			delete pubk2;
		}
	}

	void ECDSATest::Signature()
	{
		SecureRandom gen;
		ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		// alter the signature
		gen.Generate(sig, 0, 16);

		sgn.Initialize(kp->PublicKey());

		// test for sign fail-over
		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Public key integrity test failed! -DS1"));
		}
	}

	void ECDSATest::Stress()
	{
		SecureRandom gen;
		ECDSA sgn1(ECDSAParameters::ECDSAS2P25519S);
		std::vector<uint8_t> msg1(0);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);
		size_t msglen;
		bool status;

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			// test random-variable sized messages
			msglen = gen.NextUInt32(128, 16);
			msg1.resize(msglen);

			AsymmetricKeyPair* kp = sgn1.Generate();

			// sign and verify
			sgn1.Initialize(kp->PrivateKey());
			sgn1.Sign(msg1, sig);

			sgn1.Initialize(kp->PublicKey());
			status = sgn1.Verify(sig, msg2);

			// test the verification status, and message equivalency
			if (!status)
			{
				throw TestException(std::string("Stress"), sgn1.Name(), std::string("Stress test authentication has failed! -DR1"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), std::string("ECDSA"), std::string("Stress test authentication has failed! -DR2"));
			}

			status = false;
		}
	}

	void ECDSATest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> msgexp =
		{
			std::string("A750C232933DC14B1184D86D8B4CE72E16D69744BA69818B6AC33B1D823BB2C3"),
			std::string("4BAFDAC9099D4057ED6DD08BCAEE8756E9A40F2CB9598020EB95019528409BBE"
				"A38B384A59F119F57297BFB2FA142FC7BB1D90DBDDDE772BCDE48C5670D5FA13"),
			std::string("FE6C1A31068E332D12AAB37D99406568DEAA36BDB277CEE55304633BD0A267A8"
				"50E203BB3FABE5110BCC1CA4316698AB1CF00F0B0F1D97EF2180887F0EC0991E"
				"8C1111F0C0E1D2B712433AD2B3071BD66E1D81F7FA47BB4BB31AC0F059BB3CB8"),
			std::string("F7E67D982A2FF93ECDA4087152B4864C943B1BA7021F5407043CCB4253D348C2"
				"7B9283ACB26C194FD1CBB79E6AFC32FF686B55B0B3617218DCF39316B4B66B3C"
				"8C0D67267A86DB8ADF3750801BCF9327D4C25441B96197832B4CDE0EAC3FF228"
				"92A2F0BC17C2C213C02377A333E308ED271658049383B7E2E57B6B8B125512E0")
		};
		HexConverter::Decode(msgexp, 4, m_msgexp);

		const std::vector<std::string> pubexp =
		{
			std::string("B49F3A78B1C6A7FCA8F3466F33BC0E929F01FBA04306C2A7465F46C3759316D9"),
			std::string("F73FA076F84B6DB675A5FDA5AD67E351A41E8E7F29ADD16809CA010387E9C6CC"),
			std::string("6FF19B1F18D64851D5C74845C6407F0BF596A52E385E020127E83E54CFF5AC19"),
			std::string("98BE21001993A7EB1A1277FF74C15504183D25FDFCC05F0D4DEA892F6E301890"),
			std::string("B5076A8474A832DAEE4DD5B4040983B6623B5F344ACA57D4D6EE4BAF3F259E6E")
		};
		HexConverter::Decode(pubexp, 5, m_pubexp);

		const std::vector<std::string> priexp =
		{
			std::string("8ED7A797B9CEA8A8370D419136BCDF683B759D2E3C6947F17E13E2485AA9D420"
				"B49F3A78B1C6A7FCA8F3466F33BC0E929F01FBA04306C2A7465F46C3759316D9"),
			std::string("BA4D6E67B2CE67A1E44326494044F37A442F3B81725BC1F9341462718B55EE20"
				"F73FA076F84B6DB675A5FDA5AD67E351A41E8E7F29ADD16809CA010387E9C6CC"),
			std::string("3ADCE3A3D3FBC977DD4B300A74749F13A3B04A5D73A2CD75A994E3195EFEBDAC"
				"6FF19B1F18D64851D5C74845C6407F0BF596A52E385E020127E83E54CFF5AC19"),
			std::string("8400962BB769F63868CAE5A3FEC8DB6A9C8D3F1C846C8DCEEB642B6946EFA8E3"
				"98BE21001993A7EB1A1277FF74C15504183D25FDFCC05F0D4DEA892F6E301890"),
			std::string("421151A459FAEADE3D247115F94AEDAE42318124095AFABE4D1451A559FAEDEE"
				"B5076A8474A832DAEE4DD5B4040983B6623B5F344ACA57D4D6EE4BAF3F259E6E")
		};
		HexConverter::Decode(priexp, 5, m_priexp);

		const std::vector<std::string> rngseed =
		{
			std::string("421151A459FAEADE3D247115F94AEDAE42318124095AFABE4D1451A559FAEDEE"),
			std::string("421151A459FAEADE3D247115F94AEDAE42318124095AFABE4D1451A559FAEDEE")
		};
		HexConverter::Decode(rngseed, 2, m_rngseed);

		const std::vector<std::string> sigexp =
		{
			std::string("04266C033B91C1322CEB3446C901FFCF3CC40C4034E887C9597CA1893BA7330B"
				"ECBBD8B48142EF35C012C6BA51A66DF9308CB6268AD6B1E4B03E70102495790B"
				"A750C232933DC14B1184D86D8B4CE72E16D69744BA69818B6AC33B1D823BB2C3"),
			std::string("57B9D2A711207F837421BAE7DD48EAA18EAB1A9A70A0F1305806FEE17B458F3A"
				"0964B302D1834D3E0AC9E8496F000B77F0083B41F8A957E632FBC7840EEE6A06"
				"4BAFDAC9099D4057ED6DD08BCAEE8756E9A40F2CB9598020EB95019528409BBE"
				"A38B384A59F119F57297BFB2FA142FC7BB1D90DBDDDE772BCDE48C5670D5FA13"),
			std::string("7DDA89F85B40539F5AD8C6DE4953F7094A715B63DDA30EC7CF65A785CEAE5FC6"
				"88707EE00BE682CECBE7EE37D8FC39EE6D83C64409681708A0898A183B288A06"
				"FE6C1A31068E332D12AAB37D99406568DEAA36BDB277CEE55304633BD0A267A8"
				"50E203BB3FABE5110BCC1CA4316698AB1CF00F0B0F1D97EF2180887F0EC0991E"
				"8C1111F0C0E1D2B712433AD2B3071BD66E1D81F7FA47BB4BB31AC0F059BB3CB8"),
			std::string("0AD71B0025F3D9A50DB338414D6D670E7799B7270A8444F6AE7F12AE7EB71BD0"
				"3FFD3C4F36631F69FDCC4061468FF582EDE495243EF1361A3B3295FA813BA205"
				"F7E67D982A2FF93ECDA4087152B4864C943B1BA7021F5407043CCB4253D348C2"
				"7B9283ACB26C194FD1CBB79E6AFC32FF686B55B0B3617218DCF39316B4B66B3C"
				"8C0D67267A86DB8ADF3750801BCF9327D4C25441B96197832B4CDE0EAC3FF228"
				"92A2F0BC17C2C213C02377A333E308ED271658049383B7E2E57B6B8B125512E0")
		};
		HexConverter::Decode(sigexp, 4, m_sigexp);

		/*lint -restore */
	}

	void ECDSATest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
