#include "RainbowTest.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Kyber.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/Rainbow.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Enumeration::AsymmetricKeyTypes;
	using Enumeration::AsymmetricPrimitives;
	using Enumeration::AsymmetricParameters;
	using Exception::CryptoAsymmetricException;
	using Utility::IntegerTools;
	using Test::NistRng;
	using Prng::SecureRandom;
	using Asymmetric::Sign::RNBW::Rainbow;
	using Enumeration::RainbowParameters;

	const std::string RainbowTest::CLASSNAME = "RainbowTest";
	const std::string RainbowTest::DESCRIPTION = "RainbowTest key generation, signature generation, and verification tests..";
	const std::string RainbowTest::SUCCESS = "SUCCESS! RainbowTest tests have executed succesfully.";

	RainbowTest::RainbowTest()
		:
		m_msgexp(0),
		m_pubexp(0),
		m_priexp(0),
		m_rngseed(0),
		m_sigexp(0),
		m_progressEvent()
	{
	}

	RainbowTest::~RainbowTest()
	{
		IntegerTools::Clear(m_msgexp);
		IntegerTools::Clear(m_pubexp);
		IntegerTools::Clear(m_priexp);
		IntegerTools::Clear(m_rngseed);
		IntegerTools::Clear(m_sigexp);
	}

	const std::string RainbowTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RainbowTest::Progress()
	{
		return m_progressEvent;
	}

	std::string RainbowTest::Run()
	{
		try
		{
			Initialize();

			Integrity();
			OnProgress(std::string("RainbowTest: Passed signature, message verification, public and private key known answer tests.."));
			Kat();
			OnProgress(std::string("RainbowTest: Passed signature cipher-text and message verification known answer tests.."));
			Authentication();
			OnProgress(std::string("RainbowTest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("RainbowTest: Passed exception handling test.."));
			PrivateKey();
			OnProgress(std::string("RainbowTest: Passed private key integrity test.."));
			PublicKey();
			OnProgress(std::string("RainbowTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("RainbowTest: Passed key serialization tests.."));
			Signature();
			OnProgress(std::string("RainbowTest: Passed signature tamper test.."));
			Stress();
			OnProgress(std::string("RainbowTest: Passed encryption and decryption stress tests.."));

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

	void RainbowTest::Authentication()
	{
		Rainbow sgn1(RainbowParameters::RNBWS1S128SHAKE256);
		Rainbow sgn2(RainbowParameters::RNBWS1S128SHAKE256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
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
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -SA1"));
		}
		if (ret != true)
		{
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -SA1"));
		}
	}

	void RainbowTest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			Rainbow sgn(Enumeration::RainbowParameters::None);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE1"));
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
			Rainbow sgn(Enumeration::RainbowParameters::RNBWS1S128SHAKE256, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE2"));
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
			//Rainbow sgn(Enumeration::RainbowParameters::RNBWS1S128SHAKE256, nullptr);

			//throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE3"));
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
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
			sgn.Sign(msg, sig);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE4"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test verif without initialization
		try
		{
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
			sgn.Verify(sig, msg);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE5"));
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
			Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
			Asymmetric::Encrypt::MLWE::Kyber cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			sgn.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE6"));
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
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
			AsymmetricKeyPair* kp = sgn.Generate();
			sgn.Initialize(kp->PublicKey());
			sgn.Sign(msg, sig);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE7"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RainbowTest::Integrity()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> msg(0);
		std::vector<byte> sig(0);
		NistRng gen;

		// RNBWS1S128SHAKE256

		gen.Initialize(m_rngseed);

		Rainbow sgn1(RainbowParameters::RNBWS1S128SHAKE256, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp1 = sgn1.Generate();

		// verify private and public keys
		if (!IntegerTools::Compare(kp1->PublicKey()->Polynomial(), 0, m_pubexp[0], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Public key does not match expected! -RI1"));
		}

		if (!IntegerTools::Compare(kp1->PrivateKey()->Polynomial(), 0, m_priexp[0], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Private key does not match expected! -RI2"));
		}

		// initialize and sign
		sgn1.Initialize(kp1->PrivateKey());
		sgn1.Sign(m_msgexp, sig);

		// verify the signature
		if (sig != m_sigexp[0])
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Cipher-text arrays do not match! -RI3"));
		}

		// initialize and verify
		sgn1.Initialize(kp1->PublicKey());

		// verify and test for expected output
		if (!sgn1.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Failed authentication test! -RI4"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Messages do not match! -RI5"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp1;

		// RNBWS2S192SHAKE512

		gen.Initialize(m_rngseed);
		Rainbow sgn2(RainbowParameters::RNBWS2S192SHAKE512, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp2 = sgn2.Generate();

		if (!IntegerTools::Compare(kp2->PublicKey()->Polynomial(), 0, m_pubexp[1], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Public key does not match expected! -RI6"));
		}

		if (!IntegerTools::Compare(kp2->PrivateKey()->Polynomial(), 0, m_priexp[1], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Private key does not match expected! -RI7"));
		}

		// initialize and encapsulate
		sgn2.Initialize(kp2->PrivateKey());
		sgn2.Sign(m_msgexp, sig);

		if (sig != m_sigexp[1])
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Cipher-text arrays do not match! -RI8"));
		}

		// initialize and decapsulate
		sgn2.Initialize(kp2->PublicKey());

		if (!sgn2.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Failed authentication test! -RI9"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Messages do not match! -RI10"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp2;


		// RNBWS3S256SHAKE512

		gen.Initialize(m_rngseed);
		Rainbow sgn3(RainbowParameters::RNBWS3S256SHAKE512, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp3 = sgn3.Generate();

		if (!IntegerTools::Compare(kp3->PublicKey()->Polynomial(), 0, m_pubexp[2], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Public key does not match expected! -RI6"));
		}

		if (!IntegerTools::Compare(kp3->PrivateKey()->Polynomial(), 0, m_priexp[2], 0, 1024))
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Private key does not match expected! -RI7"));
		}

		// initialize and encapsulate
		sgn3.Initialize(kp3->PrivateKey());
		sgn3.Sign(m_msgexp, sig);

		if (sig != m_sigexp[2])
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Cipher-text arrays do not match! -RI8"));
		}

		// initialize and decapsulate
		sgn3.Initialize(kp3->PublicKey());

		if (!sgn3.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Failed authentication test! -RI9"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Messages do not match! -RI10"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp3;
	}

	void RainbowTest::Kat()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> msg(0);
		std::vector<byte> sig(0);
		NistRng gen;

		// RNBWS1S128SHAKE256

		gen.Initialize(m_rngseed);

		Rainbow sgn1(RainbowParameters::RNBWS1S128SHAKE256, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp1 = sgn1.Generate();
		// initialize and sign
		sgn1.Initialize(kp1->PrivateKey());
		sgn1.Sign(m_msgexp, sig);

		// verify the signature
		if (sig != m_sigexp[0])
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Cipher-text arrays do not match! -RK1"));
		}

		// initialize and verify
		sgn1.Initialize(kp1->PublicKey());

		// verify and test for expected output
		if (!sgn1.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Failed authentication test! -RK2"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn1.Name(), std::string("Messages do not match! -RK3"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp1;

		// RNBWS2S192SHAKE512

		gen.Initialize(m_rngseed);
		Rainbow sgn2(RainbowParameters::RNBWS2S192SHAKE512, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp2 = sgn2.Generate();

		// initialize and encapsulate
		sgn2.Initialize(kp2->PrivateKey());
		sgn2.Sign(m_msgexp, sig);

		if (sig != m_sigexp[1])
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Cipher-text arrays do not match! -RK4"));
		}

		// initialize and decapsulate
		sgn2.Initialize(kp2->PublicKey());

		if (!sgn2.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Failed authentication test! -RK5"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn2.Name(), std::string("Messages do not match! -RK6"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp2;


		// RNBWS3S256SHAKE512

		gen.Initialize(m_rngseed);
		Rainbow sgn3(RainbowParameters::RNBWS3S256SHAKE512, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp3 = sgn3.Generate();

		// initialize and encapsulate
		sgn3.Initialize(kp3->PrivateKey());
		sgn3.Sign(m_msgexp, sig);

		if (sig != m_sigexp[2])
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Cipher-text arrays do not match! -RK7"));
		}

		// initialize and decapsulate
		sgn3.Initialize(kp3->PublicKey());

		if (!sgn3.Verify(sig, msg))
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Failed authentication test! -RK8"));
		}

		if (msg != m_msgexp)
		{
			throw TestException(std::string("Integrity"), sgn3.Name(), std::string("Messages do not match! -RK9"));
		}

		cpt.clear();
		msg.clear();
		sig.clear();
		delete kp3;
	}

	void RainbowTest::PublicKey()
	{
		SecureRandom gen;
		Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<byte> pk1 = (kp->PublicKey()->Polynomial());
		gen.Generate(pk1, 0, 16);
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::Rainbow, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(RainbowParameters::RNBWS1S128SHAKE256));

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -XP1"));
		}
	}

	void RainbowTest::PrivateKey()
	{
		SecureRandom gen;
		Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter private key
		std::vector<byte> sk1 = kp->PrivateKey()->Polynomial();
		gen.Generate(sk1, 0, 128);
		AsymmetricKey* sk2 = new AsymmetricKey(sk1, AsymmetricPrimitives::Rainbow, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(RainbowParameters::RNBWS1S128SHAKE256));

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -XS1"));
		}
	}

	void RainbowTest::Serialization()
	{
		Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
		SecureVector<byte> skey(0);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = sgn.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Private key serialization test has failed! -XR1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Public key serialization test has failed! -XR2"));
			}
		}
	}

	void RainbowTest::Signature()
	{
		SecureRandom gen;
		Rainbow sgn(RainbowParameters::RNBWS1S128SHAKE256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		// alter signature
		gen.Generate(sig, msg1.size(), 16);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature test failed! -XS1"));
		}
	}

	void RainbowTest::Stress()
	{
		const size_t CYCLES = TEST_CYCLES == 1 ? 1 : TEST_CYCLES / 2;

		SecureRandom gen;
		Rainbow sgn1(RainbowParameters::RNBWS1S128SHAKE256);
		Rainbow sgn2(RainbowParameters::RNBWS1S128SHAKE256);
		std::vector<byte> msg1(0);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		size_t msglen;
		bool status;

		for (size_t i = 0; i < CYCLES; ++i)
		{
			msglen = gen.NextUInt32(128, 16);
			msg1.resize(msglen);

			AsymmetricKeyPair* kp = sgn1.Generate();

			sgn1.Initialize(kp->PrivateKey());
			sgn1.Sign(msg1, sig);

			sgn1.Initialize(kp->PublicKey());
			status = sgn1.Verify(sig, msg2);

			if (!status)
			{
				throw TestException(std::string("Stress"), sgn1.Name(), std::string("Stress test authentication has failed! -XR1"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn1.Name(), std::string("Stress test authentication has failed! -XR2"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}

		for (size_t i = 0; i < CYCLES; ++i)
		{
			msglen = gen.NextUInt32(128, 16);
			msg1.resize(msglen);

			AsymmetricKeyPair* kp = sgn2.Generate();

			sgn2.Initialize(kp->PrivateKey());
			sgn2.Sign(msg1, sig);

			sgn2.Initialize(kp->PublicKey());
			status = sgn2.Verify(sig, msg2);

			if (!status)
			{
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -XR3"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -XR4"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}
	}

	void RainbowTest::Initialize()
	{
		/*lint -save -e417 */

		HexConverter::Decode(std::string("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8"), m_msgexp);

		const std::vector<std::string> pubexp =
		{
			std::string("21E7A66481C53F059D280DD92FD89D2BE4B9343245FBD1C05437D1A55690276CF43CD233664EC55EDB89FE465750A9A65CF82F1D6CB71222D138C292A0C8BC57"
				"97D6A2D4B23CC410D3696A7BF72C4CE786B6C2B313DEE28C101CC9F6B9A3E414E6558797C368B8267F342DF12AA6B1030D9508EA2C4F5F188F61E4801B126895"
				"2264A4BC704A31282A609E2E947351DB6EA5FD922B46B4ED67138448B931D5BF3CFC866F0CFA98FB6ABDBABEDC6DE2C10E1484EEA7F78D5E06366C2D1F5409A8"
				"844B96F8811D532F345F904FCA39E1F2903C6F9C1BD24032E396EA518E670807643B3AB8FAD1771CF17977A88866F3E85960CF170F3ECBE598F808B8ED6A6CA5"
				"E2B80C9C1647289CEA597BA9801B7DB4C7AAA73AED52F5D718555FA2EA3DDFF33D1BD7F6D5BC794EEDF86E875F36C149E312202B15F9A4D49C4C3268B31BF6B5"
				"8833FF6C24A7F0466B27CAF2733E2F48DECE5DC2EBEF51CACDEE1AC255E4EB9D02D7F411AC26D6CA4D23B24F1E6762C9F9B869A6EDE6303825883214A836792C"
				"6FCC134CEF5A2B0D1E8623163C5A97E799FC494F79299D641B6E9CA678EF3EEA9FDA171F1A78A008D7589CCDFD507B5C22300BD48087404952FDBD30399723E0"
				"8487B348B00BACE9975C9AFB819114A57E5A7856BEF8A96B473FFD57F79996883FEA23B766CD1DE1355DA0C17FEFFA43DB27A7726C40E5E0F9192B69DD1B8CB3"
				"3B35F0B6E18C35DCBF900B43215538A9A011E409622928BA4AEFF4FA952EF96CA4FF532D5A3556BEC3FE6E80425BFEF3CE874B4F4E94F0D2B504AECD40D0B673"
				"7BC3B5FEF8159A380935051A22393B832DBBBDCF9FF50490473BF5AF90123A7FC2834543CA8BACAED5B2FC3FDD6C9A7CC48A165A65FE3EF46A00004C8FA70802"
				"C6E074A3000DBA13468EBE53883FE3FDF2BE813C309C6B790EF97FC1A8B8EEF933A6FB1585E77CB5B61A0F643C1210412A941C26602F1161DFAEAED6E9FF2AE6"
				"A44C3C1942AC1F3D6481925C7F1C5BFB420EA04647B5108B3E93FBD3A1A71A6EA8BB530B424865E3DB193D8A5E430BB1C6B0820A4C5BED20147FF99CDBDCD125"
				"BF8DC2AB892427507ADFD20F001FE2D4D98D408276352ACD0CDA1F430561DCD53C19373B7F80206F8AA342AE42D5B75FBEC28962A14FCC68D0B56381F1F0B5B4"
				"FAA13AB4A10DDF1CEFA4841F141F7370890C1B41535C265EB83B0BEF77837043B303E11A813DE3B9E59715AB38F6B98E2A5A81E678EA884A7649D2B7F9AF6116"
				"6632C6DC0B088E88D349E633EC5378580C426F87ED1D880973DD7B2D509969AD6BC1D2AF042F17176A71BE7B055079D36334F7BA8D20C9781FA0996BAE815976"
				"53C76E4E6A4A9449A2B0DD3D7185A10E30576A88468B92ECC55B4EB2D92174EA30B3BE87B367985B67304FB45A057078FF72FA4CCDA674235DD2D53A0076C187"),
			std::string("3ABF712DE3D2FEC9633CC1724E228F9B044E9507F48A61CF6F0E6CA93C922D8FDEF0C1AB107916757846BC813DAA78AFDFC5120BF654CE9D66DFCB325D2D39DC"
				"75087FCE210238E5736F73D4A5936389312E57FBC4DAF2ABA633455BE5D183FEECC343AD614D2870141463B212EBCDCF0218E4A2699874D5C64CF521CCB32C47"
				"8DD9FEF944A5251883149B10C41FE216F198DF925C30AC7082266EBA7E0B2062496854C71429A31F1F8303CBCEFAA5B2D53F7A73C9F1A1F6599B64DEEE55508D"
				"03C060F83649DD7B3EA1EF182E3B92C5E48CD3BA2F3A5432E89147DF4DEC5779D5EAB71B16978F4051B2DFB774769012E2466044109E681F7B8C1CA0931C1F3B"
				"E480183ABC8C2D2561DB69B45CE7ABD041A8A8CC0B0B2292125998C627EF10245A25C51B23211D80439786B88E9416B5BFFFB3607E81F2A9F0218DE167D8A814"
				"30635FF4CE5A19FED9F774154083DFF3B8CCB25E4C602E22E9E3269F656B7882C0AE9FB6D974D524FCAD5D4F911296027F5246E56842DD913BFFBDBAF264D99C"
				"BB9E01DB45B00590CA26A505A99438B8D7BECC2B0625DF4CC7A153042DDD11A93C0B2846AEE88521743CB2395027274CFA1A0D2B2A9405C2E08C5A6491FFF749"
				"851CADEDB36D07B41D7A115622C9FB07F2C72500460966419E72BE27FA5182D5A4EE6C61DB0FFC4B8E2B3D818D1AC4EECB3F78473C7A91849F09F754396A66D5"
				"C9CC52CD76A241EE501014029D0C3C4BC5E1ED1F86036FBCB5579052C355E566449671D4A7ABB55428DC333C9C3C57B9362D3F331169E8DA9BF863DF6D0D6CFB"
				"F8617D6319BB39214C11A01F72477A7A85043A705D33B88B3A277DF868D755FF5A68A73A12C2485CB019671CFA53B60B8DE5A728C2BF852DA0986114C7FC78D5"
				"F57CBC3458345C353665EADA5D31DA56B895F551819069B1085F6B15DD86A8EDB490F626F99227B230A3144C937D030294F38BFB804BDCA5DABC62E6E64CC65A"
				"BB4FE10CE33BED67C230A566F75E8EB33CC88EC504B73B53E2F6EDB5232DF0200341B9C39EA5A7EF9A5F6E3A5C990C978E5B9B0D49419EC89015A3EACB9A09E7"
				"A5C37C4B702D49AC44B27D436644B00F622EE8657932AB2C5025C286E2648295847A5F55DFF3C40ADEA2C909782DA676DBA5CB9DE90AED86A28FDC5EBAC9E864"
				"7A4E24FADE8FF2408412494392161D64B42A3ED6CDC9DCAF52C6E5E640FE7ECA2D4460BB493D52D8FF333D769EA399859EA3A4E31688AE40C1A2498919193ABE"
				"885298D6FAF5ED0CC5527A7205D977ABE2F469F95785BE656991D429D59BBF1895323E1EB3DBED53E18ED042CCEF5BCE765C74BCCB82E935E266F802CFCF58C7"
				"DDFB3A3294738117FDC10F102A16C3825E25D523D8296797DEA88B1585992F34E9C543FC4C5D12499A82FEF88558DEE85CEC840BD8EAF1271425D9108943EC41"),
			std::string("9AEF31187A2ADBAC8D31E26BE459CECC65077AD6E0F137E10F2F3C13C50145B833439EFFBBDA65FC184D770301512432107916757846BC813DAA78AFDFC5120B"
				"F654CE9D66DFCB325D2D39DC75087FCE210238E512EBCDCF0218E4A2699874D595E67D6F72C5F8B1889E5ED9C5906ED34B8C42168765AF0943B91B589C7A8DB9"
				"B7C62AD101B16A8002C7F7CBBA720DA9C64CF521CCB32C478DD9FEF944A5251883149B10C41FE216C9F1A1F6599B64DEEE55508D03C060F83649DD7B3EA1EF18"
				"7EC833181B028CE85E65E46FBB69CD31FEFE5372D3B772BC220F10A5150BA9AF2334080DE14FE85F71E8499A2B921FD22E3B92C5E48CD3BA2F3A5432931C1F3B"
				"E480183ABC8C2D2561DB69B45CE7ABD041A8A8CC0B0B2292125998C627EF1024613A7EA0828EFD8C43323EB9F0128CA8321469D767576D2E88D3BDEA09A80CA4"
				"2AABEF4240017DAB35AC17B555CDEE1FCE5A19FED9F774154083DFF3B8CCB25E4C602E22E9E3269F656B7882C0AE9FB6D974D524A99438B8D7BECC2B0625DF4C"
				"334AD823BA0BE38E296FB04D75C632009023E71D429C3B2FBC4CDF57A7804547F079BA8278E6339116A2F5582A07C37BC7A153042DDD11A93C0B2846AEE88521"
				"743CB2395027274C460966419E72BE27FA5182D5A4EE6C61DB0FFC4B8E2B3D81E6E2DF36D272BCAD1BAC8FD1A33F376FA8DB3CE027262C71418C7C3388178633"
				"86A67DB37E8A64BB7A4D5B63034508B88D1AC4EECB3F78473C7A9184C355E566449671D4A7ABB55428DC333C9C3C57B9362D3F331169E8DA9BF863DF6D0D6CFB"
				"7C7FAB73036C7DCD5ADB5827B87FF8BEB36E422841433E1147F28DBE61EF1CD3B439A0AF9D1E3916548102176892E6B312C2485CB019671CFA53B60B8DE5A728"
				"C2BF852DA0986114C7FC78D5F57CBC3458345C35937D030294F38BFB804BDCA5445E2644953AA71C74C05507D0A8DF08657C5679D140A5D19974E7AA855BE55F"
				"6C034BA7021CA06AF4EE8B1D41031ADFDABC62E6E64CC65ABB4FE10CE33BED67C230A566F75E8EB349419EC89015A3EACB9A09E7A5C37C4B702D49AC44B27D43"
				"26D88CACC81B2B1DA5AB0107E23139F59CA0BCF305A5C6075C148337906D407D3A841289F64C17C26C24C6F81A5DDEB96644B00F622EE8657932AB2CBAC9E864"
				"7A4E24FADE8FF2408412494392161D64B42A3ED6CDC9DCAF52C6E5E640FE7ECA828D0971556679A1D65B2C9FAA80AC94544A9547559440C0E7E3C5DD5126E4EC"
				"FFE3E1B357915C71AB836FC72862277EFAF5ED0CC5527A7205D977ABE2F469F95785BE656991D429D59BBF1895323E1EB3DBED532A16C3825E25D523D8296797"
				"A1CBA9AE02EE6D187A683C748C18B99708C0FADD5E78C63280F51E2DDF7ACA50570F4B080308580F946FB82E6595B471DEA88B1585992F34E9C543FC4C5D1249")
		};
		HexConverter::Decode(pubexp, 3, m_pubexp);

		const std::vector<std::string> priexp =
		{
			std::string("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D03776B5A7AADA5E977FB802359A6E57C95D7FC4D6C7BFF1228C89AE67FC9AB74"
				"D3096224C8AABFE28066CE5F550E39262B19E815F1A615A2FAF4EB35D45C3828252781436325B83C449618B5C539787B74C08CC73518CF118E39FF33EF8D61C4"
				"A2E9A1A51E2BFF6530C37EFEA8A30951C0B99C306C3DD53490DC300707FB6B5148DB331827119674D83160840437B59182DBF2A473196612D87E125C9366477B"
				"76048FD81B660025A15A9D3762166C1B9D4B3EDCC4BEE9C670C6B4DAE809433AA74D55701655BEFA83084E4D1D286F08D286EDA89B7B09B4AB650FC43B0A7935"
				"6966D2E3BE3FACF1F85849C2B0295A27E188BB9180F6D300765E45B0866B529D90048A3F10470B2FAD2AB7ED020D04841872B573DCDD0FB2DAA4250582AAFC73"
				"F332A99A185509E3DEE3387EA5C80ED9DDA3648F1E2CB5B64FE0874079D8E8C60A0D6160B28433BAE59AA69B91A79447BDCD97EB79C35E03DF4BE1CD06A55A92"
				"3B9A457AE70BA4E138BBEED081CF9B01297E5E1770FD69908C46FCDBD7DD2AFB5F43DB1874943CCB780D623FAB760B447F043764A275D005DCE8B9E33FE63E0B"
				"9D484E54EC4F36AF321212C630FEA015345F65AF5271FF50BE1818816461E66821CE7227E6A462D10B81B2C25609778A957F611D52665D66751E86D75F02D2B7"
				"DEED3FB9B0F6DA83A08B2291F5E71F5749D164A791021634E8392AC95D5392A6BE00EABDF45F62A8109F422B20F78EB9AE1B377264BB1E7EB052014DB78202DA"
				"A0099B221624665E6BA27B2305BB922C68F24F97BFF65414AEA3E25FEEA4CC2247E5DA0766B94332527973BEE825075B22DF6E891CD7EEA56E9A066BE093B28F"
				"E2ABD87B176D813B41A011A85E21511C54906AB91862B098375D7F7BD90E31A3435943EF1523A2A56B4A72F122EF78595F48987A674CDD793E1CB030AC4C02F4"
				"7E741DE523ED73B356491273C6A785ADA03BCD94786F3260E638BCDB481B770542ADF9C9306490CF1DCF0BB815E74F2AF5FB18BAD84B6706FE82EF9696C712FF"
				"D0ABC1C1076B0EED29F2116A3086E9BFE559890D8A3D07E26AA95F323B8492A8C3E528731A17FCACD05725ADB1F85BEA80F500F9D1EAA83FC56CB5B27F217475"
				"C48459D3265B4189E0E9106787519EC7858E7A7744BD1CB74C3A59FE675671A2B430DE8EA78E8C8FF6B5E58A20272E991DE2DB23A2A7C8DC8853EEBF2DBAEFC8"
				"14B0E1A13AF4E53DB1409158C292A78B665074EC686B2AEB014153EE6A0A6FEB174FAEE156275775512CD5D170CE67CFD07E9C5A4E14A5EF76453812DAAA1CD7"
				"9D1F6B74DB67745EF28EA863050B95154A893229F41807BB447963D4667315E0A04510868586FD8E1643C12FE041F461BE1DF871E04DE9E9F5BE0C77F7B6A53C"),
			std::string("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DCDA096DF495148FC5A65814E9E6DF7B855FB9A193875CFBC39A49E0EF91514A3"
				"147D717B75BECDEBC3E7F413358C73199A31BB16E5BC1355FB15F5FA280E7EDF3ABA739E43DCB917EEF8EAB252F96A80B45C9011C0E370538AB9A7E4D0444646"
				"114704CE76AC71F52BC46789F7344BB5E09077968311419BB169B07172F595EAAFC5226119B5F0B697FC5737E9D6DAD33DAC6E62939F579A3B03BE314C943E4A"
				"BA636B9014D171F6065B73F4639058E7087DAC17D03CFCE676408DD3DFF1DA2F468FF2EEF5CBFE73C4707B69FE9D579D35F734103F0CE4602CEE3CD6C07EE169"
				"CC75BF643BB0F54FC6AF2541616B295DC076578D3FB45BEB218FFFB97949DCA7BB394031478EA45BE513C40A5050F69A7AF8F1CB4C358B1B68E7F794DDF89D2C"
				"FA65EE2DD11832E1395A83018A84E3C84A4C9C1F41964013203158421E435061E28601198CF5E7EC95F3EDFCEC93766E1B9FF13A07348BC20E65AEA1F84826BA"
				"D43782864901AF6720B884B7DFF5329B10754E8294F8D1812D10C54B2BE5B0A57415F32FBD400898E49EE27C02B921AB3719EFB460BC2B0CFF27972BD194EB20"
				"0625DE34CDCDFD9D80BA7BCA2A22B5FDF994027CCC289FDC4AE9E219AF0BB1043FFADD665769C4FF9455B21B8764E377636510C92C3D890C611EB34A1E0375ED"
				"37AB78F7D24E02726472165F7C15C8E91D2C9955EF6EC3460BFE8133E72F8D4718B4B943C5663AD535A60962B321D576124534866678156A7FCFA9BE5FC06872"
				"F3248979EC9C9C721D265627DFA5E370570162F0D90CCBD581C28D33DC364EEEE533A185E20A6071D1AD2FC13AFD92B15732169E9180803E3BF7918BF0A8BF77"
				"6C476D38AC47AD36839BCF474752324C8A6A0B3378DC12310037785B11ED80DD247D157A79AEF9322DE51E883B5063BBDD36227733C89B8EF0E3C27C761D603D"
				"BF1D7F61122CA9B8EA8D5C61115710A7C05BB9BC96CDDCD250560AF568E8D869A8A7093462A35F2B034368C422B6C7812416B577385ED4F4D8DF9565C5CC015B"
				"ECAF75DC1115157B4E9E0D7C1099FD98C006893A587BAEF07D08E818E1D3B6685F5577D2C9810DCC8001CF86051D0E008C5A6B97BC980B6EC9C10446EF10FB0F"
				"5611D1DAE19B138F8978BE8B89E7EC30DF90D15697D913391AE05C8D486FD20AAF4FDF10EE45DFE28A69C50275408F0463D297BF86EC48A48068E2D0F0187D0E"
				"048FD5D32B4C8B0A50873350A0AC282A667476BDAA509E4FE205E3CEF53185E249D33DAD0A9A19AC476DD261C801F0D5BDF4E0E3F8E90EAFEDD6970AFF613D3F"
				"5F633D2C6557F55B99DF3AC2FC3256501CFD0E288A574597CAFDF6F91425217019B2850C694B14FE00E76F0BEF7D5C7F6CFC8E9640155C4ABC6220726D69C4EB"),
			std::string("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DCDA096DF495148FC5A65814E9E6DF7B855FB9A193875CFBC39A49E0EF91514A3"
				"147D717B75BECDEBC3E7F413358C73199A31BB16E5BC1355FB15F5FA280E7EDF3ABA739E43DCB917EEF8EAB252F96A80B45C9011C0E370538AB9A7E4D0444646"
				"114704CE76AC71F52BC46789F7344BB5E09077968311419BB169B07172F595EAAFC5226119B5F0B697FC5737E9D6DAD33DAC6E62939F579A3B03BE314C943E4A"
				"BA636B9014D171F6065B73F4639058E7087DAC17D03CFCE676408DD3DFF1DA2F468FF2EEF5CBFE73C4707B69FE9D579D35F734103F0CE4602CEE3CD6C07EE169"
				"CC75BF643BB0F54FC6AF2541616B295DC076578D3FB45BEB218FFFB97949DCA7BB394031478EA45BE513C40A5050F69A7AF8F1CB4C358B1B68E7F794DDF89D2C"
				"FA65EE2DD11832E1395A83018A84E3C84A4C9C1F41964013203158421E435061E28601198CF5E7EC95F3EDFCEC93766E1B9FF13A07348BC20E65AEA1F84826BA"
				"D43782864901AF6720B884B7DFF5329B10754E8294F8D1812D10C54B2BE5B0A57415F32FBD400898E49EE27C02B921AB3719EFB460BC2B0CFF27972BD194EB20"
				"0625DE34CDCDFD9D80BA7BCA2A22B5FDF994027CCC289FDC4AE9E219AF0BB1043FFADD665769C4FF9455B21B8764E377636510C92C3D890C611EB34A1E0375ED"
				"37AB78F7D24E02726472165F7C15C8E91D2C9955EF6EC3460BFE8133E72F8D4718B4B943C5663AD535A60962B321D576124534866678156A7FCFA9BE5FC06872"
				"F3248979EC9C9C721D265627DFA5E370570162F0D90CCBD581C28D33DC364EEEE533A185E20A6071D1AD2FC13AFD92B15732169E9180803E3BF7918BF0A8BF77"
				"6C476D38AC47AD36839BCF474752324C8A6A0B3378DC12310037785B11ED80DD247D157A79AEF9322DE51E883B5063BBDD36227733C89B8EF0E3C27C761D603D"
				"BF1D7F61122CA9B8EA8D5C61115710A7C05BB9BC96CDDCD250560AF568E8D869A8A7093462A35F2B034368C422B6C7812416B577385ED4F4D8DF9565C5CC015B"
				"ECAF75DC1115157B4E9E0D7C1099FD98C006893A587BAEF07D08E818E1D3B6685F5577D2C9810DCC8001CF86051D0E008C5A6B97BC980B6EC9C10446EF10FB0F"
				"5611D1DAE19B138F8978BE8B89E7EC30DF90D15697D913391AE05C8D486FD20AAF4FDF10EE45DFE28A69C50275408F0463D297BF86EC48A48068E2D0F0187D0E"
				"048FD5D32B4C8B0A50873350A0AC282A667476BDAA509E4FE205E3CEF53185E249D33DAD0A9A19AC476DD261C801F0D5BDF4E0E3F8E90EAFEDD6970AFF613D3F"
				"5F633D2C6557F55B99DF3AC2FC3256501CFD0E288A574597CAFDF6F91425217019B2850C694B14FE00E76F0BEF7D5C7F6CFC8E9640155C4ABC6220726D69C4EB")
		};
		HexConverter::Decode(priexp, 3, m_priexp);

		HexConverter::Decode(std::string("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), m_rngseed);

		const std::vector<std::string> sigexp =
		{
			// Rainbow
			std::string("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8CFA0690155E920F4E6E29DC3A3E2E4BC63DAF3294BEEC19681F59EAA4D31B8"
				"863DC2926A04DE5C22AA61F3FCCDAC18A9FA6D073D9FCFB5F767B034A5B881227009F1AE5483D81C08A7742655972A97AE750E67DF448236730085673FEFE4A8"
				"555ED47D643D612AD213EBC5892940D6AC8F3A2B34AB120CB08D20A79C73BA5EE9"),
			std::string("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8846B84CA6A08F98EA16BED5661FF2F102766E4B6BA19DCD88E03006E32EDFB"
				"2732C0530A4B863D76786DA86C5ED70698CB771AAC86F5D00E2624AA0D98AD88A38D5C4DFC057F8533C04C81193EE2B4DD4D9E57F0891CD9536CD458153AF01D"
				"4BA0F52796E46053A49E4D3D4C34BE43F66C8C0E848B3FCE85655D043A6A0A9E1FCE9ECC8E1BB1F7E6B1B430FB7BF41EB03C7BD73C660522091DBA7CED"),
			std::string("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8099AA9D74014861FB5B2C35BE8E495782E64343C92B07BA64AA646EE7F0E2A"
				"988B772968725E15355A8790C302398D9B200C0B9881DCD5E5BDAE7C7DBAE908166C9D8C66849B23F40311841811264FFDB5404B8182CCA0E621DE4193B8963D"
				"7AB542CC67C302AFB8F35D4D3C8CA022261554C2A6B801DE47B3330C4BF0FC2FB50489DF0BB162FEB1E7A02DACAD16E3CA65F6166809691D6719F2BB597EE1A7"
				"51E543DEAE0F8B74CDF61CA6C9560EFC2E0B2605CE724CAC4F91A3AF3FBFE3DC270CAB8A55612CCD12E818B959"),
		};
		HexConverter::Decode(sigexp, 3, m_sigexp);

		/*lint -restore */
	}

	void RainbowTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
