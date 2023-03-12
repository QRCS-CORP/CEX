#include "DilithiumTest.h"
#include "NistPqParser.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/Dilithium.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Sign::DLTM::Dilithium;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Enumeration::DilithiumParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Prng::SecureRandom;
	using CEX::Tools::IntegerTools;
	using Test::NistPqParser;
	using Test::NistRng;
	using namespace Test::TestFiles::NISTPQ3;

	const std::string DilithiumTest::CLASSNAME = "DilithiumTest";
	const std::string DilithiumTest::DESCRIPTION = "DilithiumTest key generation, signature generation, and verification tests..";
	const std::string DilithiumTest::SUCCESS = "SUCCESS! DilithiumTest tests have executed succesfully.";

	DilithiumTest::DilithiumTest()
		:
		m_progressEvent()
	{
	}

	DilithiumTest::~DilithiumTest()
	{
	}

	const std::string DilithiumTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &DilithiumTest::Progress()
	{
		return m_progressEvent;
	}

	std::string DilithiumTest::Run()
	{
		try
		{
			Initialize();

			Kat();
			OnProgress(std::string("DilithiumTest: Passed signature cipher-text and message verification known answer tests.."));
			Authentication();
			OnProgress(std::string("DilithiumTest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("DilithiumTest: Passed exception handling test.."));
			PrivateKey();
			OnProgress(std::string("DilithiumTest: Passed private key integrity test.."));
			PublicKey();
			OnProgress(std::string("DilithiumTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("DilithiumTest: Passed key serialization tests.."));
			Signature();
			OnProgress(std::string("DilithiumTest: Passed signature tamper test.."));
			Stress();
			OnProgress(std::string("DilithiumTest: Passed encryption and decryption stress tests.."));

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

	void DilithiumTest::Authentication()
	{
		Dilithium sgn1(DilithiumParameters::DLTMS3P4016);
		Dilithium sgn2(DilithiumParameters::DLTMS3P4016);
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

	void DilithiumTest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			Dilithium sgn(DilithiumParameters::None);

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
			Dilithium sgn(DilithiumParameters::DLTMS3P4016, Enumeration::Prngs::None);

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
			Dilithium sgn(DilithiumParameters::DLTMS3P4016, nullptr);

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
			Dilithium sgn(DilithiumParameters::DLTMS3P4016);
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
			Dilithium sgn(DilithiumParameters::DLTMS3P4016);
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

		// test initialization with wrong key
		try
		{
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			Dilithium sgn(DilithiumParameters::DLTMS3P4016);
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

	void DilithiumTest::Kat()
	{
		Kat2544();
		Kat4016();
		Kat4880();
	}

	void DilithiumTest::Kat2544()
	{
		std::vector<uint8_t> kmsg(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksig(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> msg(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sig(0);
		NistRng gen;
		size_t msglen;
		size_t pklen;
		size_t seedlen;
		size_t siglen;
		size_t sklen;

		msglen = 0;
		pklen = 0;
		seedlen = 0;
		siglen = 0;
		sklen = 0;
		
		NistPqParser::ParseNistSignatureKat(DILITHIUM2544, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		Dilithium sgn(DilithiumParameters::DLTMS1P2544, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat2544"), sgn.Name(), std::string("Failed expected public key test! -DK1"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat2544"), sgn.Name(), std::string("Failed expected private key test! -DK2"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("Kat2544"), sgn.Name(), std::string("Cipher-text arrays do not match! -DK3"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("Kat2544"), sgn.Name(), std::string("Failed authentication test! -DK4"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("Kat2544"), sgn.Name(), std::string("Messages do not match! -DK5"));
		}

		delete kp;
	}
	
	void DilithiumTest::Kat4016()
	{
		std::vector<uint8_t> kmsg(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksig(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> msg(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sig(0);
		NistRng gen;
		size_t msglen;
		size_t pklen;
		size_t seedlen;
		size_t siglen;
		size_t sklen;

		msglen = 0;
		pklen = 0;
		seedlen = 0;
		siglen = 0;
		sklen = 0;

		NistPqParser::ParseNistSignatureKat(DILITHIUM4016, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		Dilithium sgn(DilithiumParameters::DLTMS3P4016, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat4016"), sgn.Name(), std::string("Failed expected public key test! -DK6"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat4016"), sgn.Name(), std::string("Failed expected private key test! -DK7"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("Kat4016"), sgn.Name(), std::string("Cipher-text arrays do not match! -DK8"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("Kat4016"), sgn.Name(), std::string("Failed authentication test! -DK9"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("Integrity"), sgn.Name(), std::string("Messages do not match! -DK10"));
		}

		delete kp;
	}

	void DilithiumTest::Kat4880()
	{
		std::vector<uint8_t> kmsg(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksig(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> msg(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sig(0);
		NistRng gen;
		size_t msglen;
		size_t pklen;
		size_t seedlen;
		size_t siglen;
		size_t sklen;

		msglen = 0;
		pklen = 0;
		seedlen = 0;
		siglen = 0;
		sklen = 0;

		NistPqParser::ParseNistSignatureKat(DILITHIUM4880, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		Dilithium sgn(DilithiumParameters::DLTMS5P4880, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat4880"), sgn.Name(), std::string("Failed expected public key test! -DK11"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat4880"), sgn.Name(), std::string("Failed expected private key test! -DK12"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("Kat4880"), sgn.Name(), std::string("Cipher-text arrays do not match! -DK13"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("Kat4880"), sgn.Name(), std::string("Failed authentication test! -DK14"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("Kat4880"), sgn.Name(), std::string("Messages do not match! -DK15"));
		}

		delete kp;
	}

	void DilithiumTest::PrivateKey()
	{
		SecureRandom gen;
		Dilithium sgn(DilithiumParameters::DLTMS3P4016);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// serialize and alter private key
		std::vector<uint8_t> sk1 = kp->PrivateKey()->Polynomial();
		gen.Generate(sk1, 0, 16);
		AsymmetricKey* sk2 = new AsymmetricKey(sk1, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(DilithiumParameters::DLTMS3P4016));

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		// test for sign fail-over
		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -DS1"));
		}
	}

	void DilithiumTest::PublicKey()
	{
		SecureRandom gen;
		Dilithium sgn(DilithiumParameters::DLTMS3P4016);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<uint8_t> pk1 = kp->PublicKey()->Polynomial();
		gen.Generate(pk1, 0, 16);
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(DilithiumParameters::DLTMS3P4016));

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		// test for sign fail-over
		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -DP1"));
		}
	}

	void DilithiumTest::Serialization()
	{
		Dilithium sgn(DilithiumParameters::DLTMS3P4016);
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

	void DilithiumTest::Signature()
	{
		SecureRandom gen;
		Dilithium sgn(DilithiumParameters::DLTMS3P4016);
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

	void DilithiumTest::Stress()
	{
		SecureRandom gen;
		Dilithium sgn1(DilithiumParameters::DLTMS1P2544);
		Dilithium sgn2(DilithiumParameters::DLTMS3P4016);
		Dilithium sgn3(DilithiumParameters::DLTMS5P4880);
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
				throw TestException(std::string("Stress"), std::string("Dilithium"), std::string("Stress test authentication has failed! -DR2"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}

		for (size_t i = 0; i < TEST_CYCLES; ++i)
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
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -DR3"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -DR4"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			msglen = gen.NextUInt32(128, 16);
			msg1.resize(msglen);

			AsymmetricKeyPair* kp = sgn3.Generate();

			sgn3.Initialize(kp->PrivateKey());
			sgn3.Sign(msg1, sig);

			sgn3.Initialize(kp->PublicKey());
			status = sgn3.Verify(sig, msg2);

			if (!status)
			{
				throw TestException(std::string("Stress"), sgn3.Name(), std::string("Stress test authentication has failed! -DR5"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn3.Name(), std::string("Stress test authentication has failed! -DR6"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}
	}

	void DilithiumTest::Initialize()
	{
	}

	void DilithiumTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
