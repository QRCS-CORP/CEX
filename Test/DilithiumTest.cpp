#include "DilithiumTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/Dilithium.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using namespace Asymmetric;
	using Asymmetric::Sign::DLM::Dilithium;
	using Enumeration::DilithiumParameters;
	using Prng::SecureRandom;

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
		Dilithium sgn1(DilithiumParameters::DLMS2N256Q8380417);
		Dilithium sgn2(DilithiumParameters::DLMS2N256Q8380417);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		SecureRandom rnd;
		bool ret;

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
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417, Enumeration::Prngs::None);

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
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417, nullptr);

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
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
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

		// test verif without initialization
		try
		{
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
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
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
			Asymmetric::Encrypt::MLWE::ModuleLWE cprb;
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
			std::vector<byte> msg(32);
			std::vector<byte> sig(0);
			Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
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

	void DilithiumTest::PrivateKey()
	{
		SecureRandom gen;
		Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter private key
		std::vector<byte> sk1 = kp->PrivateKey()->Polynomial();
		gen.Generate(sk1, 0, 16);
		AsymmetricKey* sk2 = new AsymmetricKey(sk1, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(DilithiumParameters::DLMS2N256Q8380417));

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -DS1"));
		}
	}

	void DilithiumTest::PublicKey()
	{
		SecureRandom gen;
		Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<byte> pk1 = kp->PublicKey()->Polynomial();
		gen.Generate(pk1, 0, 16);
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::Dilithium, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(DilithiumParameters::DLMS2N256Q8380417));

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -DP1"));
		}
	}

	void DilithiumTest::Serialization()
	{
		Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
		SecureVector<byte> skey(0);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = sgn.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Private key serialization test has failed! -DR1"));
			}

			delete prik1;
			delete prik2;

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
		Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		// alter signature
		gen.Generate(sig, 0, 16);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Public key integrity test failed! -DS1"));
		}
	}

	void DilithiumTest::Stress()
	{
		SecureRandom gen;
		Dilithium sgn1(DilithiumParameters::DLMS1256Q8380417);
		Dilithium sgn2(DilithiumParameters::DLMS2N256Q8380417);
		Dilithium sgn3(DilithiumParameters::DLMS3N256Q8380417);
		std::vector<byte> msg1(0);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		size_t msglen;
		bool status;

		for (size_t i = 0; i < TEST_CYCLES; ++i)
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

	void DilithiumTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
