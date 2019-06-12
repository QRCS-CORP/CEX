#include "SphincsTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/Sphincs.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Enumeration::AsymmetricKeyTypes;
	using Enumeration::AsymmetricPrimitives;
	using Enumeration::AsymmetricTransforms;
	using Exception::CryptoAsymmetricException;
	using Utility::IntegerTools;
	using Asymmetric::Sign::SPX::Sphincs;
	using Prng::SecureRandom;
	using Enumeration::SphincsParameters;

	const std::string SphincsTest::CLASSNAME = "SphincsTest";
	const std::string SphincsTest::DESCRIPTION = "SphincsTest key generation, signature generation, and verification tests..";
	const std::string SphincsTest::SUCCESS = "SUCCESS! SphincsTest tests have executed succesfully.";

	SphincsTest::SphincsTest()
		:
		m_msgexp(0),
		m_pubexp(0),
		m_priexp(0),
		m_rngseed(0),
		m_sigexp(0),
		m_progressEvent()
	{
	}

	SphincsTest::~SphincsTest()
	{
		IntegerTools::Clear(m_msgexp);
		IntegerTools::Clear(m_pubexp);
		IntegerTools::Clear(m_priexp);
		IntegerTools::Clear(m_rngseed);
		IntegerTools::Clear(m_sigexp);
	}

	const std::string SphincsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SphincsTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SphincsTest::Run()
	{
		std::string fname;

		try
		{
			fname = "Authentication";
			Authentication();
			OnProgress(std::string("SphincsTest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("SphincsTest: Passed exception handling test.."));
			PrivateKey();
			OnProgress(std::string("SphincsTest: Passed private key integrity test.."));
			PublicKey();
			OnProgress(std::string("SphincsTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("SphincsTest: Passed key serialization tests.."));
			Signature();
			OnProgress(std::string("SphincsTest: Passed signature tamper test.."));
			Stress();
			OnProgress(std::string("SphincsTest: Passed encryption and decryption stress tests.."));

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

	void SphincsTest::Authentication()
	{
		Sphincs sgn1(SphincsParameters::SPXS128F256);
		Sphincs sgn2(SphincsParameters::SPXS128F256);
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

	void SphincsTest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			Sphincs sgn(Enumeration::SphincsParameters::None);

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
			Sphincs sgn(Enumeration::SphincsParameters::SPXS128F256, Enumeration::Prngs::None);

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
			Sphincs sgn(Enumeration::SphincsParameters::SPXS128F256, nullptr);

			throw TestException(std::string("Exception"), sgn.Name(), std::string("Exception handling failure! -SE3"));
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
			Sphincs sgn(SphincsParameters::SPXS128F256);
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
			Sphincs sgn(SphincsParameters::SPXS128F256);
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
			Sphincs sgn(SphincsParameters::SPXS128F256);
			Asymmetric::Encrypt::MLWE::ModuleLWE cprb;
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
			Sphincs sgn(SphincsParameters::SPXS128F256);
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

	void SphincsTest::PrivateKey()
	{
		SecureRandom gen;
		Sphincs sgn(SphincsParameters::SPXS256F256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter private key
		std::vector<byte> sk1 = kp->PrivateKey()->Polynomial();
		gen.Generate(sk1, 0, 16);
		AsymmetricKey* sk2 = new AsymmetricKey(sk1, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricTransforms>(SphincsParameters::SPXS256F256));

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -SS1"));
		}
	}

	void SphincsTest::PublicKey()
	{
		SecureRandom gen;
		Sphincs sgn(SphincsParameters::SPXS256F256);
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<byte> pk1 = (kp->PublicKey()->Polynomial());
		gen.Generate(pk1, 0, 16);
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::Sphincs, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricTransforms>(SphincsParameters::SPXS256F256));

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -SP1"));
		}
	}

	void SphincsTest::Serialization()
	{
		Sphincs sgn(SphincsParameters::SPXS128F256);
		SecureVector<byte> skey(0);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = sgn.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Private key serialization test has failed! -SR1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), sgn.Name(), std::string("Public key serialization test has failed! -SR2"));
			}
		}
	}

	void SphincsTest::Signature()
	{
		SecureRandom gen;
		Sphincs sgn(SphincsParameters::SPXS128F256);
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
			throw TestException(std::string("Signature"), sgn.Name(), std::string("Signature test failed! -SS1"));
		}
	}

	void SphincsTest::Stress()
	{
		const size_t CYCLES = TEST_CYCLES == 1 ? 1 : TEST_CYCLES / 2;

		SecureRandom gen;
		Sphincs sgn1(SphincsParameters::SPXS128F256);
		Sphincs sgn2(SphincsParameters::SPXS256F256);
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
				throw TestException(std::string("Stress"), sgn1.Name(), std::string("Stress test authentication has failed! -SR1"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn1.Name(), std::string("Stress test authentication has failed! -SR2"));
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
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -SR3"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("Stress"), sgn2.Name(), std::string("Stress test authentication has failed! -SR4"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}
	}

	void SphincsTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
