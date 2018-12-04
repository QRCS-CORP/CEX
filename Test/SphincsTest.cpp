#include "SphincsTest.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/IntUtils.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/Sphincs.h"
#include "../CEX/SphincsKeyPair.h"
#include "../CEX/SphincsPrivateKey.h"
#include "../CEX/SphincsPublicKey.h"

namespace Test
{
	using namespace Key::Asymmetric;
	using Cipher::Asymmetric::Sign::SPX::Sphincs;
	using Prng::SecureRandom;

	const std::string SphincsTest::DESCRIPTION = "SphincsTest key generation, signature generation, and verification tests..";
	const std::string SphincsTest::FAILURE = "FAILURE! ";
	const std::string SphincsTest::SUCCESS = "SUCCESS! SphincsTest tests have executed succesfully.";

	SphincsTest::SphincsTest()
		:
		m_progressEvent()
	{
	}

	SphincsTest::~SphincsTest()
	{
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
		try
		{
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
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(FAILURE + std::string(" : Unknown Error"));
		}
	}

	void SphincsTest::Authentication()
	{
		Sphincs sgn1;
		Sphincs sgn2;
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		SecureRandom rnd;
		bool ret;

		IAsymmetricKeyPair* kp = sgn1.Generate();
		sgn1.Initialize(kp->PrivateKey());
		sgn1.Sign(msg1, sig);
		sgn2.Initialize(kp->PublicKey());
		ret = sgn2.Verify(sig, msg2);

		if (msg1 != msg2)
		{
			throw TestException(std::string("SphincsTest: Message authentication test failed! -SA1"));
		}
		if (ret != true)
		{
			throw TestException(std::string("SphincsTest: Message authentication test failed! -SA1"));
		}
	}

	void SphincsTest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			Sphincs sgn(Enumeration::SphincsParameters::None);

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE1"));
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

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// null prng and kdf
		try
		{
			Sphincs sgn(Enumeration::SphincsParameters::SPXS128F256, nullptr, nullptr);

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE3"));
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
			Sphincs sgn;
			sgn.Sign(msg, sig);

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE4"));
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
			Sphincs sgn;
			sgn.Verify(sig, msg);

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE5"));
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
			Sphincs sgn;
			Cipher::Asymmetric::MLWE::ModuleLWE cprb;
			// create an invalid key set
			IAsymmetricKeyPair* kp = cprb.Generate();
			sgn.Initialize(kp->PrivateKey());

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE6"));
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
			Sphincs sgn;
			IAsymmetricKeyPair* kp = sgn.Generate();
			sgn.Initialize(kp->PublicKey());
			sgn.Sign(msg, sig);

			throw TestException(std::string("SPHINCS+"), std::string("Exception: Exception handling failure! -SE7"));
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
		Sphincs sgn;
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		IAsymmetricKeyPair* kp = sgn.Generate();

		// alter private key
		std::vector<byte> sk1 = ((SphincsPrivateKey*)kp->PrivateKey())->R();
		gen.Generate(sk1, 0, 16);
		SphincsPrivateKey* sk2 = new SphincsPrivateKey(SphincsParameters::SPXS256F256, sk1);

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("SPHINCS+"), std::string("Exception: Private-key integrity test failed! -SS1"));
		}
	}

	void SphincsTest::PublicKey()
	{
		SecureRandom gen;
		Sphincs sgn;
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		IAsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<byte> pk1 = ((SphincsPublicKey*)kp->PublicKey())->P();
		gen.Generate(pk1, 0, 16);
		SphincsPublicKey* pk2 = new SphincsPublicKey(SphincsParameters::SPXS256F256, pk1);

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("SPHINCS+"), std::string("Exception: Public-key integrity test failed! -SP1"));
		}
	}

	void SphincsTest::Serialization()
	{
		Sphincs sgn;
		std::vector<byte> skey;

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			IAsymmetricKeyPair* kp = sgn.Generate();
			SphincsPrivateKey* prik1 = (SphincsPrivateKey*)kp->PrivateKey();
			skey = prik1->ToBytes();
			SphincsPrivateKey prik2(skey);

			if (prik1->R() != prik2.R() || prik1->Parameters() != prik2.Parameters())
			{
				throw TestException(std::string("SphincsTest: Private key serialization test has failed! -SR1"));
			}

			SphincsPublicKey* pubk1 = (SphincsPublicKey*)kp->PublicKey();
			skey = pubk1->ToBytes();
			SphincsPublicKey pubk2(skey);

			if (pubk1->P() != pubk2.P() || pubk1->Parameters() != pubk2.Parameters())
			{
				throw TestException(std::string("SphincsTest: Public key serialization test has failed! -SR2"));
			}
		}
	}

	void SphincsTest::Signature()
	{
		SecureRandom gen;
		Sphincs sgn;
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);

		IAsymmetricKeyPair* kp = sgn.Generate();

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		// alter signature
		gen.Generate(sig, 0, 16);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("SPHINCS+"), std::string("Exception: Public-key integrity test failed! -SS1"));
		}
	}

	void SphincsTest::Stress()
	{
		SecureRandom gen;
		Sphincs sgn1(SphincsParameters::SPXS128F256);
		Sphincs sgn2(SphincsParameters::SPXS256F256);
		std::vector<byte> msg1(0);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		size_t msglen;
		bool status;
		const size_t CYCLES = TEST_CYCLES == 1 ? 1 : TEST_CYCLES / 2;

		for (size_t i = 0; i < CYCLES; ++i)
		{
			msglen = gen.NextUInt32(128, 16);
			msg1.resize(msglen);

			IAsymmetricKeyPair* kp = sgn1.Generate();

			sgn1.Initialize(kp->PrivateKey());
			sgn1.Sign(msg1, sig);

			sgn1.Initialize(kp->PublicKey());
			status = sgn1.Verify(sig, msg2);

			if (!status)
			{
				throw TestException(std::string("SPHINCS+"), std::string("Stress test authentication has failed! -SR1"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("SPHINCS+"), std::string("Stress test authentication has failed! -SR2"));
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

			IAsymmetricKeyPair* kp = sgn2.Generate();

			sgn2.Initialize(kp->PrivateKey());
			sgn2.Sign(msg1, sig);

			sgn2.Initialize(kp->PublicKey());
			status = sgn2.Verify(sig, msg2);

			if (!status)
			{
				throw TestException(std::string("SPHINCS+"), std::string("Stress test authentication has failed! -SR3"));
			}
			if (msg1 != msg2)
			{
				throw TestException(std::string("SPHINCS+"), std::string("Stress test authentication has failed! -SR4"));
			}

			sig.clear();
			msg1.clear();
			msg2.clear();
			status = false;
		}
	}

	void SphincsTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
