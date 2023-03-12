#include "SphincsPlusTest.h"
#include "NistPqParser.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Kyber.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/SphincsPlus.h"

namespace Test
{
	using Test::NistPqParser;
	using Test::NistRng;
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Sign::SPXP::SphincsPlus;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Enumeration::SphincsPlusParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Prng::SecureRandom;
	using CEX::Tools::IntegerTools;
	using namespace Test::TestFiles::NISTPQ3;

	const std::string SphincsPlusTest::CLASSNAME = "SphincsPlusTest";
	const std::string SphincsPlusTest::DESCRIPTION = "SphincsPlusTest key generation, signature generation, and verification tests..";
	const std::string SphincsPlusTest::SUCCESS = "SUCCESS! SphincsPlusTest tests have executed succesfully.";

	SphincsPlusTest::SphincsPlusTest()
		:
		m_progressEvent()
	{
	}

	SphincsPlusTest::~SphincsPlusTest()
	{
	}

	const std::string SphincsPlusTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SphincsPlusTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SphincsPlusTest::Run()
	{
		try
		{
			Initialize();

			Kat();
			OnProgress(std::string("SphincsPlusTest: Passed signature cipher-text and message verification known answer tests.."));
			Authentication();
			OnProgress(std::string("SphincsPlusTest: Passed message authentication test.."));
			Exception();
			OnProgress(std::string("SphincsPlusTest: Passed exception handling test.."));
			PrivateKey();
			OnProgress(std::string("SphincsPlusTest: Passed private key integrity test.."));
			PublicKey();
			OnProgress(std::string("SphincsPlusTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("SphincsPlusTest: Passed key serialization tests.."));
			Signature();
			OnProgress(std::string("SphincsPlusTest: Passed signature tamper test.."));
			Stress();
			OnProgress(std::string("SphincsPlusTest: Passed encryption and decryption stress tests.."));

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

	void SphincsPlusTest::Authentication()
	{
		SphincsPlus sgn1(SphincsPlusParameters::SPXPS1S128SHAKE);
		SphincsPlus sgn2(SphincsPlusParameters::SPXPS1S128SHAKE);
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
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -SA1"));
		}
		if (ret != true)
		{
			throw TestException(std::string("Authentication"), sgn1.Name(), std::string("Message authentication test failed! -SA1"));
		}
	}

	void SphincsPlusTest::Exception()
	{
		// test invalid constructor parameters -sphincs parameters
		try
		{
			SphincsPlus sgn(Enumeration::SphincsPlusParameters::None);

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
			SphincsPlus sgn(Enumeration::SphincsPlusParameters::SPXPS1S128SHAKE, Enumeration::Prngs::None);

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
			SphincsPlus sgn(Enumeration::SphincsPlusParameters::SPXPS1S128SHAKE, nullptr);

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
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
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
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
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
			SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
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
			std::vector<uint8_t> msg(32);
			std::vector<uint8_t> sig(0);
			SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
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

	void SphincsPlusTest::Kat128()
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
		
		NistPqParser::ParseNistSignatureKat(SPHINCSPLUS128S, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("KatS128"), sgn.Name(), std::string("Failed expected public key test! -SK1"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("KatS128"), sgn.Name(), std::string("Failed expected private key test! -SK2"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("KatS128"), sgn.Name(), std::string("Cipher-text arrays do not match! -SK3"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("KatS128"), sgn.Name(), std::string("Failed authentication test! -SK4"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("KatS128"), sgn.Name(), std::string("Messages do not match! -SK5"));
		}

		delete kp;
	}

	void SphincsPlusTest::Kat192()
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
		
		NistPqParser::ParseNistSignatureKat(SPHINCSPLUS192S, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		SphincsPlus sgn(SphincsPlusParameters::SPXPS3S192SHAKE, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("KatS192"), sgn.Name(), std::string("Failed expected public key test! -SK1"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("KatS192"), sgn.Name(), std::string("Failed expected private key test! -SK2"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("KatS192"), sgn.Name(), std::string("Cipher-text arrays do not match! -SK3"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("KatS192"), sgn.Name(), std::string("Failed authentication test! -SK4"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("KatS192"), sgn.Name(), std::string("Messages do not match! -SK5"));
		}

		delete kp;
	}

	void SphincsPlusTest::Kat256()
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
		
		NistPqParser::ParseNistSignatureKat(SPHINCSPLUS256S, seed, &seedlen, kmsg, &msglen, kpk, &pklen, ksk, &sklen, ksig, &siglen, 0);

		gen.Initialize(seed);

		SphincsPlus sgn(SphincsPlusParameters::SPXPS5S256SHAKE, &gen);

		// generate the key pair
		AsymmetricKeyPair* kp = sgn.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("KatS256"), sgn.Name(), std::string("Failed expected public key test! -SK1"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("KatS256"), sgn.Name(), std::string("Failed expected private key test! -SK2"));
		}

		// initialize and sign
		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(kmsg, sig);

		// test for correct signature cipher-text
		if (sig != ksig)
		{
			throw TestException(std::string("KatS256"), sgn.Name(), std::string("Cipher-text arrays do not match! -SK3"));
		}

		// initialize and verify
		sgn.Initialize(kp->PublicKey());

		// verify and test for expected message
		if (!sgn.Verify(sig, msg))
		{
			throw TestException(std::string("KatS256"), sgn.Name(), std::string("Failed authentication test! -SK4"));
		}

		if (msg != kmsg)
		{
			throw TestException(std::string("KatS256"), sgn.Name(), std::string("Messages do not match! -SK5"));
		}

		delete kp;
	}

	void SphincsPlusTest::Kat()
	{
		Kat128();
		Kat192();
		Kat256();
	}

	void SphincsPlusTest::PrivateKey()
	{
		SecureRandom gen;
		SphincsPlus sgn(SphincsPlusParameters::SPXPS3S192SHAKE);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter private key
		std::vector<uint8_t> sk1 = kp->PrivateKey()->Polynomial();
		gen.Generate(sk1, 0, 16);
		AsymmetricKey* sk2 = new AsymmetricKey(sk1, AsymmetricPrimitives::SphincsPlus, AsymmetricKeyTypes::SignaturePrivateKey, static_cast<AsymmetricParameters>(SphincsPlusParameters::SPXPS3S192SHAKE));

		sgn.Initialize(sk2);
		sgn.Sign(msg1, sig);

		sgn.Initialize(kp->PublicKey());

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PrivateKey"), sgn.Name(), std::string("Private key integrity test failed! -SS1"));
		}
	}

	void SphincsPlusTest::PublicKey()
	{
		SecureRandom gen;
		SphincsPlus sgn(SphincsPlusParameters::SPXPS3S192SHAKE);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

		AsymmetricKeyPair* kp = sgn.Generate();

		// alter public key
		std::vector<uint8_t> pk1 = (kp->PublicKey()->Polynomial());
		gen.Generate(pk1, 0, 16);
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::SphincsPlus, AsymmetricKeyTypes::SignaturePublicKey, static_cast<AsymmetricParameters>(SphincsPlusParameters::SPXPS3S192SHAKE));

		sgn.Initialize(kp->PrivateKey());
		sgn.Sign(msg1, sig);

		sgn.Initialize(pk2);

		if (sgn.Verify(sig, msg2))
		{
			throw TestException(std::string("PublicKey"), sgn.Name(), std::string("Public key integrity test failed! -SP1"));
		}
	}

	void SphincsPlusTest::Serialization()
	{
		SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
		SecureVector<uint8_t> skey(0);

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

			delete kp;
		}
	}

	void SphincsPlusTest::Signature()
	{
		SecureRandom gen;
		SphincsPlus sgn(SphincsPlusParameters::SPXPS1S128SHAKE);
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);

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

	void SphincsPlusTest::Stress()
	{
		const size_t CYCLES = TEST_CYCLES == 1 ? 1 : TEST_CYCLES / 2;

		SecureRandom gen;
		SphincsPlus sgn1(SphincsPlusParameters::SPXPS1S128SHAKE);
		SphincsPlus sgn2(SphincsPlusParameters::SPXPS3S192SHAKE);
		std::vector<uint8_t> msg1(0);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);
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

	void SphincsPlusTest::Initialize()
	{
	}

	void SphincsPlusTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
