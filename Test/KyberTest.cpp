#include "KyberTest.h"
#include "NistRng.h"
#include "NistPqParser.h"
#include "TestFiles.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Kyber.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Encrypt::MLWE::Kyber;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Prng::SecureRandom;
	using CEX::Enumeration::KyberParameters;
	using CEX::Tools::IntegerTools;
	using Test::NistPqParser;
	using Test::NistRng;
	using namespace Test::TestFiles::NISTPQ3;

	const std::string KyberTest::CLASSNAME = "KyberTest";
	const std::string KyberTest::DESCRIPTION = "Kyber key generation, encryption, and decryption tests..";
	const std::string KyberTest::SUCCESS = "SUCCESS! Kyber tests have executed succesfully.";

	KyberTest::KyberTest()
		:
		m_progressEvent()
	{
	}

	KyberTest::~KyberTest()
	{
	}

	const std::string KyberTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KyberTest::Progress()
	{
		return m_progressEvent;
	}

	std::string KyberTest::Run()
	{
		try
		{
			Initialize();

			Authentication();
			OnProgress(std::string("KyberTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("KyberTest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("KyberTest: Passed exception handling test.."));
			Kat();
			OnProgress(std::string("KyberTest: Passed NIST PQ Round 3 shared-secret known answer tests.."));
			PublicKey();
			OnProgress(std::string("KyberTest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("KyberTest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("KyberTest: Passed encryption and decryption stress tests.."));

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

	void KyberTest::Authentication()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		// test param 1: KYBERS32400
		Kyber cpr1(KyberParameters::KYBERS32400);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);
		cpr1.Initialize(kp1->PrivateKey());

		if (!cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -MA1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp1;

		// test param 2: KYBERS53168
		Kyber cpr2(KyberParameters::KYBERS53168);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);
		cpr2.Initialize(kp2->PrivateKey());

		if (!cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp2;

		// test param 3: KYBERS63936
		Kyber cpr3(KyberParameters::KYBERS53168);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, sec1);
		cpr3.Initialize(kp3->PrivateKey());

		if (!cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr3.Name(), std::string("Message authentication test failed! -MA3"));
		}

		delete kp3;
	}

	void KyberTest::CipherText()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);
		SecureRandom gen;

		// test param 1: KYBERS32400
		Kyber cpr1(KyberParameters::KYBERS32400);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr1.Name(), std::string("Cipher text integrity test failed! -MC1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp1;

		// test param 2: KYBERS53168
		Kyber cpr2(KyberParameters::KYBERS53168);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr2.Name(), std::string("Cipher text integrity test failed! -MC2"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp2;

		// test param 3: KYBERS63936
		Kyber cpr3(KyberParameters::KYBERS63936);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr3.Name(), std::string("Cipher text integrity test failed! -MC3"));
		}

		delete kp3;
	}

	void KyberTest::KatK2400()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> kcpt(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> kss(32);
		std::vector<uint8_t> pk(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sk(0);
		std::vector<uint8_t> ss1(32);
		std::vector<uint8_t> ss2(32);
		size_t cptlen;
		size_t pklen;
		size_t seedlen;
		size_t sklen;
		size_t sslen;
		NistRng gen;

		cptlen = 0;
		pklen = 0;
		seedlen = 0;
		sklen = 0;

		NistPqParser::ParseNistCipherKat(KYBER2400, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);
		// 1. c= 1088, pk= 1184, sk= 2400
		gen.Initialize(seed);

		Kyber cpr1(KyberParameters::KYBERS32400, &gen);
		AsymmetricKeyPair* kp = cpr1.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -KK1"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -KK2"));
		}

		Kyber cpr2(KyberParameters::KYBERS32400, &gen);
		cpr2.Initialize(kp->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -KK3"));
		}

		cpr2.Initialize(kp->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -KK4"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -KK5"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp;
	}

	void KyberTest::KatK3168()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> kcpt(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> kss(32);
		std::vector<uint8_t> pk(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sk(0);
		std::vector<uint8_t> ss1(32);
		std::vector<uint8_t> ss2(32);
		size_t cptlen;
		size_t pklen;
		size_t seedlen;
		size_t sklen;
		size_t sslen;
		NistRng gen;

		cptlen = 0;
		pklen = 0;
		seedlen = 0;
		sklen = 0;

		NistPqParser::ParseNistCipherKat(KYBER3168, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);
		// 2. c= 1568, pk= 1568, sk= 3168
		gen.Initialize(seed);

		Kyber cpr1(KyberParameters::KYBERS53168, &gen);
		AsymmetricKeyPair* kp = cpr1.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -KK6"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -KK7"));
		}

		Kyber cpr2(KyberParameters::KYBERS53168, &gen);
		cpr2.Initialize(kp->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -KK8"));
		}

		cpr2.Initialize(kp->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -KK9"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -KK10"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp;
	}

	void KyberTest::KatK3936()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> kcpt(0);
		std::vector<uint8_t> kpk(0);
		std::vector<uint8_t> ksk(0);
		std::vector<uint8_t> kss(32);
		std::vector<uint8_t> pk(0);
		std::vector<uint8_t> seed(0);
		std::vector<uint8_t> sk(0);
		std::vector<uint8_t> ss1(32);
		std::vector<uint8_t> ss2(32);
		size_t cptlen;
		size_t pklen;
		size_t seedlen;
		size_t sklen;
		size_t sslen;
		NistRng gen;

		cptlen = 0;
		pklen = 0;
		seedlen = 0;
		sklen = 0;

		NistPqParser::ParseNistCipherKat(KYBER3936, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);
		// 3. c= 1920, pk= 1952, sk= 3936
		gen.Initialize(seed);

		Kyber cpr1(KyberParameters::KYBERS63936, &gen);
		AsymmetricKeyPair* kp = cpr1.Generate();

		if (kpk != kp->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -KK11"));
		}

		if (ksk != kp->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -KK12"));
		}

		Kyber cpr2(KyberParameters::KYBERS63936, &gen);
		cpr2.Initialize(kp->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -KK13"));
		}

		cpr2.Initialize(kp->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -KK14"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -KK15"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp;
	}

	void KyberTest::Kat()
	{
		KatK2400();
		KatK3168();
		KatK3936(); 
	}

	void KyberTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			Kyber cpr(KyberParameters::None);

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
			Kyber cpr(KyberParameters::KYBERS53168, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void KyberTest::PublicKey()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);

		// test param 1: KYBERS32400
		Kyber cpr1(KyberParameters::KYBERS32400);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<uint8_t> pk1 = kp1->PublicKey()->Polynomial();
		pk1[0] += 1;
		pk1[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(KyberParameters::KYBERS32400));
		cpr1.Initialize(pk2);
		cpr1.Encapsulate(cpt, sec1);

		cpr1.Initialize(kp1->PrivateKey());

		if (cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr1.Name(), std::string("Public key integrity test failed! -MP1"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp1;
		delete pk2;

		// test param 2: KYBERS53168
		Kyber cpr2(KyberParameters::KYBERS53168);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<uint8_t> pk3 = kp2->PublicKey()->Polynomial();
		pk3[0] += 1;
		pk3[1] += 1;
		AsymmetricKey* pk4 = new AsymmetricKey(pk3, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(KyberParameters::KYBERS53168));
		cpr2.Initialize(pk4);
		cpr2.Encapsulate(cpt, sec1);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -MP2"));
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		delete kp2;
		delete pk4;

		// test param 3: KYBERS63936
		Kyber cpr3(KyberParameters::KYBERS63936);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		// alter public key
		std::vector<uint8_t> pk5 = kp3->PublicKey()->Polynomial();
		pk5[0] += 1;
		pk5[1] += 1;
		AsymmetricKey* pk6 = new AsymmetricKey(pk5, AsymmetricPrimitives::Kyber, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(KyberParameters::KYBERS63936));
		cpr3.Initialize(pk6);
		cpr3.Encapsulate(cpt, sec1);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr3.Name(), std::string("Public key integrity test failed! -MP3"));
		}

		delete kp3;
		delete pk6;
	}

	void KyberTest::Serialization()
	{
		SecureVector<uint8_t> skey(0);
		size_t i;

		// test param 1: KYBERS32400
		Kyber cpr1(KyberParameters::KYBERS32400);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Private key serialization test has failed! -MR1"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Public key serialization test has failed! -MR2"));
			}

			delete kp;
			delete prik2;
			delete pubk2;
		}

		skey.clear();

		// test param 2: KYBERS53168
		Kyber cpr2(KyberParameters::KYBERS53168);

		for (i = 0; i < TEST_CYCLES; ++i)
		{

			AsymmetricKeyPair* kp = cpr2.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Private key serialization test has failed! -MR3"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr2.Name(), std::string("Public key serialization test has failed! -MR4"));
			}

			delete kp;
			delete prik2;
			delete pubk2;
		}

		skey.clear();

		// test param 3: KYBERS63936
		Kyber cpr3(KyberParameters::KYBERS63936);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr3.Generate();
			AsymmetricKey* prik1 = kp->PrivateKey();
			skey = AsymmetricKey::Serialize(*prik1);
			AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

			if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr3.Name(), std::string("Private key serialization test has failed! -MR5"));
			}

			AsymmetricKey* pubk1 = kp->PublicKey();
			skey = AsymmetricKey::Serialize(*pubk1);
			AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

			if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
			{
				throw TestException(std::string("Serialization"), cpr3.Name(), std::string("Public key serialization test has failed! -MR6"));
			}

			delete kp;
			delete prik2;
			delete pubk2;
		}
	}

	void KyberTest::Stress()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);
		SecureRandom gen;
		size_t i;

		Kyber cpr1(KyberParameters::KYBERS53168);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr1.Generate();

			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, sec1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -MT1"));
			}

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -MT2"));
			}

			delete kp;
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();

		Kyber cpr2(KyberParameters::KYBERS53168);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr2.Generate();

			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, sec1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test authentication has failed! -MT3"));
			}

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test has failed! -MT4"));
			}

			delete kp;
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();

		Kyber cpr3(KyberParameters::KYBERS63936);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			gen.Generate(sec1);
			AsymmetricKeyPair* kp = cpr3.Generate();

			cpr3.Initialize(kp->PublicKey());
			cpr3.Encapsulate(cpt, sec1);

			cpr3.Initialize(kp->PrivateKey());

			if (!cpr3.Decapsulate(cpt, sec2))
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test authentication has failed! -MT5"));
			}

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test has failed! -MT6"));
			}

			delete kp;
		}
	}

	void KyberTest::Initialize()
	{
	}

	void KyberTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
