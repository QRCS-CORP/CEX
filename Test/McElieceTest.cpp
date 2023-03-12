#include "McElieceTest.h"
#include "NistRng.h"
#include "NistPqParser.h"
#include "TestFiles.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/McEliece.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using CEX::Asymmetric::AsymmetricKey;
	using CEX::Asymmetric::AsymmetricKeyPair;
	using CEX::Asymmetric::Encrypt::MPKC::McEliece;
	using CEX::Enumeration::AsymmetricKeyTypes;
	using CEX::Enumeration::AsymmetricPrimitives;
	using CEX::Enumeration::AsymmetricParameters;
	using CEX::Enumeration::McElieceParameters;
	using CEX::Exception::CryptoAsymmetricException;
	using CEX::Tools::IntegerTools;
	using Test::NistPqParser;
	using Test::NistRng;
	using CEX::Prng::SecureRandom;
	using namespace Test::TestFiles::NISTPQ3;

	const std::string McElieceTest::CLASSNAME = "McElieceTest";
	const std::string McElieceTest::DESCRIPTION = "McEliece key generation, encryption, and decryption tests.";
	const std::string McElieceTest::SUCCESS = "SUCCESS! McEliece tests have executed succesfully.";

	McElieceTest::McElieceTest()
		:
		m_rngexp(0),
		m_rngkey(0),
		m_progressEvent()
	{
	}
	
	McElieceTest::~McElieceTest()
	{
		IntegerTools::Clear(m_rngexp);
		IntegerTools::Clear(m_rngkey);
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
			Initialize();

			NistRngKat();
			OnProgress(std::string("McElieceTest: Passed the Nist Rng known answer test.."));
			Authentication();
			OnProgress(std::string("McElieceTest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("McElieceTest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("McElieceTest: Passed exception handling test.."));
			Kat();
			OnProgress(std::string("McElieceTest: Passed cipher-text and shared-secret known answer tests.."));
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
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void McElieceTest::Authentication()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> ssk1(32);
		std::vector<uint8_t> ssk2(32);

		McEliece cpr2(McElieceParameters::MPKCS3N4608T96);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());

		// decapsulate with altered ciphertext, throw if succesful
		if (!cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}
	}

	void McElieceTest::CipherText()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> ssk1(32);
		std::vector<uint8_t> ssk2(32);
		SecureRandom gen;

		// MPKCS2N6960T119

		cpt.clear();
		ssk1.clear();
		ssk2.clear();

		McEliece cpr2(McElieceParameters::MPKCS3N4608T96);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		// alter ciphertext
		gen.Generate(cpt, 0, 4);
		cpr2.Initialize(kp2->PrivateKey());

		// decapsulate with altered ciphertext, throw if succesful
		if (cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		delete kp2;
	}

	void McElieceTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			McEliece cpr(McElieceParameters::None);

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
			McEliece cpr(McElieceParameters::MPKCS3N4608T96, Enumeration::Prngs::None);

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

	void McElieceTest::KatN4608T96()
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

		NistPqParser::ParseNistCipherKat(MCELIECE460896, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);

		gen.Initialize(seed);

		McEliece cpr1(McElieceParameters::MPKCS3N4608T96, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		if (kpk != kp1->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -MK1"));
		}

		if (ksk != kp1->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -MK2"));
		}

		McEliece cpr2(McElieceParameters::MPKCS3N4608T96, &gen);
		cpr2.Initialize(kp1->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -MK3"));
		}

		cpr2.Initialize(kp1->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -MK4"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -MK5"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp1;
	}

	void McElieceTest::KatN6960T119()
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

		NistPqParser::ParseNistCipherKat(MCELIECE6960119, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);

		gen.Initialize(seed);

		McEliece cpr1(McElieceParameters::MPKCS3N6960T119, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		if (kpk != kp1->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -MK6"));
		}

		if (ksk != kp1->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -MK7"));
		}

		McEliece cpr2(McElieceParameters::MPKCS3N6960T119, &gen);
		cpr2.Initialize(kp1->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -MK8"));
		}

		cpr2.Initialize(kp1->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -MK9"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -MK10"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp1;
	}

	void McElieceTest::KatN6688T128()
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

		NistPqParser::ParseNistCipherKat(MCELIECE6688128, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);

		gen.Initialize(seed);

		McEliece cpr1(McElieceParameters::MPKCS4N6688T128, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		if (kpk != kp1->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -MK11"));
		}

		if (ksk != kp1->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -MK12"));
		}

		McEliece cpr2(McElieceParameters::MPKCS4N6688T128, &gen);
		cpr2.Initialize(kp1->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -MK13"));
		}

		cpr2.Initialize(kp1->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -MK14"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -MK15"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp1;
	}

	void McElieceTest::KatN8192T128()
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

		NistPqParser::ParseNistCipherKat(MCELIECE8192128, seed, &seedlen, kpk, &pklen, ksk, &sklen, kcpt, &cptlen, kss, &sslen, 0);

		gen.Initialize(seed);

		McEliece cpr1(McElieceParameters::MPKCS5N8192T128, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		if (kpk != kp1->PublicKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected public key test! -MK16"));
		}

		if (ksk != kp1->PrivateKey()->Polynomial())
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed expected private key test! -MK17"));
		}

		McEliece cpr2(McElieceParameters::MPKCS5N8192T128, &gen);
		cpr2.Initialize(kp1->PublicKey());
		cpr2.Encapsulate(cpt, ss1);

		if (cpt != kcpt)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed cipher-text test! -MK18"));
		}

		cpr2.Initialize(kp1->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ss2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -MK19"));
		}

		if (ss1 != kss || ss1 != ss2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -MK20"));
		}

		cpt.clear();
		ss1.clear();
		ss2.clear();
		delete kp1;
	}

	void McElieceTest::Kat()
	{
		KatN4608T96();
		KatN6960T119();
		KatN6688T128();
		KatN8192T128();
	}

	void McElieceTest::NistRngKat()
	{
		std::vector<uint8_t> exp(m_rngexp[0].size());

		NistRng gen;
		gen.Initialize(m_rngkey);
		gen.Generate(exp, 0, exp.size());

		if (exp != m_rngexp[0])
		{
			throw TestException(std::string("McElieceTest"), std::string("NistRngKat"), std::string("Arrays do not match! -MN1"));
		}

		gen.Generate(exp, 0, exp.size());

		if (exp != m_rngexp[1])
		{
			throw TestException(std::string("McElieceTest"), std::string("NistRngKat"), std::string("Arrays do not match! -MN2"));
		}
	}

	void McElieceTest::PublicKey()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> ssk1(32);
		std::vector<uint8_t> ssk2(32);
		SecureRandom gen;

		cpt.clear();
		ssk1.clear();
		ssk2.clear();

		McEliece cpr2(McElieceParameters::MPKCS3N4608T96);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<uint8_t> pk2 = kp2->PublicKey()->Polynomial();
		gen.Generate(pk2, 0, 4096);

		AsymmetricKey* ak2 = new AsymmetricKey(pk2, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricParameters>(McElieceParameters::MPKCS3N4608T96));
		cpr2.Initialize(ak2);
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -MP2"));
		}

		delete kp2;
		delete ak2;
	}

	void McElieceTest::Serialization()
	{
		SecureVector<uint8_t> skey(0);

		McEliece cpr(McElieceParameters::MPKCS3N4608T96);
		AsymmetricKeyPair* kp = cpr.Generate();
		AsymmetricKey* prik1 = kp->PrivateKey();
		skey = AsymmetricKey::Serialize(*prik1);
		AsymmetricKey* prik2 = AsymmetricKey::DeSerialize(skey);

		if (prik1->Polynomial() != prik2->Polynomial() || prik1->Parameters() != prik2->Parameters())
		{
			throw TestException(std::string("Serialization"), cpr.Name(), std::string("Private key serialization test has failed! -MR1"));
		}

		AsymmetricKey* pubk1 = kp->PublicKey();
		skey = AsymmetricKey::Serialize(*pubk1);
		AsymmetricKey* pubk2 = AsymmetricKey::DeSerialize(skey);

		if (pubk1->Polynomial() != pubk2->Polynomial() || pubk1->Parameters() != pubk2->Parameters())
		{
			throw TestException(std::string("Serialization"), cpr.Name(), std::string("Public key serialization test has failed! -MR2"));
		}

		delete kp;
		delete prik2;
		delete pubk2;
	}

	void McElieceTest::Stress()
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> ssk1(32, 0xFF);
		std::vector<uint8_t> ssk2(32);
		AsymmetricKeyPair* kp;

		McEliece cpr1(McElieceParameters::MPKCS3N4608T96);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			kp = cpr1.Generate();
			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, ssk1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, ssk2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -MS3"));
			}

			if (ssk1 != ssk2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -MS4"));
			}

			delete kp;
		}
	}

	//~~~Private Functions~~~//

	void McElieceTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> rngexp =
		{
			std::string("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA19810F5392D076276EF41277C3AB6E94A"),
			std::string("04562AD35E8ECAFAAFDA16981CDAA147606BEEA62801342AF13C8B5535F72F9495B74317C762F0ADAB7ABE710797612176B61B0E208398113CF9C170157BC75F")
		};
		HexConverter::Decode(rngexp, 2, m_rngexp);

		const std::string rngkey =
		{
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"),
		};
		HexConverter::Decode(rngkey, m_rngkey);

		/*lint -restore */
	}

	void McElieceTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
