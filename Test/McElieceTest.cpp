#include "McElieceTest.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/McEliece.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Enumeration::AsymmetricKeyTypes;
	using Enumeration::AsymmetricPrimitives;
	using Enumeration::AsymmetricTransforms;
	using Exception::CryptoAsymmetricException;
	using Asymmetric::Encrypt::MPKC::McEliece;
	using Enumeration::MPKCParameters;
	using Test::NistRng;
	using Prng::SecureRandom;

	const std::string McElieceTest::CLASSNAME = "McElieceTest";
	const std::string McElieceTest::DESCRIPTION = "McEliece key generation, encryption, and decryption tests.";
	const std::string McElieceTest::SUCCESS = "SUCCESS! McEliece tests have executed succesfully.";

	McElieceTest::McElieceTest()
		:
		m_cptexp(0),
		m_sskexp(0),
		m_cprseed(0),
		m_rngexp(0),
		m_rngkey(0),
		m_progressEvent()
	{
	}
	
	McElieceTest::~McElieceTest()
	{
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
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);

		// MPKCS1N4096T62

		McEliece cpr1(MPKCParameters::MPKCS1N4096T62);
		AsymmetricKeyPair* kp1 = cpr1.Generate();
		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, ssk1);
		cpr1.Initialize(kp1->PrivateKey());
		delete kp1;

		// decapsulate
		if (!cpr1.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -MA1"));
		}

		// MPKCS1N6960T119

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr2(MPKCParameters::MPKCS1N6960T119);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());
		delete kp2;

		// decapsulate with altered ciphertext, throw if succesful
		if (!cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		// MPKCS1N8192T128

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr3(MPKCParameters::MPKCS1N8192T128);
		AsymmetricKeyPair* kp3 = cpr3.Generate();
		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, ssk1);
		cpr3.Initialize(kp3->PrivateKey());
		delete kp3;

		// decapsulate with altered ciphertext, throw if succesful
		if (!cpr3.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr3.Name(), std::string("Message authentication test failed! -MA3"));
		}
	}

	void McElieceTest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);
		SecureRandom gen;

		// MPKCS1N4096T62

		McEliece cpr1(MPKCParameters::MPKCS1N4096T62);
		AsymmetricKeyPair* kp1 = cpr1.Generate();
		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, ssk1);
		// alter ciphertext
		gen.Generate(cpt, 0, 4);
		cpr1.Initialize(kp1->PrivateKey());
		delete kp1;

		// decapsulate with altered ciphertext, throw if succesful
		if (cpr1.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -MA1"));
		}

		// MPKCS1N6960T119

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr2(MPKCParameters::MPKCS1N6960T119);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		// alter ciphertext
		gen.Generate(cpt, 0, 4);
		cpr2.Initialize(kp2->PrivateKey());
		delete kp2;

		// decapsulate with altered ciphertext, throw if succesful
		if (cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		// MPKCS1N8192T128

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr3(MPKCParameters::MPKCS1N8192T128);
		AsymmetricKeyPair* kp3 = cpr3.Generate();
		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, ssk1);
		// alter ciphertext
		gen.Generate(cpt, 0, 4);
		cpr3.Initialize(kp3->PrivateKey());
		delete kp3;

		// decapsulate with altered ciphertext, throw if succesful
		if (cpr3.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Authentication"), cpr3.Name(), std::string("Message authentication test failed! -MA3"));
		}
	}

	void McElieceTest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			McEliece cpr(MPKCParameters::None);

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
			McEliece cpr(MPKCParameters::MPKCS1N4096T62, Enumeration::Prngs::None);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME2"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			McEliece cpr(MPKCParameters::MPKCS1N4096T62, Enumeration::Prngs::BCR);
			Asymmetric::Encrypt::RLWE::RingLWE cprb;
			// create an invalid key set
			AsymmetricKeyPair* kp = cprb.Generate();
			cpr.Initialize(kp->PrivateKey());

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -ME3"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void McElieceTest::Kat()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);
		NistRng gen;

		// MPKCS1N4096T62

		gen.Initialize(m_cprseed);

		McEliece cpr1(MPKCParameters::MPKCS1N4096T62, &gen);
		AsymmetricKeyPair* kp1 = cpr1.Generate();
		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, ssk1);
		cpr1.Initialize(kp1->PrivateKey());

		if (!cpr1.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Failed authentication test! -MK1"));
		}

		if (ssk1 != ssk2)
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secrets do not match! -MK2"));
		}

		if (ssk1 != m_sskexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Shared secret does not match expected! -MK3"));
		}

		if (cpt != m_cptexp[0])
		{
			throw TestException(std::string("Kat"), cpr1.Name(), std::string("Cipher-text arrays do not match! -MK4"));
		}

		// MPKCS1N6960T119

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);
		gen.Initialize(m_cprseed);

		McEliece cpr2(MPKCParameters::MPKCS1N6960T119, &gen);
		AsymmetricKeyPair* kp2 = cpr2.Generate();
		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());

		if (!cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Failed authentication test! -MK5"));
		}

		if (ssk1 != ssk2)
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Shared secrets do not match! -MK6"));
		}

		if (ssk1 != m_sskexp[1])
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Shared secret does not match expected! -MK7"));
		}

		if (cpt != m_cptexp[1])
		{
			throw TestException(std::string("Kat"), cpr2.Name(), std::string("Cipher-text arrays do not match! -MK8"));
		}

		// MPKCS1N8192T128

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);
		gen.Initialize(m_cprseed);

		McEliece cpr3(MPKCParameters::MPKCS1N8192T128, &gen);
		AsymmetricKeyPair* kp3 = cpr3.Generate();
		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, ssk1);
		cpr3.Initialize(kp3->PrivateKey());

		if (!cpr3.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("Kat"), cpr3.Name(), std::string("Failed authentication test! -MK9"));
		}

		if (ssk1 != ssk2)
		{
			throw TestException(std::string("Kat"), cpr3.Name(), std::string("Shared secrets do not match! -MK10"));
		}

		if (ssk1 != m_sskexp[2])
		{
			throw TestException(std::string("Kat"), cpr3.Name(), std::string("Shared secret does not match expected! -MK11"));
		}

		if (cpt != m_cptexp[2])
		{
			throw TestException(std::string("Kat"), cpr3.Name(), std::string("Cipher-text arrays do not match! -MK12"));
		}
	}

	void McElieceTest::NistRngKat()
	{
		std::vector<byte> exp(m_rngexp[0].size());

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
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(64);
		std::vector<byte> ssk2(64);
		SecureRandom gen;

		// MPKCS1N4096T62

		McEliece cpr1(MPKCParameters::MPKCS1N4096T62);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> pk1 = kp1->PublicKey()->Polynomial();
		gen.Generate(pk1, 0, 2048);

		AsymmetricKey* ak1 = new AsymmetricKey(pk1, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MPKCParameters::MPKCS1N4096T62));
		cpr1.Initialize(ak1);
		cpr1.Encapsulate(cpt, ssk1);
		cpr1.Initialize(kp1->PrivateKey());
		delete kp1;

		// fail on decapsulation success
		if (cpr1.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("PublicKey"), cpr1.Name(), std::string("Public key integrity test failed! -MP1"));
		}

		// MPKCS1N6960T119

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr2(MPKCParameters::MPKCS1N6960T119);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> pk2 = kp2->PublicKey()->Polynomial();
		gen.Generate(pk2, 0, 4096);

		AsymmetricKey* ak2 = new AsymmetricKey(pk2, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MPKCParameters::MPKCS1N6960T119));
		cpr2.Initialize(ak2);
		cpr2.Encapsulate(cpt, ssk1);
		cpr2.Initialize(kp2->PrivateKey());
		delete kp2;

		if (cpr2.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("PublicKey"), cpr2.Name(), std::string("Public key integrity test failed! -MP2"));
		}

		// MPKCS1N8192T128

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);

		McEliece cpr3(MPKCParameters::MPKCS1N8192T128);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		// alter public key
		std::vector<byte> pk3 = kp3->PublicKey()->Polynomial();
		gen.Generate(pk3, 0, 8192);

		AsymmetricKey* ak3 = new AsymmetricKey(pk3, AsymmetricPrimitives::McEliece, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MPKCParameters::MPKCS1N8192T128));
		cpr3.Initialize(ak3);
		cpr3.Encapsulate(cpt, ssk1);
		cpr3.Initialize(kp3->PrivateKey());
		delete kp3;

		if (cpr3.Decapsulate(cpt, ssk2))
		{
			throw TestException(std::string("PublicKey"), cpr3.Name(), std::string("Public key integrity test failed! -MP3"));
		}
	}

	void McElieceTest::Serialization()
	{
		SecureVector<byte> skey(0);

		McEliece cpr(MPKCParameters::MPKCS1N4096T62);
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
		delete prik1;
		delete pubk1;
	}

	void McElieceTest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);
		McEliece cpr1(MPKCParameters::MPKCS1N4096T62);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr1.Generate();
			cpr1.Initialize(kp->PublicKey());
			cpr1.Encapsulate(cpt, ssk1);

			cpr1.Initialize(kp->PrivateKey());

			if (!cpr1.Decapsulate(cpt, ssk2))
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test authentication has failed! -MS1"));
			}

			delete kp;

			if (ssk1 != ssk2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -MS2"));
			}
		}

		ssk1.clear();
		ssk2.clear();
		ssk1.resize(32);
		ssk2.resize(32);
		McEliece cpr2(MPKCParameters::MPKCS1N6960T119);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr2.Generate();
			cpr2.Initialize(kp->PublicKey());
			cpr2.Encapsulate(cpt, ssk1);

			cpr2.Initialize(kp->PrivateKey());

			if (!cpr2.Decapsulate(cpt, ssk2))
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test authentication has failed! -MS3"));
			}

			delete kp;

			if (ssk1 != ssk2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test has failed! -MS4"));
			}
		}

		ssk1.clear();
		ssk2.clear();
		ssk1.resize(32);
		ssk2.resize(32);
		McEliece cpr3(MPKCParameters::MPKCS1N8192T128);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			AsymmetricKeyPair* kp = cpr3.Generate();
			cpr3.Initialize(kp->PublicKey());
			cpr3.Encapsulate(cpt, ssk1);

			cpr3.Initialize(kp->PrivateKey());

			if (!cpr3.Decapsulate(cpt, ssk2))
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test authentication has failed! -MS5"));
			}

			delete kp;

			if (ssk1 != ssk2)
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test has failed! -MS6"));
			}
		}
	}

	//~~~Private Functions~~~//

	void McElieceTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: this is the old shared-key expected when using the first seed of the Nist PQ round 1 version:
		// old shared-key: E1ED829F7190FF7932035761BBA154AB36BE888349FC6684FD15A50A1D82E179
		// I am using the newer version of the cipher as posted to SuperCop version 2019-01-10.
		// Significant changes were made to the secret-key generation by the authors in this newer version,
		// which has caused the cipher outputs to change.
		// However, this SuperCop version is recommended by the authors.
		// The authors website: https://classic.mceliece.org/software.html

		// There is yet a third version of these ciphers as recently posted to the Nist PQ Round 2 forum,
		// but as this seems to be at least temporarily unstable as it undergoes improvements through round 2,
		// I have for the time being decided to use the SuperCop version of the cipher.
		// rng seed: 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
		// new shared-key outputs, nist seeds 0,1,2
		// 4C7ABB9813DA435D12F5FC5A28673C59661F15BCDDFDA1D41CBD9F715DC5A74B
		// C2F94289EBA9ACAF2C132D1D0130311CA9FB7712F7802536BF836AC8C94AC822
		// 1F271CF0A51C89E8507368C4DF7CE2CFB864B17072B9FACBD7C2271756F24BF1

		const std::vector<std::string> cprcpt =
		{
			std::string("9F5705C11979DE1F574BC3755BDF872FC218690E8092B6D764C968393D119DDB9AB0CDBA25CB16465617592F2256E0E5D9E2A61993BE4049E4266CE93E500386"
				"39F976110549E8BC0F4F08F980FB71950815F99DCC100AAFE5FB454874C7350CA326448B4185AF1DE66C2C0A9129C9CDAEB126EBA1A0A5067CF0380A4640F1F0"
				"D8C8A95BC01D458F4149C979BD"),
			std::string("056DACA18318D82849759ED3C816C45821186E6AA763A018C5A40AA29593A6C312A30CE36FB3C30BC4E2A4AFD1C7B06514E9FE59678A0F2A14F09B0645F9EC98"
				"0D406790DE6775781E3136A248D4588D60344F73CB4E3C567DE64BBE588C7C549A9E3585EF98A5F55C3B9BAD7418932CB8966EC08B28B3A2A30B5C9067DFC854935DD041"
				"0D19BB24BF7086C0BCAB2DD0A69D25A15B5A685936855F05BFA7CA9CF9E58557B3AE8D4EBC8853B32FD52AD1DF66D6576CB69D58CFC8915BCC9D1C101602430E3F44F481"
				"35F4370B0959B02E891F597C5BFBD340154BA8E9233DE6CE1FAF"),
			std::string("9583F9C0E887851BE079E0AEF65CC7F6C11482AA537E99EAD8865C3B5E65821468C4687CDF017C9FCF2B318238A975199D05E7FE51034585B26B54F3E3E99C41"
				"0BCDC090A736BDBFC34C400402A9860E39438DEA312379EFE4DAE5CFCD7280CA978F8A96B96397C02B8518D11615FFA8B26D74A85406138199E6F4B8B4A683FB"
				"966398F5EDAC38557D73A127816B06443BDE6524A936C2C0DA8EFDDDB3850F522F0A26FC3DC3BCBBFFB32A0AD0FD156A8F3192D45B10B48647C546F8C5DB3F0D"
				"1AEAA192D88493AE6C1F1E9C253342551094F5643697600DCB99758E6D06375DCA20005FEBABBDC3A894CF676EB51992")
		};
		HexConverter::Decode(cprcpt, 3, m_cptexp);

		const std::vector<std::string> cprexp =
		{
			std::string("9DF29F0FC955C8A1280752039E090DC1A27E5A829D435CEC247EB347AB897A67"),
			std::string("179C2314367D02DCC0CF1C1CCF7055FB870CB26F529BBD4A393D6603FE70AE95"),
			std::string("DD1A7EC5E1026D5A77210F1374219018FC1C6CFD6BADF848A860C4749424D344")
		};
		HexConverter::Decode(cprexp, 3, m_sskexp);

		const std::string cprseed =
		{
			std::string("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"),
		};
		HexConverter::Decode(cprseed, m_cprseed);

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
