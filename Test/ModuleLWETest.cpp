#include "ModuleLWETest.h"
#include "NistRng.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/CryptoAuthenticationFailure.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/RingLWE.h"
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
	using Enumeration::MLWEParameters;
	using Asymmetric::Encrypt::MLWE::ModuleLWE;
	using Test::NistRng;
	using Prng::SecureRandom;

	const std::string ModuleLWETest::CLASSNAME = "ModuleLWETest";
	const std::string ModuleLWETest::DESCRIPTION = "ModuleLWE key generation, encryption, and decryption tests..";
	const std::string ModuleLWETest::SUCCESS = "SUCCESS! ModuleLWE tests have executed succesfully.";

	ModuleLWETest::ModuleLWETest()
		:
		m_progressEvent()
	{
	}

	ModuleLWETest::~ModuleLWETest()
	{
	}

	const std::string ModuleLWETest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ModuleLWETest::Progress()
	{
		return m_progressEvent;
	}

	std::string ModuleLWETest::Run()
	{
		try
		{
			Initialize();

			Kat();
			OnProgress(std::string("ModuleLWETest: Passed cipher-text and shared-secret known answer tests.."));


			Authentication();
			OnProgress(std::string("ModuleLWETest: Passed message authentication test.."));
			CipherText();
			OnProgress(std::string("ModuleLWETest: Passed cipher-text integrity test.."));
			Exception();
			OnProgress(std::string("ModuleLWETest: Passed exception handling test.."));
			PublicKey();
			OnProgress(std::string("ModuleLWETest: Passed public key integrity test.."));
			Serialization();
			OnProgress(std::string("ModuleLWETest: Passed key serialization tests.."));
			Stress();
			OnProgress(std::string("ModuleLWETest: Passed encryption and decryption stress tests.."));

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

	void ModuleLWETest::Authentication()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		cpr1.Initialize(kp1->PublicKey());
		cpr1.Encapsulate(cpt, sec1);
		cpr1.Initialize(kp1->PrivateKey());

		if (!cpr1.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr1.Name(), std::string("Message authentication test failed! -MA1"));
		}

		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpt.resize(0);

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);
		cpr2.Initialize(kp2->PrivateKey());

		if (!cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr2.Name(), std::string("Message authentication test failed! -MA2"));
		}

		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpt.resize(0);

		cpr3.Initialize(kp3->PublicKey());
		cpr3.Encapsulate(cpt, sec1);
		cpr3.Initialize(kp3->PrivateKey());

		if (!cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("Authentication"), cpr3.Name(), std::string("Message authentication test failed! -MA3"));
		}

		delete kp3;
	}

	void ModuleLWETest::CipherText()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);
		SecureRandom gen;

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
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

		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		cpt.resize(0);

		cpr2.Initialize(kp2->PublicKey());
		cpr2.Encapsulate(cpt, sec1);

		// alter ciphertext
		gen.Generate(cpt, 0, 4);

		cpr2.Initialize(kp2->PrivateKey());

		if (cpr2.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("CipherText"), cpr2.Name(), std::string("Cipher text integrity test failed! -MC2"));
		}

		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		cpt.resize(0);

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

	void ModuleLWETest::Kat()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> ssk1(32);
		std::vector<byte> ssk2(32);
		NistRng gen;

		// MLWES2Q7681N256

		gen.Initialize(m_cprseed);

		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256, &gen);
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

		// MLWES3Q7681N256

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);
		gen.Initialize(m_cprseed);

		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256, &gen);
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

		// MLWES4Q7681N256

		cpt.clear();
		ssk1.clear();
		ssk1.resize(32);
		ssk2.clear();
		ssk2.resize(32);
		gen.Initialize(m_cprseed);

		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256, &gen);
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

	void ModuleLWETest::Exception()
	{
		// test invalid constructor parameters
		try
		{
			ModuleLWE cpr(MLWEParameters::None);

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
			ModuleLWE cpr(MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::None);

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
			ModuleLWE cpr(MLWEParameters::MLWES3Q7681N256, Enumeration::Prngs::BCR);
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

	void ModuleLWETest::PublicKey()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(64);
		std::vector<byte> sec2(64);

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);
		AsymmetricKeyPair* kp1 = cpr1.Generate();

		// alter public key
		std::vector<byte> pk1 = kp1->PublicKey()->Polynomial();
		pk1[0] += 1;
		pk1[1] += 1;
		AsymmetricKey* pk2 = new AsymmetricKey(pk1, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES2Q7681N256));
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
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp1;

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);
		AsymmetricKeyPair* kp2 = cpr2.Generate();

		// alter public key
		std::vector<byte> pk3 = kp2->PublicKey()->Polynomial();
		pk3[0] += 1;
		pk3[1] += 1;
		AsymmetricKey* pk4 = new AsymmetricKey(pk3, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES3Q7681N256));
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
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);
		delete kp2;

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);
		AsymmetricKeyPair* kp3 = cpr3.Generate();

		// alter public key
		std::vector<byte> pk5 = kp3->PublicKey()->Polynomial();
		pk5[0] += 1;
		pk5[1] += 1;
		AsymmetricKey* pk6 = new AsymmetricKey(pk5, AsymmetricPrimitives::ModuleLWE, AsymmetricKeyTypes::CipherPublicKey, static_cast<AsymmetricTransforms>(MLWEParameters::MLWES4Q7681N256));
		cpr3.Initialize(pk6);
		cpr3.Encapsulate(cpt, sec1);

		cpr3.Initialize(kp3->PrivateKey());

		if (cpr3.Decapsulate(cpt, sec2))
		{
			throw TestException(std::string("PublicKey"), cpr3.Name(), std::string("Public key integrity test failed! -MP3"));
		}

		delete kp3;
	}

	void ModuleLWETest::Serialization()
	{
		SecureVector<byte> skey(0);

		// test param 1: MLWES2Q7681N256
		ModuleLWE cpr1(MLWEParameters::MLWES2Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
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
		}

		skey.clear();
		skey.resize(0);

		// test param 2: MLWES3Q7681N256
		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
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
		}

		skey.clear();
		skey.resize(0);

		// test param 3: MLWES4Q7681N256
		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
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
		}
	}

	void ModuleLWETest::Stress()
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		SecureRandom gen;

		ModuleLWE cpr1(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
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

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr1.Name(), std::string("Stress test has failed! -MT2"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		ModuleLWE cpr2(MLWEParameters::MLWES3Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
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

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr2.Name(), std::string("Stress test has failed! -MT4"));
			}
		}

		cpt.clear();
		sec1.clear();
		sec2.clear();
		cpt.resize(0);
		sec1.resize(64);
		sec2.resize(64);

		ModuleLWE cpr3(MLWEParameters::MLWES4Q7681N256);

		for (size_t i = 0; i < TEST_CYCLES / 3; ++i)
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

			delete kp;

			if (sec1 != sec2)
			{
				throw TestException(std::string("Stress"), cpr3.Name(), std::string("Stress test has failed! -MT6"));
			}
		}
	}

	void ModuleLWETest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> cprcpt =
		{
			std::string("7605192156310FD02891F471CE8E2AB934F2CAC69108936A85AADB23C27611459656DD601FCF2D5DB7B3C9ABC15835F2874A171598B1CB4A6901089FC63399E2"
				"C6EEE5671CAAA0597FC9D92ED40012D3201602310FFDC1A8ED534521F7A20F949331AD0D452556796869C38966AD88D50FE4F5DB32A48EF1350157BA59222996"
				"D4AE31079E5C988F367D64EE9F11A0051F1F79E12528D594769C7E69CF89A54CC5D3E668FC376B5BC870542F73F6F3AF71A575386A5B98A2D262E510BFC52368"
				"25DFB90989656EB1815209BB161F1CDEA9000B445C019CED8864BCD4B996DA8ADCEFC3EA1FFCDCE9323769B67B01BFB02D87F3F4E1E419DBC8A7E15C4121C2CB"
				"7DA11633A2B8EDF9CE487BC0D4772372E070A23A99B01ACC2ED8120E179B361E3D7C50F2FAF787794588E0509E815D6DF339492FCF3447DD5D1ECEB069F000DD"
				"7DF46CB64B58183035DCA0DAE2D7A41D18956AD503C90A54B40745211CCC85A8BCCB0A3E6F00B37C2D016F8331823442927CAF8CF6BF0C26A437E1CDDCBD1450"
				"208782420B8403596A2F1B8DA8FA611D89410771669578A780870954CDFE2924B1B920E050756D790D7B8AAAD5E043A50073EBA5C6880110321C4F593C753542"
				"F0C12D9987645085FB11E5CC8437591B7F88896C08A00BF0C2CB66B18CB8FB35194EAA3DF66A6CDD6EF10C176AFBBDC9F5D40B81CF675BC5BEF876150C75F0F1"
				"597CB97C8098D47A8E1A30516CD584267DFB663A27168BC4F88CD95F3A3CA1A2A652B5B26843EABD5D1626A9CF09E970F2B7EED8AA6C8FEC586DA2D35D62BF1E"
				"FF138D3CF1291CE33C9B9549DED6F4E309D25A519DFF7C008655ED33E53F8F3266D5809A7F7C6E48BBD21B2FE4D23943A07777D7DF0D3671C1597E17258D1B91"
				"C72A8DCD8893EB8FDC84780A5D998DA461173338C93FB11C61A3F82B6C508421FD107D27690366F492975B6D61D36C617ABA0B9027E4EDCD93C14A698AC82BBB"
				"83D0BD0484C5EB33AA60EFC7A10F16A9A818D038221A4F1037B117409E829912"),
			std::string("EADD5ADA14DA57F0AEF3505F1CAA6485D4238D999A3EF4B0A59A1CDBE0A27E478547A3A99D2AB09AC7D7C8F5AE3D6432045CBA3FA778345892542BD81C05BEFC"
				"D2E5CC9A579BEFB7C58D02FB94F33392FE17F4EBA2CB510EC74CC9D1D8A87C1066A4869A3983E664BFE9DEA5AE4FDF310C8F59815A678FA325F369AF84FFEBC1"
				"D150431FE3BD2734F636CF658E6C1A6A6E2CBE071F9A7C26119AD105098EDA622CAB8E176762109877D9AE9D6729D44A58E707D6B8AD6E696A33C672DA9D08DA"
				"2A7F9E3BF02218238722A46B31D49DAFF9AF00A6363C3A423B2E873DEFDDBCD969B75A81053D9A97C06DE2BFE3D0CFD3D3C77983B18DBDE23C0728604A71435A"
				"D40DF1579096DDBE02E4612210CAA034DCEFB8B4D7B5E6D2EBA37A79FB61F34B5AF7D9B27B13E4936222411249B7FBB69E73461DAF4AA6F3E2C73944F10CE67C"
				"86FED260BDA7B40DB39B1DE3C7D8F09A77F3C84BC62931D228B24A574AC3F4EB745CFF7E031A3FB2A08595C15370A3C82DB7D9F41BB1D8ECC429CFA3A6583301"
				"6AB6EA60C9390CFA1B65CCEAE550940795386ED24133FBAE8B3017502AF3CFE951D781D36CFEFF85BFDF5AF040BE4065681B3B0A63C2747F0808CF3DA725169D"
				"DED1003DA6CD5DE4CB041942938D0A7F8802D48F2E3C6EEB45CD90AF6FC9F4507E9F8380AC33CACA7751487F65500441D920B94880A497D01C0802BB08D74C5D"
				"4C6BF2D865EE5822B3375C755D1A5E3D3244C320510A1E30357702CD4252072CF86437F7A9DE5561C7E59B94B9584100131AC399F4C1EB19FB4BDF65E62785E9"
				"7C194B8764CCF32FD05D804C2E439DDA2A109274FBFFA81A837C51B26D154F974B882A5B174B308FC48768D222922532B183ABDF6FBB0BC7492766974D321EE6"
				"FB7C5F7B3EEA2378DC6D6BB48019250B8D8D8DEDB522421AEEDB318676982A80E7961EC40E6D7F3339694255BAFF51BE3A7EA7D8793A109BE3AE4423BF082E20"
				"6A573B4F0F93FC16DDE81BD5DC583F528C08A0A9AB8E6CD524E297C9CF0F43C344913830ECB16F91441477BA782EDD4E73E732979D3A664EB99EA5D24B6C84AA"
				"69F377CB0CAD5AE4E641E38B197A0994D58B2387E91760E9B6FEBCB445CF85BBA24A94CDA75E338674428249FE6DE4692601D1EAE0EA021D9BC8077BE8665D07"
				"37748FA30FCF80F7E482584674F633A5006A538267627FD91854E0871268A6B0B05DD51495135DEFB9376E9B841B64E5DBF43CE6C74BCF3AE1FC427E810B7CBF"
				"6957DBF904690E87842543897DE78F13D08D92EBD27FB2CFCC0C765430589057B16B15F207CA1E6F08D52616DD57AD43EFEA6FDDAAEA18D33731FAC7ECAAE950"
				"E1DF3C5A4E6FCB223DF5E86B487FD7092D0822EFFAEC82C4BEC10C600FDB90E77482911B1595277738841409D0F8F113191D47F5E56C115A05DEA759AA6FB1D0"
				"47F9FCA4ED519EA5D21FE3BA5B9434FEA1283DFAD63D01589B0EB61F244351D03341DCD4DF62265AFCAEC6676A877D5CACB359EBB5319610DD447DA97E950B0C"),
			std::string("C27F01244D4B3FB21D8437F840017CCCB7B7DAD5FB2B47B9B57EAE4F77D0A4555E5092A24969F2273E9702884A08477B568D8017F13875D1F5A6D413BDD228EB"
				"B11260F7F4529CBCEBF9B6862E8A841235F29F60F8E8417434189D579920FE6B98DBE713EC16C3FDDBB81E731D956B06DB4980F49C26F28661FF9CE6E9D861EC"
				"7A09840C19DE0EB6722071F8AA48362D2FF127A4AE46F99337826832ADAC239165F22585BB57A889C9C6AF82367EC7B07237C0535B31B38C1CAC40AC1A0C958A"
				"1887FE34711083FD37AF4BC5B1B4E1E2EE2843693D57DD1E657D4C24ED207EE712AD2A0891458180E9E8BD36FC14D8D633F5B741CEA108D2D4FD751C5A67B05E"
				"30324A67E9DD75C993D4FE0854FB78DF6F3D45A2A9C8E42510F0C3D80203712FB39E36B5DD8B5CCD3D09CEA94203BAF872084571ECF978BDB9548A250EE4907B"
				"4AFC31B21F319AE4BF0AB19CBD11EBE13359D1AAF4FDB83B6502501422A5FE50A8A38EF53DEB603CE23FD9792B04DEB378719AB769AA5897CC65E9B16304CEA5"
				"37E1762BD8C9B109DA14A829E6419F1B9FF8A466E2A6D6B34D74FFE1A59299181759D0D387FCED1D907F5FB5EDB426C05130E6CA5909B276D1A47E713C30D996"
				"DA5E8E57E712C77738F21BE74B42B518432DAD7EF73E6A8C43AA9A626994D71A31812851806E9FBB1F2BD356CEA39D95F2F87CA30DAF6F2733F7BCE79F8DA995"
				"051E49A7FD2264379C0A752E553ED608EB9344C79498F691538564C54F823BB70B12B59E8824B4A4BB1EEAC67C810CCC2E23744783CE958097F7A6BC6E1F1759"
				"7521B8C3D1EE8596A29FFEF14ED91632097C16D5065DB2A963CA7383AC60AD8F4ED0D41BD0BC3BAF198C5125AE911506C926D4C11785FD618229BFF54CB1161A"
				"B8FC7B51DAECCCD9131EDF437D8E528E7581B82C660E8C5E2512D5F6380A528F2AE4AEE263DB9676024BC7AD398BC9CDDAD607968BBAB22329E04D6E771FE647"
				"107AC46667A51AD558A635F026951F4F48C888D701C2AFF4EAB4E34ADB159ABBBFABE59B3F4CF8AAB1DD661E4DD0C5558DC059202EE64625A3B4B92FF4D15697"
				"F16C18D4D2338CFB496E0703526871C9784BAC8EBAE8279CF2713AF3CC2D440E8CD200867B8518AAD3B9E285027DA0ADD9F0229ED4E842D05E226ADAC13A3952"
				"E3835C8FB0A42874C94C661B39DF7B72887D227D583CE6B3BD65F795107BD093389BFEFD1768A5716F685B174ED23E94A5956E29BB2DDB792103E62F68928ACC"
				"603EEC2FF56DB14C08B7CBE4E2B4F2E0EAEE54162E95BB35EF36303EE3E6CC61061373876F7A096A8AF57D782F8C8203DE93423A379122FE7DAD770C3690F978"
				"228460D025CE93B1B336C573E4E55840EA65CFDD6122C672C912F52939D9EA5BE06210F5E7EDB65B66945D7056F559A7D69253F4BDBC579DE964F3E93A86FA38"
				"B6A2C0B54338DCE093F0B4684EE361449F16C279A72B7731E44600A7027768FDD0F643ED10064B98A9DA032F1F5DEAD311E177335094DB4E38514EAE15A8F8EC"
				"F2F2414E378EFBF997B1066B6F69D66909A47E298A7FEC961A83782E0E470FE071DECF4B26ACA6ED688359E1085055FD2B5AE9F4918749897AF133606053D5F6"
				"A8528CCB31AB7F3F2D89A95C5F05B15700E532AD81D59D9DB8A2C29CAC936E3F33DFE24B0B1B71902DC9C30EC8C70BDABA484FCD2B946D735F16EEAD04031CAF"
				"DE9EE01696EC9F0A8D5F36B69C642FFD0AD0D2544F5E7FD89A80498EF68E181617FAD41E0BD59BAAFFEEFE2F99724C719D47A2ECBA721D76F237EBA73DB47D88"
				"B699E3582B073C7EAD2A5B3CF024466396F9F2826CB754F66018E9503F4AD1F9D92121AA9956506051D596FFD467E1AA8D964C1767C925B468BBC9850600C843"
				"490541E8555A3D8BD9F18791EF9EBD3594E74C1FE3D3B80940A8A079F8D2CA8D30134FC66F87008126E43BD06EB6E41C3A70FA4739319BF1A932F02C30645656"
				"0CDA44DDAC43ED6D900445F5BF85BB0CE325947436E0D0685E41B16BC7169518259E5734FDCE080FFE85191B1D8D8DE4DB48143FB564038ACE80104D3A8D0712"
				"45E2AA56C71933F4DCF925EEE844C80FDDF3251F74006A23413318BBFD2ED9E05351B5AAEBCC77CFAC8D5F0364231A50EA8647C72F713E817A2075323029E3B8"
				"8B72442264C597B0F1FC09F9401CE88AC97C5522A56364523C37FEA2D6BD06B2")
		};
		HexConverter::Decode(cprcpt, 3, m_cptexp);

		const std::vector<std::string> cprexp =
		{
			std::string("D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E"),
			std::string("ED20140C05D78B15F2E412671A84154217FD77619A2C522D3C3CB688CB34C68B"),
			std::string("FBC4EEA691EEF4C1B476A29936453F4C3D4881794EE37BAF0FD72840743E7B7D")
		};
		HexConverter::Decode(cprexp, 3, m_sskexp);

		const std::string cprseed =
		{
			std::string("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"),
		};
		HexConverter::Decode(cprseed, m_cprseed);

		/*lint -restore */
	}

	void ModuleLWETest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
