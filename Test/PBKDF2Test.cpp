#include "PBKDF2Test.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/HMAC.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/PBKDF2.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA2256.h"
#include "../CEX/SHA2512.h"
#include "../CEX/SymmetricKeySize.h"

namespace Test
{
	using Exception::CryptoKdfException;
	using Tools::IntegerTools;
	using Kdf::PBKDF2;
	using Prng::SecureRandom;
	using Enumeration::SHA2Digests;
	using Cipher::SymmetricKeySize;

	const std::string PBKDF2Test::CLASSNAME = "PBKDF2Test";
	const std::string PBKDF2Test::DESCRIPTION = "PBKDF2 SHA-2 test vectors.";
	const std::string PBKDF2Test::SUCCESS = "SUCCESS! All PBKDF2 tests have executed succesfully.";

	PBKDF2Test::PBKDF2Test()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent(),
		m_salt(0)
	{
		Initialize();
	}

	PBKDF2Test::~PBKDF2Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_salt);
	}

	const std::string PBKDF2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &PBKDF2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string PBKDF2Test::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("PBKDF2Test: Passed PBKDF2 exception handling tests.."));

			PBKDF2* gen1 = new PBKDF2(SHA2Digests::SHA2256);
			PBKDF2* gen2 = new PBKDF2(SHA2Digests::SHA2512);

			// official SHA2256 vectors
			Kat(gen1, m_key[0], m_salt[0], m_expected[0], 1);
			Kat(gen1, m_key[0], m_salt[0], m_expected[1], 2);
			Kat(gen1, m_key[0], m_salt[0], m_expected[2], 4096);
			Kat(gen1, m_key[1], m_salt[1], m_expected[3], 4096);
			OnProgress(std::string("PBKDF2Test: Passed PBKDF2 SHA2256 KAT vector tests.."));

			// original SHA2512 vectors
			Kat(gen2, m_key[2], m_salt[2], m_expected[4], 1);
			Kat(gen2, m_key[2], m_salt[2], m_expected[5], 2);
			Kat(gen2, m_key[3], m_salt[3], m_expected[6], 1024);
			Kat(gen2, m_key[3], m_salt[3], m_expected[7], 4096);
			OnProgress(std::string("PBKDF2Test: Passed PBKDF2 SHA2512 KAT vector tests.."));

			gen1->Iterations() = 1;
			gen2->Iterations() = 1;

			Params(gen1);
			Params(gen2);
			OnProgress(std::string("PBKDF2Test: Passed initialization parameters tests.."));

			Stress(gen1);
			Stress(gen2);
			OnProgress(std::string("PBKDF2Test: Passed stress tests.."));

			delete gen1;
			delete gen2;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoKdfException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void PBKDF2Test::Exception()
	{
		// test constructor
		try
		{
			// invalid digest choice
			PBKDF2 gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE1"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			PBKDF2 gen(SHA2Digests::SHA2256);
			// invalid key size
			std::vector<byte> key(1);
			SymmetricKey kp(key);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE2"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -1
		try
		{
			PBKDF2 gen(SHA2Digests::SHA2256);
			std::vector<byte> otp(32);
			// generator was not initialized
			gen.Generate(otp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE3"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -2
		try
		{
			PBKDF2 gen(SHA2Digests::SHA2256);
			Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> otp(32);
			SymmetricKey kp(key);

			gen.Initialize(kp);
			// array too small
			gen.Generate(otp, 0, otp.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE4"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void PBKDF2Test::Initialize()
	{
		const std::vector<std::string> expected =
		{
			std::string("120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B"),
			std::string("AE4D0C95AF6B46D32D0ADFF928F06DD02A303F8EF3C251DFD6E2D85A95474C43"),
			std::string("C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A"),
			std::string("348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C4E2A1FB8DD53E1C635518C7DAC47E9"),

			std::string("A5BCEB9A38919829373125EFFC5D28B581C30B962B3ED944D5B4697738904D125AFB6D75164461AFE9E028B5AA12BFD51C574CD5B1F432F91818FF68B73E7D3E"),
			std::string("729DC0402BF66F858AA06BC18EE3493C6F2FD26A66CF7E0F406F58A8719FAA4AB24C718C5A03CCBBE7F588264B9AA236B11738713DBCD62AF652D5613EA1283B"),
			std::string("13497B2E1932A9F136CD708F9E91C7A83CD9EC1BE09677ABAF19469324FD03684F8C614D2DF6B5F0EFD30F26456BCAABA331F0B24A7A165D4D7428818F233046"),
			std::string("8DCEB67A3DDCE5F60598A76BEFD5136B42E635062C05E301CF8E6C0077F9712872B68E285BD6EE20B72A2B9CFD04147366381652E8AB5C9BA671CA800B1E51501057D79D17E69BB5CECF50F23BB361EF")
		};
		HexConverter::Decode(expected, 8, m_expected);

		const std::vector<std::string> key =
		{
			std::string("70617373776F7264"),
			std::string("70617373776F726450415353574F524470617373776F7264"),
			std::string("70617373776F726470617373776F7264"),
			std::string("70617373776F726450415353574F524470617373776F726470617373776F726450415353574F524470617373776F7264")
		};
		HexConverter::Decode(key, 4, m_key);

		const std::vector<std::string> salt =
		{
			std::string("73616C74"),
			std::string("73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414C5473616C74"),
			std::string("73616C7473616C74"),
			std::string("73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414C5473616C7473616C7453414C5473616C7453414C5473616C7453414C5473616C7453414C5473616C74")
		};
		HexConverter::Decode(salt, 4, m_salt);
	}

	void PBKDF2Test::Kat(IKdf* Generator, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, uint Iterations)
	{
		std::vector<byte> otp(Expected.size());
		dynamic_cast<PBKDF2*>(Generator)->Iterations() = Iterations;
		SymmetricKey kp(Key, Salt);

		Generator->Initialize(kp);
		Generator->Generate(otp);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Output does not match the known answer! -PK1"));
		}
	}

	void PBKDF2Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void PBKDF2Test::Params(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> otp1;
		std::vector<byte> otp2;
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp1.reserve(MAXM_ALLOC);
		otp2.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			otp1.resize(OTPLEN);
			otp2.resize(OTPLEN);
			rnd.Generate(key, 0, key.size());

			// generate with the kdf
			SymmetricKey kp(key);
			Generator->Initialize(kp);
			Generator->Generate(otp1, 0, OTPLEN);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Generate(otp2, 0, OTPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -HR1"));
			}
		}
	}

	void PBKDF2Test::Stress(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				otp.resize(OTPLEN);
				rnd.Generate(key, 0, key.size());

				// generate with the kdf
				SymmetricKey kp(key);
				Generator->Initialize(kp);
				Generator->Generate(otp, 0, OTPLEN);
				Generator->Reset();
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
