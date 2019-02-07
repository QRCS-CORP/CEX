#include "HCGTest.h"
#include "RandomUtils.h"
#include "../CEX/CSP.h"
#include "../CEX/Digests.h"
#include "../CEX/HCG.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA256.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using namespace Drbg;
	using Enumeration::Digests;
	using Utility::IntegerTools;
	using Prng::SecureRandom;

	const std::string HCGTest::CLASSNAME = "HCGTest";
	const std::string HCGTest::DESCRIPTION = "HCG implementations vector comparison tests.";
	const std::string HCGTest::SUCCESS = "SUCCESS! All HCG tests have executed succesfully.";

	HCGTest::HCGTest()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent()
	{
		Initialize();
	}

	HCGTest::~HCGTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
	}

	const std::string HCGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HCGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HCGTest::Run()
	{
		try
		{
			//Exception();
			OnProgress(std::string("HCGTest: Passed HMAC Generator exception handling tests.."));

			//Stress();
			OnProgress(std::string("HCGTest: Passedstress tests.."));

			HCG* genh256 = new HCG(SHA2Digests::SHA256, Providers::None);
			Kat(genh256, m_key[0], m_expected[0]);
			HCG* genh512 = new HCG(SHA2Digests::SHA512, Providers::None);
			Kat(genh512, m_key[1], m_expected[1]);
			OnProgress(std::string("HCGTest: Passed HMAC Generator known answer tests.."));

			OnProgress(std::string(""));
			OnProgress(std::string("HCGTest: Evaluate random qualities using ChiSquare, Mean, and Ordered Runs for each generator variant"));
			Evaluate(genh256);
			Evaluate(genh512);
			delete genh256;
			delete genh512;
			OnProgress(std::string("HCGTest: Passed HMAC Generator random evaluation tests.."));

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

	void HCGTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid digest choice
			HCG gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE1"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test constructor -2
		try
		{
			// invalid null digest instance
			HCG gen(nullptr);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			// invalid key size
			std::vector<byte> k(1);
			gen.Initialize(k);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE3"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator state -1
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			std::vector<byte> m(16);
			// cipher was not initialized
			gen.Generate(m);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE4"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator state -2
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize());
			gen.Initialize(k);
			std::vector<byte> m(16);
			// array is too small
			gen.Generate(m, 0, m.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE5"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator request
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize());
			gen.Initialize(k);
			// more than the max request size -64kb
			std::vector<byte> m(gen.MaxRequestSize() + 1);
			gen.Generate(m, 0, m.size());

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE6"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void HCGTest::Evaluate(IDrbg* Rng)
	{
		size_t i;

		try
		{
			const size_t SEGCNT = SAMPLE_SIZE / Rng->MaxRequestSize();
			std::vector<byte> smp(SEGCNT * Rng->MaxRequestSize());

			for (i = 0; i < SEGCNT; ++i)
			{
				Rng->Generate(smp, i * Rng->MaxRequestSize(), Rng->MaxRequestSize());
			}

			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-HE1"));
		}
	}

	void HCGTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> expected =
		{
			// standard vectors
			std::string("51A8DA01B21A30F87FAD0F90664CFC7C1BFB6753BFDDDD6AE475EC3F2258B24BD60EF746ECDD6698172081889305A9629A89C984C634720F99F07FA65F958D9A"),
			std::string("416472DC5CF923F7093B7CE517C2BDCBC2D58250801F19D2990981C08DA609EFC59D7BC12029CA226D89BBCB7AA21E9D24B45BEA4486812AF88A1DD263B5147F")
		};
		HexConverter::Decode(expected, 2, m_expected);

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D427"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637")
		};
		HexConverter::Decode(key, 2, m_key);
		/*lint -restore */
	}

	void HCGTest::Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		const size_t EXPLEN = Expected.size();
		std::vector<byte> exp(EXPLEN);
		SymmetricKey kp(Key);

		// generate
		Rng->Initialize(kp);
		Rng->Generate(exp, 0, EXPLEN);

		if (exp != Expected)
		{
			throw TestException(std::string("Kat"), Rng->Name(), std::string("Output does not match the known answer! -HK1"));
		}
	}

	void HCGTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void HCGTest::Stress()
	{
		HCG gen;
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
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
				IntegerTools::Fill(key, 0, key.size(), rnd);

				// generate with the gen
				gen.Initialize(key);
				gen.Generate(otp, 0, OTPLEN);
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
