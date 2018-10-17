#include "CSGTest.h"
#include "../CEX/CSG.h"
#include "../CEX/CSP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/Providers.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHAKE.h"
#include "../CEX/ShakeModes.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using namespace Drbg;
	using Utility::IntUtils;
	using Prng::SecureRandom;
	using Kdf::SHAKE;
	using Enumeration::ShakeModes;

	const std::string CSGTest::DESCRIPTION = "CSG implementations vector comparison tests.";
	const std::string CSGTest::FAILURE = "FAILURE! ";
	const std::string CSGTest::SUCCESS = "SUCCESS! All CSG tests have executed succesfully.";

	CSGTest::CSGTest()
		:
		m_custom(0),
		m_expected(0),
		m_progressEvent(),
		m_key(0)
	{
		Initialize();
	} 

	CSGTest::~CSGTest()
	{
		IntUtils::ClearVector(m_custom);
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
	}

	const std::string CSGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CSGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CSGTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("CSGTest: Passed cSHAKE Generator exception handling tests.."));

			Stress();
			OnProgress(std::string("CSGTest: Passed cSHAKE Generator stress tests.."));

			CSG* gen128 = new CSG(Enumeration::ShakeModes::SHAKE128, Enumeration::Providers::None);
			Kat(gen128, m_key[0], m_expected[0]);
			Kat(gen128, m_key[1], m_expected[1]);
			CSG* gen256 = new CSG(Enumeration::ShakeModes::SHAKE256, Enumeration::Providers::None);
			Kat(gen256, m_key[0], m_expected[2]);
			Kat(gen256, m_key[1], m_expected[3]);
			CSG* gen512 = new CSG(Enumeration::ShakeModes::SHAKE512, Enumeration::Providers::None);
			Kat(gen512, m_key[1], m_expected[4]);
			CSG* gen1024 = new CSG(Enumeration::ShakeModes::SHAKE1024, Enumeration::Providers::None);
			Kat(gen1024, m_key[0], m_expected[5]);
			OnProgress(std::string("CSGTest: Passed customized cSHAKE 128/256/512/1024 KAT test.."));

#if defined(__AVX2__)
			CSG* gen512w = new CSG(Enumeration::ShakeModes::SHAKE512, Enumeration::Providers::None, true);
			Kat(gen512w, m_key[0], m_expected[6]);
			OnProgress(std::string("CSG: Passed customized cSHAKEW-512 KAT test.."));
#endif

			OnProgress(std::string(""));
			OnProgress(std::string("CSGTest: Evaluate random qualities using ChiSquare, Mean, and Ordered Runs for each generator variant"));
			Evaluate(gen128);
			Evaluate(gen256);
			Evaluate(gen512);
			Evaluate(gen1024);
			delete gen128;
			delete gen256;
			delete gen512;
			delete gen1024;
#if defined(__AVX2__)
			Evaluate(gen512w);
			delete gen512w;
#endif
			OnProgress(std::string("CSGTest: Passed cSHAKE Generator random evaluation tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void CSGTest::Evaluate(IDrbg* Rng)
	{
		std::vector<byte> otp(SAMPLE_SIZE);
		Key::Symmetric::SymmetricKeySize ks = Rng->LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
		SecureRandom rnd;
		double x;
		std::string status;

		IntUtils::Fill(key, 0, key.size(), rnd);
		IntUtils::Fill(iv, 0, iv.size(), rnd);
		SymmetricKey kp(key, iv);

		Rng->Initialize(kp);
		Rng->Generate(otp);

		// mean value test
		x = TestUtils::MeanValue(otp);

		status = (Rng->Name() + std::string(": Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

		if (x < 122.5 || x > 132.5)
		{
			status += std::string("(FAIL)");
		}
		else if (x < 125.0 || x > 130.0)
		{
			status += std::string("(WARN)");
		}
		else
		{
			status += std::string("(PASS)");
		}

		OnProgress(std::string(status));

		// ChiSquare
		x = TestUtils::ChiSquare(otp) * 100;
		status = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

		if (x < 1.0 || x > 99.0)
		{
			status += std::string("(FAIL)");
		}
		else if (x < 5.0 || x > 95.0)
		{
			status += std::string("(WARN)");
		}
		else
		{
			status += std::string("(PASS)");
		}
		OnProgress(std::string(status));

		// ordered runs
		if (TestUtils::OrderedRuns(otp))
		{
			throw TestException(std::string("CSG"), std::string("Exception: Ordered runs test failure! -CE1"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(otp))
		{
			throw TestException(std::string("CSG"), std::string("Exception: Succesive zeroes test failure! -CE2"));
		}
	}

	void CSGTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid shake choice
			CSG drbg(ShakeModes::None, Providers::None);

			throw TestException(std::string("CSG"), std::string("Exception: Exception handling failure! -CE3"));
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
			// invalid null provider instance
			CSG drbg(ShakeModes::SHAKE128, nullptr);

			throw TestException(std::string("CSG"), std::string("Exception: Exception handling failure! -CE4"));
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
			CSG drbg(ShakeModes::SHAKE128, Providers::CSP);
			// invalid key size
			std::vector<byte> k(1);
			drbg.Initialize(k);

			throw TestException(std::string("CSG"), std::string("Exception: Exception handling failure! -CE5"));
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
			CSG drbg(ShakeModes::SHAKE128, Providers::CSP);
			std::vector<byte> m(16);
			// cipher was not initialized
			drbg.Generate(m);

			throw TestException(std::string("CSG"), std::string("Exception: Exception handling failure! -CE6"));
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
			CSG drbg(ShakeModes::SHAKE128, Providers::CSP);
			SymmetricKeySize ks = drbg.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize());
			drbg.Initialize(k);
			std::vector<byte> m(16);
			// array is too small
			drbg.Generate(m, 0, m.size() + 1);

			throw TestException(std::string("CSG"), std::string("Exception: Exception handling failure! -CE7"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CSGTest::Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		const size_t EXPLEN = Expected.size();
		std::vector<byte> exp(EXPLEN);
		std::vector<byte> name(0);

		// generate
		Rng->Initialize(Key, m_custom, name);
		Rng->Generate(exp, 0, EXPLEN);

		if (exp != Expected)
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -CK1"));
		}
	}

	void CSGTest::Initialize()
	{
		/*lint -save -e417 */
		HexConverter::Decode(std::string("456D61696C205369676E6174757265"), m_custom);

		const std::vector<std::string> expected =
		{
			// standard vectors
			std::string("C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5"),
			std::string("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B"),
			std::string("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD164020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"),
			std::string("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC86430273091727F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB"),
			// custom: cSHAKE 512 
			std::string("9057D34DB63D37E126B94D456C15A197C610375CD5DD9B2DD15CFEC21F7668D93B3949393C6FEEAC4AF0E00E884A70F985F0428A067D5A394557233EDF14FD6E"),
			// custom: cSHAKE 1024 
			std::string("58606D16D768FF3AADCE55BB2E8FB409FFE1AF198DC21C07477E15CB09B9CBFD8554B0784613E164605E11DEE383B6190AFFA0BB91EEAD668271DB455E79BA28"),
			// custom: vectorized cSHAKEW 512 
			std::string("D0E37BA875851CB08817EF5DFF073BA392BA318CFDB914BA2654BE98C52B05D58F9D8B67A1FB9878D33BC61CF736FECDE244E11827E56F78499258E692ECD57F"
				"6C62405BEE9DF41176F970BAF9312DD8E9FC9CDF1653D39DB67A63F31C674347B370F759A2F6131CB1BAA3C343185676186A86246829615391410D98D759DAEB"
				"38B0AC20802F20B0626EE90B0D4964665335A5EECDEBC183A57CE7CED900394170A875C3BD60DA9F35A30B4AC400BF4A84ED954A315F7CE6229E6EB20C9C6CAB"
				"D86B9F5488DD2D4D3174395C2F6454D012A6FECC2C25AB68B362301EF7BDE0926209EFDBAAA859DFE05A34DCDD19D7F04E6524FD333AC28128BAA663795C0CA2"
				"8AB3069DEFE2F316DD724863D8366A54C0D251A6E08811AA3967546A642263682D0FDF74A32C923A638878442E7EE2946C03DCBE6DE519D22EF0FA9983CF12CA")
		};
		HexConverter::Decode(expected, 7, m_expected);

		const std::vector<std::string> key =
		{
			std::string("00010203"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7")
		};
		HexConverter::Decode(key, 2, m_key);
		/*lint -restore */
	}

	void CSGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void CSGTest::Stress()
	{
		SHAKE kdf(ShakeModes::SHAKE256);
		CSG drbg(ShakeModes::SHAKE256, Providers::None);
		Key::Symmetric::SymmetricKeySize ks = kdf.LegalKeySizes()[1];
		std::vector<byte> name(0);
		std::vector<byte> otp1;
		std::vector<byte> otp2;
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp1.reserve(MAXM_ALLOC);
		otp2.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			otp1.resize(INPLEN);
			otp2.resize(INPLEN);
			IntUtils::Fill(key, 0, key.size(), rnd);

			// generate with the kdf
			kdf.Initialize(key, m_custom, name);
			kdf.Generate(otp1, 0, INPLEN);
			// generate with the drbg
			drbg.Initialize(key, m_custom, name);
			drbg.Generate(otp2, 0, INPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Stress: Transformation output is not equal! -TS1"));
			}
		}
	}
}
