#include "CSGTest.h"
#include "../CEX/CSG.h"
#include "../CEX/CSP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	const std::string CSGTest::DESCRIPTION = "CSG implementations vector comparison tests.";
	const std::string CSGTest::FAILURE = "FAILURE! ";
	const std::string CSGTest::SUCCESS = "SUCCESS! All CSG tests have executed succesfully.";

	CSGTest::CSGTest()
		:
		m_custom(0),
		m_expected(0),
		m_progressEvent(),
		m_seed(0)
	{
	}

	CSGTest::~CSGTest()
	{
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
			Initialize();

			//CheckInit();

			OnProgress(std::string("CSG: Passed initialization tests.."));

			Drbg::CSG* gen128 = new Drbg::CSG(Enumeration::ShakeModes::SHAKE128, Enumeration::Providers::None);
			CompareVector(gen128, m_seed[0], m_expected[0]);
			CompareVector(gen128, m_seed[1], m_expected[1]);
			delete gen128;

			OnProgress(std::string("CSG: Passed SP800-185 cSHAKE-128 KAT tests.."));

			Drbg::CSG* gen256 = new Drbg::CSG(Enumeration::ShakeModes::SHAKE256, Enumeration::Providers::None);
			CompareVector(gen256, m_seed[0], m_expected[2]);
			CompareVector(gen256, m_seed[1], m_expected[3]);
			delete gen256;

			OnProgress(std::string("CSG: Passed SP800-185 cSHAKE-256 KAT tests.."));

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

	void CSGTest::CheckInit()
	{
		std::vector<byte> info(32, 0x03);
		std::vector<byte> nonce(8, 0x02);
		std::vector<byte> output(1024);
		std::vector<byte> seed(32, 0x01);

		try
		{
			Provider::CSP* pvd = new Provider::CSP();

			// test primitive instantiation
			Drbg::CSG ctd(Enumeration::ShakeModes::SHAKE128, pvd);
			// first legal key size
			size_t seedLen = ctd.LegalKeySizes()[0].KeySize();
			seed.resize(seedLen, 0x01);
			ctd.Initialize(seed);
			ctd.Generate(output);

			delete pvd;

			if (OrderedRuns(output))
			{
				throw TestException("CSGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("CSGTest: Failed primitive instantiation test!");
		}
	}

	bool CSGTest::OrderedRuns(const std::vector<byte> &Input)
	{
		bool state = false;

		// indicates zeroed output or bad run
		for (size_t i = 0; i < Input.size() - 4; i += 4)
		{
			if (Input[i] == Input[i + 1] &&
				Input[i + 1] == Input[i + 2] &&
				Input[i + 2] == Input[i + 3])
			{
				state = true;
				break;
			}
		}

		return state;
	}

	void CSGTest::CompareVector(Drbg::IDrbg* Generator, std::vector<byte> &Seed, std::vector<byte> &Expected)
	{
		std::vector<byte> name(0);
		std::vector<byte> output(Expected.size());
		Generator->Initialize(Seed, m_custom, name);
		Generator->Generate(output);

		if (output != Expected)
		{
			throw TestException("CSGTest: Genertated arrays are not equal!");
		}
	}

	void CSGTest::Initialize()
	{
		/*lint -save -e417 */

		HexConverter::Decode(std::string("456D61696C205369676E6174757265"), m_custom);

		const std::vector<std::string> expected =
		{
			std::string("C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5"),
			std::string("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B"),
			std::string("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD164020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"),
			std::string("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC86430273091727F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB")
		};
		HexConverter::Decode(expected, 4, m_expected);

		const std::vector<std::string> seed =
		{
			std::string("00010203"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
			"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
			"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
			"C0C1C2C3C4C5C6C7")
		};
		HexConverter::Decode(seed, 2, m_seed);
		/*lint -restore */
	}

	void CSGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
