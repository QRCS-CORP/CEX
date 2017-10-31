#include "DCGTest.h"
#include "../CEX/CSP.h"
#include "../CEX/DCG.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/SHA256.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	const std::string DCGTest::DESCRIPTION = "DCG implementations vector comparison tests.";
	const std::string DCGTest::FAILURE = "FAILURE! ";
	const std::string DCGTest::SUCCESS = "SUCCESS! All DCG tests have executed succesfully.";

	DCGTest::DCGTest()
		:
		m_expected256(0),
		m_seed256(0),
		m_progressEvent()
	{
	}

	DCGTest::~DCGTest()
	{
	}

	std::string DCGTest::Run()
	{
		try
		{
			CheckInit();
			OnProgress(std::string("DCG: Passed initialization tests.."));

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

	void DCGTest::CheckInit()
	{
		std::vector<byte> info(32, 0x03);
		std::vector<byte> nonce(8, 0x02);
		std::vector<byte> output(SAMPLE_SIZE);
		std::vector<byte> seed(32, 0x01);

		try
		{
			Digest::SHA256* dgt = new Digest::SHA256();
			Provider::CSP* pvd = new Provider::CSP();

			// test primitive instantiation
			Drbg::DCG ctd(dgt);
			// first legal key size
			size_t seedLen = ctd.LegalKeySizes()[0].KeySize();
			seed.resize(seedLen, 0x01);
			ctd.Initialize(seed);
			ctd.Generate(output);

			delete dgt;
			delete pvd;

			if (CheckRuns(output))
				throw TestException("DCGTest: Failed duplication test!");
		}
		catch (...)
		{
			throw TestException("DCGTest: Failed primitive instantiation test!");
		}

		try
		{
			// test enumeration instantiation
			Drbg::DCG ctd(Enumeration::Digests::SHA512, CEX::Enumeration::Providers::CSP);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw TestException("DCGTest: Failed duplication test!");

			// second legal key size + nonce
			size_t seedLen = ctd.LegalKeySizes()[1].KeySize() - 8;
			seed.resize(seedLen, 0x01);
			nonce.resize(8, 0x02);
			ctd.Initialize(seed, nonce);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw TestException("DCGTest: Failed duplication test!");

			// third legal key size + nonce + info
			seedLen = (ctd.LegalKeySizes()[2].KeySize() / 2) - 8;
			seed.resize(seedLen, 0x01);
			info.resize(seedLen, 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw TestException("DCGTest: Failed duplication test!");

		}
		catch (...)
		{
			throw TestException("DCGTest: Failed enumeration instantiation test!");
		}
	}

	bool DCGTest::CheckRuns(const std::vector<byte> &Input)
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

	void DCGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}