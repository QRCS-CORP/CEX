#include "BCGTest.h"
#include "../CEX/CTR.h"
#include "../CEX/BCG.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/HKDF.h"
#include "../CEX/FileStream.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	const std::string BCGTest::DESCRIPTION = "BCG implementations vector comparison tests.";
	const std::string BCGTest::FAILURE = "FAILURE! ";
	const std::string BCGTest::SUCCESS = "SUCCESS! All BCG tests have executed succesfully.";

	BCGTest::BCGTest()
		:
		m_progressEvent()
	{
	}

	BCGTest::~BCGTest()
	{
	}

	const std::string BCGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &BCGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string BCGTest::Run()
	{
		try
		{
			CheckInit();
			OnProgress(std::string("BCG: Passed initialization tests.."));
			CompareOutput();
			OnProgress(std::string("BCG: Passed output comparison tests.."));

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

	void BCGTest::CheckInit()
	{
		using namespace Cipher::Symmetric::Block;

		std::vector<byte> info(96, 0x01);
		std::vector<byte> key(32, 0x02);
		std::vector<byte> nonce(16, 0x03);
		std::vector<byte> output(0);

		try
		{
			// test enumeration instantiation
			Drbg::BCG ctd(BlockCiphers::Rijndael, BlockCipherExtensions::HKDF256);
			output.resize(ctd.ParallelBlockSize());
			// test seed + nonce + info init
			ctd.Initialize(key, nonce, info);
			ctd.Generate(output);

			if (OrderedRuns(output))
			{
				throw TestException("BCGTest: Failed duplication test!");
			}

			// test seed + nonce init
			ctd.Initialize(key, nonce);
			ctd.Generate(output);

			if (OrderedRuns(output))
			{
				throw TestException("BCGTest: Failed duplication test!");
			}

			// test parallel
			ctd.ParallelProfile().IsParallel() = true;
			ctd.Generate(output);

			if (OrderedRuns(output))
			{
				throw TestException("BCGTest: Failed parallel duplication test!");
			}

			// test seed init
			key.resize(48, 0x02);
			ctd.Initialize(key);
			ctd.Generate(output);

			if (OrderedRuns(output))
			{
				throw TestException("BCGTest: Failed duplication test!");
			}

		}
		catch (...)
		{
			throw TestException("BCGTest: Failed enumeration instantiation test!");
		}

		try
		{
			// test primitive instantiation
			Kdf::HKDF* gen = new Kdf::HKDF(Enumeration::Digests::SHA256);
			RHX* cpr = new RHX;
			Drbg::BCG ctd2(cpr, gen);
			output.resize(ctd2.ParallelBlockSize());
			ctd2.Initialize(key);
			ctd2.Generate(output);
			delete cpr;
			delete gen;

			if (OrderedRuns(output))
			{
				throw TestException("BCGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("BCGTest: Failed primitive instantiation test!");
		}
	}

	void BCGTest::CompareOutput()
	{
		using namespace Cipher::Symmetric::Block;
		using namespace Drbg;

		std::vector<byte> iv(16, 0x01);
		std::vector<byte> key(32, 0x02);
		std::vector<byte> output1(SAMPLE_SIZE);

		Drbg::BCG ctd(BlockCiphers::Rijndael, BlockCipherExtensions::None, Providers::None);
		ctd.Initialize(key, iv);
		ctd.Generate(output1);

		std::vector<byte> input(SAMPLE_SIZE, 0x0);
		std::vector<byte> output2(SAMPLE_SIZE);
		// encrypt an array of zeroes, should be equal to generator output
		RHX* eng = new RHX();
		Mode::CTR cpr(eng);
		Key::Symmetric::SymmetricKey kp(key, iv);
		cpr.Initialize(true, kp);
		cpr.Transform(input, 0, output2, 0, output2.size());

		delete eng;

		if (output1 != output2)
		{
			throw TestException("BCG: Failed output comparison test!");
		}
	}

	bool BCGTest::OrderedRuns(const std::vector<byte> &Input)
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

	void BCGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
