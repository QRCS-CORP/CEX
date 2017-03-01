#include "CMGTest.h"
#include "../CEX/CTR.h"
#include "../CEX/CMG.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"
#include "../CEX/FileStream.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	std::string CMGTest::Run()
	{
		try
		{
			CheckInit();
			OnProgress("CMG: Passed initialization tests..");
			CompareOutput();
			OnProgress("CMG: Passed output comparison tests..");

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void CMGTest::CheckInit()
	{
		using namespace Cipher::Symmetric::Block;

		std::vector<byte> info(96, 0x01);
		std::vector<byte> key(32, 0x02);
		std::vector<byte> nonce(16, 0x03);
		std::vector<byte> output(0);

		try
		{
			// test enumeration instantiation
			Drbg::CMG ctd(BlockCiphers::Rijndael, Digests::SHA256);
			output.resize(ctd.ParallelBlockSize());
			// test seed + nonce + info init
			ctd.Initialize(key, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("CMGTest: Failed duplication test!");

			// test seed + nonce init
			ctd.Initialize(key, nonce);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("CMGTest: Failed duplication test!");

			// test parallel
			ctd.ParallelProfile().IsParallel() = true;
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("CMGTest: Failed parallel duplication test!");

			// test seed init
			key.resize(48, 0x02);
			ctd.Initialize(key);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("CMGTest: Failed duplication test!");

		}
		catch (...)
		{
			throw std::exception("CMGTest: Failed enumeration instantiation test!");
		}

		try
		{
			// test primitive instantiation
			Digest::SHA256* dgt = new Digest::SHA256;
			RHX* cpr = new RHX;
			Drbg::CMG ctd2(cpr, dgt);
			output.resize(ctd2.ParallelBlockSize());
			ctd2.Initialize(key);
			ctd2.Generate(output);
			delete cpr;
			delete dgt;

			if (CheckRuns(output))
				throw std::exception("CMGTest: Failed duplication test!");
		}
		catch (...)
		{
			throw std::exception("CMGTest: Failed primitive instantiation test!");
		}
	}

	void CMGTest::CompareOutput()
	{
		using namespace Cipher::Symmetric::Block;
		using namespace Drbg;

		std::vector<byte> iv(16, 0x01);
		std::vector<byte> key(32, 0x02);
		std::vector<byte> output1(SAMPLE_SIZE);

		Drbg::CMG ctd(BlockCiphers::Rijndael, Digests::None, Providers::None);
		ctd.Initialize(key, iv);
		ctd.Generate(output1);

		std::vector<byte> input(SAMPLE_SIZE, 0x0);
		std::vector<byte> output2(SAMPLE_SIZE);
		// encrypt an array of zeroes, should be equal to generator output
		RHX* eng = new RHX();
		Mode::CTR cpr(eng);
		Key::Symmetric::SymmetricKey kp(key, iv);
		cpr.Initialize(true, kp);
		cpr.Transform(input, output2);

		delete eng;

		if (output1 != output2)
			throw std::exception("CMG: Failed output comparison test!");
	}

	bool CMGTest::CheckRuns(const std::vector<byte> &Input)
	{
		// indicates zeroed output or bad run
		for (size_t i = 0; i < Input.size() - 4; i += 4)
		{
			if (Input[i] == Input[i + 1] && 
				Input[i + 1] == Input[i + 2] &&
				Input[i + 2] == Input[i + 3])
				return true;
		}
		return false;
	}

	void CMGTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}