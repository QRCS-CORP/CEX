#include "RangedRngTest.h"
#include "CSPPrng.h"
#include "CTRPrng.h"
#include "DGCPrng.h"
#include "PPBPrng.h"
#include "SP20Prng.h"

namespace Test
{
	std::string RangedRngTest::Run()
	{
		using namespace CEX::Prng;

		try
		{
			EvaluateRange(new CSPPrng());
			OnProgress("Passed CSPPrng range tests..");
			EvaluateRange(new CTRPrng());
			OnProgress("Passed CTRPrng range tests..");
			EvaluateRange(new DGCPrng());
			OnProgress("Passed DGCPrng range tests..");
			EvaluateRange(new SP20Prng());
			OnProgress("Passed SP20Prng range tests..");

			return SUCCESS;
		}
		catch (std::string &ex)
		{
			throw FAILURE + " : " + ex;
		}
		catch (...)
		{
			throw FAILURE;
		}
	}

	void RangedRngTest::EvaluateRange(CEX::Prng::IRandom* Rng)
	{
		const unsigned int thresh = 1000;
		std::vector<byte> bt = Rng->GetBytes(thresh);
		const unsigned int delta = 16;
		for (unsigned int i = 0, j = 0; i < bt.size(); i++)
		{
			if (bt[i] == 0)
				j++;
			// improbable but not impossible, could indicate a problem though..
			if (j > delta)
				OnProgress("Warning! Exceeded max. expected zeroes in set..");
		}

		bt.clear();
		bt.resize(1000);
		Rng->GetBytes(bt);
		for (unsigned int i = 0, j = 0; i < bt.size(); i++)
		{
			if (bt[i] == 0)
				j++;
			if (j > 16)
				OnProgress("Warning! Exceeded max. expected zeroes in set..");
		}

		unsigned int xi = 0;
		for (unsigned int i = 0; i < 1000; i++)
		{
			xi = Rng->Next();
			if (xi == 0)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xi = Rng->Next(100);
			if (xi > 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xi = Rng->Next(100, 1000);
			if (xi > 1000 || xi < 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}

		ulong xl = Rng->NextLong();
		for (unsigned int i = 0; i < 1000; i++)
		{
			xl = Rng->NextLong(100000);
			if (xl > 100000)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xl = Rng->NextLong(100, 100000);
			if (xl > 100000 || xi < 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}

		delete Rng;
	}

	void RangedRngTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}