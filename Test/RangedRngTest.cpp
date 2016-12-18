#include "RangedRngTest.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	std::string RangedRngTest::Run()
	{
		try
		{
			EvaluateRange();

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw FAILURE + " : " + ex.what();
		}
		catch (...)
		{
			throw FAILURE;
		}
	}

	void RangedRngTest::EvaluateRange()
	{
		const unsigned int thresh = 1000;
		Prng::SecureRandom rnd;
		std::vector<byte> bt = rnd.GetBytes(thresh);
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
		rnd.GetBytes(bt);
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
			xi = rnd.Next();
			if (xi == 0)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xi = rnd.NextInt32(100);
			if (xi > 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xi = rnd.NextInt32(100, 1000);
			if (xi > 1000 || xi < 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}

		ulong xl = rnd.NextLong();
		for (unsigned int i = 0; i < 1000; i++)
		{
			xl = rnd.NextInt64(100000);
			if (xl > 100000)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
		for (unsigned int i = 0; i < 1000; i++)
		{
			xl = rnd.NextInt64(100, 100000);
			if (xl > 100000 || xi < 100)
				throw new std::string("RangedRngTest: Expected range exceeded!");
		}
	}

	void RangedRngTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}