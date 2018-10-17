#include "CJPTest.h"
#include "RandomUtils.h"
#include "../CEX/CJP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::CJP;
	using Exception::CryptoRandomException;
	using Utility::IntUtils;
	using Prng::SecureRandom;

	const std::string CJPTest::DESCRIPTION = "CJP stress and random evaluation tests.";
	const std::string CJPTest::FAILURE = "FAILURE! ";
	const std::string CJPTest::SUCCESS = "SUCCESS! All CJP tests have executed succesfully.";

	CJPTest::CJPTest()
		:
		m_progressEvent()
	{
	}

	CJPTest::~CJPTest()
	{
	}

	const std::string CJPTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CJPTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CJPTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("CJPTest: Passed CJP exception handling tests.."));

#if !defined(_DEBUG)
			Stress();
			OnProgress(std::string("CJPTest: Passed CJP stress tests.."));
#endif

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

	void CJPTest::Evaluate(IProvider* Rng)
	{
		std::vector<byte> otp(SAMPLE_SIZE);
		double x;
		std::string status;

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
			throw TestException(std::string("CJP"), std::string("Exception: Ordered runs test failure! -CE1"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(otp))
		{
			throw TestException(std::string("CJP"), std::string("Exception: Succesive zeroes test failure! -CE2"));
		}
	}

	void CJPTest::Exception()
	{
		// test generate
		try
		{
			CJP gen;
			std::vector<byte> rnd(16);
			// generator was not initialized
			gen.Generate(rnd, 0, rnd.size() + 1);

			throw TestException(std::string("CJP"), std::string("Exception: Exception handling failure! -CE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CJPTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void CJPTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		CJP gen;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				msg.resize(MSGLEN);

				gen.Generate(msg);
				gen.Reset();
			}
			catch (...)
			{
				throw TestException(std::string("CJP"), std::string("Stress: The generator has thrown an exception! -CS1"));
			}
		}
	}
}
