#include "ACPTest.h"
#include "RandomUtils.h"
#include "../CEX/ACP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::ACP;
	using Exception::CryptoRandomException;
	using Utility::IntUtils;
	using Prng::SecureRandom;

	const std::string ACPTest::DESCRIPTION = "ACP stress and random evaluation tests.";
	const std::string ACPTest::FAILURE = "FAILURE! ";
	const std::string ACPTest::SUCCESS = "SUCCESS! All ACP tests have executed succesfully.";

	ACPTest::ACPTest()
		:
		m_progressEvent()
	{
	}

	ACPTest::~ACPTest()
	{
	}

	const std::string ACPTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ACPTest::Progress()
	{
		return m_progressEvent;
	}

	std::string ACPTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("ACPTest: Passed ACP exception handling tests.."));

			Stress();
			OnProgress(std::string("ACPTest: Passed ACP stress tests.."));

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

	void ACPTest::Evaluate(IProvider* Rng)
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
			throw TestException(std::string("ACP"), std::string("Exception: Ordered runs test failure! -AE1"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(otp))
		{
			throw TestException(std::string("ACP"), std::string("Exception: Succesive zeroes test failure! -AE2"));
		}
	}

	void ACPTest::Exception()
	{
		// test generate
		try
		{
			ACP gen;
			std::vector<byte> rnd(16);
			// generator was not initialized
			gen.Generate(rnd, 0, rnd.size() + 1);

			throw TestException(std::string("ACP"), std::string("Exception: Exception handling failure! -AE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ACPTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void ACPTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		ACP gen;
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
				throw TestException(std::string("ACP"), std::string("Stress: The generator has thrown an exception! -AS1"));
			}
		}
	}
}
