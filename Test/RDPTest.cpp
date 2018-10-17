#include "RDPTest.h"
#include "RandomUtils.h"
#include "../CEX/RDP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::RDP;
	using Exception::CryptoRandomException;
	using Utility::IntUtils;
	using Prng::SecureRandom;

	const std::string RDPTest::DESCRIPTION = "RDP stress and random evaluation tests.";
	const std::string RDPTest::FAILURE = "FAILURE! ";
	const std::string RDPTest::SUCCESS = "SUCCESS! All RDP tests have executed succesfully.";

	RDPTest::RDPTest()
		:
		m_progressEvent()
	{
	}

	RDPTest::~RDPTest()
	{
	}

	const std::string RDPTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RDPTest::Progress()
	{
		return m_progressEvent;
	}

	std::string RDPTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("RDPTest: Passed RDP exception handling tests.."));

			Stress();
			OnProgress(std::string("RDPTest: Passed RDP stress tests.."));

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

	void RDPTest::Evaluate(IProvider* Rng)
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
			throw TestException(std::string("RDP"), std::string("Exception: Ordered runs test failure! -RE1"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(otp))
		{
			throw TestException(std::string("RDP"), std::string("Exception: Succesive zeroes test failure! -RE2"));
		}
	}

	void RDPTest::Exception()
	{
		// test generate
		try
		{
			RDP gen;
			std::vector<byte> rnd(16);
			// generator was not initialized
			gen.Generate(rnd, 0, rnd.size() + 1);

			throw TestException(std::string("RDP"), std::string("Exception: Exception handling failure! -RE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RDPTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void RDPTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		RDP gen;
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
				throw TestException(std::string("RDP"), std::string("Stress: The generator has thrown an exception! -RS1"));
			}
		}
	}
}
