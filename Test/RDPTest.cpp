#include "RDPTest.h"
#include "RandomUtils.h"
#include "../CEX/RDP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::RDP;
	using Exception::CryptoRandomException;
	using Utility::IntegerTools;
	using Prng::SecureRandom;

	const std::string RDPTest::CLASSNAME = "RDPTest";
	const std::string RDPTest::DESCRIPTION = "RDP stress and random evaluation tests.";
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

			RDP* gen = new RDP;
			Evaluate(gen);
			OnProgress(std::string("RDPTest: Passed RDP random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("RDPTest: Passed RDP stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void RDPTest::Evaluate(IProvider* Rng)
	{
		try
		{
			std::vector<byte> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-RE1"));
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

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -RE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RDPTest::OnProgress(const std::string &Data)
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
			catch (std::exception const&)
			{
				throw TestException(std::string("Exception"), gen.Name(), std::string("The generator has thrown an exception! -RS1"));
			}
		}
	}
}
