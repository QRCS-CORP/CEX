#include "ACPTest.h"
#include "RandomUtils.h"
#include "../CEX/ACP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::ACP;
	using Exception::CryptoRandomException;
	using Tools::IntegerTools;
	using Prng::SecureRandom;

	const std::string ACPTest::CLASSNAME = "ACPTest";
	const std::string ACPTest::DESCRIPTION = "ACP stress and random evaluation tests.";
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

			ACP* gen = new ACP;
			Evaluate(gen);
			OnProgress(std::string("ACPTest: Passed ACP random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("ACPTest: Passed ACP stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void ACPTest::Evaluate(IProvider* Rng)
	{
		try
		{
			std::vector<byte> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-AE1"));
		}
	}

	void ACPTest::Exception()
	{
		// test generate
		try
		{
			ACP gen;
			std::vector<byte> smp(16);
			// buffer is too small
			gen.Generate(smp, 0, smp.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -AE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ACPTest::OnProgress(const std::string &Data)
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
			catch (const std::exception&)
			{
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -AS1"));
			}
		}
	}
}
