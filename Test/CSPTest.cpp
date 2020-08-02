#include "CSPTest.h"
#include "RandomUtils.h"
#include "../CEX/CSP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::CSP;
	using Exception::CryptoRandomException;
	using Tools::IntegerTools;
	using Prng::SecureRandom;

	const std::string CSPTest::CLASSNAME = "CSPTest";
	const std::string CSPTest::DESCRIPTION = "CSP stress and random evaluation tests.";
	const std::string CSPTest::SUCCESS = "SUCCESS! All CSP tests have executed succesfully.";

	CSPTest::CSPTest()
		:
		m_progressEvent()
	{
	}

	CSPTest::~CSPTest()
	{
	}

	const std::string CSPTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CSPTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CSPTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("CSPTest: Passed CSP exception handling tests.."));

			CSP* gen = new CSP;
			Evaluate(gen);
			OnProgress(std::string("CSPTest: Passed CSP random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("CSPTest: Passed CSP stress tests.."));

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

	void CSPTest::Evaluate(IProvider* Rng)
	{
		try
		{
			std::vector<byte> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-CE1"));
		}
	}

	void CSPTest::Exception()
	{
		// test generate
		try
		{
			CSP gen;
			std::vector<byte> rnd(16);
			// buffer is too small
			gen.Generate(rnd, 0, rnd.size() + 1);

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

	void CSPTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void CSPTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		CSP gen;
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
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -AS1"));
			}
		}
	}
}
