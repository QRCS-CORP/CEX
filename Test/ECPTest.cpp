#include "ECPTest.h"
#include "RandomUtils.h"
#include "../CEX/ECP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::ECP;
	using Exception::CryptoRandomException;
	using Tools::IntegerTools;
	using Prng::SecureRandom;

	const std::string ECPTest::CLASSNAME = "ECPTest";
	const std::string ECPTest::DESCRIPTION = "ECP stress and random evaluation tests.";
	const std::string ECPTest::SUCCESS = "SUCCESS! All ECP tests have executed succesfully.";

	ECPTest::ECPTest()
		:
		m_progressEvent()
	{
	}

	ECPTest::~ECPTest()
	{
	}

	const std::string ECPTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ECPTest::Progress()
	{
		return m_progressEvent;
	}

	std::string ECPTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("ECPTest: Passed ECP exception handling tests.."));

			ECP* gen = new ECP;
			Evaluate(gen);
			OnProgress(std::string("ECPTest: Passed CSP random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("ECPTest: Passed ECP stress tests.."));

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

	void ECPTest::Evaluate(IProvider* Rng)
	{
		try
		{
			std::vector<byte> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-EE1"));
		}
	}

	void ECPTest::Exception()
	{
		// test generate
		try
		{
			ECP gen;
			std::vector<byte> rnd(16);
			// buffer is too small
			gen.Generate(rnd, 0, rnd.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -EE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ECPTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void ECPTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		ECP gen;
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
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -ES1"));
			}
		}
	}
}
