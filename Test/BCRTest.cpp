#include "BCRTest.h"
#include "RandomUtils.h"
#include "../CEX/BCR.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Prng::BCR;
	using Exception::CryptoRandomException;
	using Tools::IntegerTools;
	using Prng::SecureRandom;

	const std::string BCRTest::CLASSNAME = "BCRTest";
	const std::string BCRTest::DESCRIPTION = "BCR stress and random evaluation tests.";
	const std::string BCRTest::SUCCESS = "SUCCESS! All BCR tests have executed succesfully.";

	BCRTest::BCRTest()
		:
		m_progressEvent()
	{
	}

	BCRTest::~BCRTest()
	{
	}

	const std::string BCRTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &BCRTest::Progress()
	{
		return m_progressEvent;
	}

	std::string BCRTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("BCRTest: Passed BCR exception handling tests.."));

			BCR* gen = new BCR;
			Evaluate(gen);
			OnProgress(std::string("BCRTest: Passed BCR random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("BCRTest: Passed BCR stress tests.."));

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

	void BCRTest::Evaluate(IPrng* Rng)
	{
		try
		{
			std::vector<uint8_t> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-AE1"));
		}
	}

	void BCRTest::Exception()
	{
		// test generate
		try
		{
			BCR gen;
			std::vector<uint8_t> smp(16);
			// generator was not initialized
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

	void BCRTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void BCRTest::Stress()
	{
		std::vector<uint8_t> msg;
		SecureRandom rnd;
		BCR gen;
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
