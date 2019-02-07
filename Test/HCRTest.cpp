#include "HCRTest.h"
#include "RandomUtils.h"
#include "../CEX/HCR.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Prng::HCR;
	using Exception::CryptoRandomException;
	using Utility::IntegerTools;
	using Prng::SecureRandom;

	const std::string HCRTest::CLASSNAME = "HCRTest";
	const std::string HCRTest::DESCRIPTION = "HCR stress and random evaluation tests.";
	const std::string HCRTest::SUCCESS = "SUCCESS! All HCR tests have executed succesfully.";

	HCRTest::HCRTest()
		:
		m_progressEvent()
	{
	}

	HCRTest::~HCRTest()
	{
	}

	const std::string HCRTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HCRTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HCRTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("HCRTest: Passed HCR exception handling tests.."));

			HCR* gen = new HCR;
			Evaluate(gen);
			OnProgress(std::string("HCRTest: Passed HCR random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("HCRTest: Passed HCR stress tests.."));

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

	void HCRTest::Evaluate(IPrng* Rng)
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

	void HCRTest::Exception()
	{
		// test generate
		try
		{
			HCR gen;
			std::vector<byte> smp(16);
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

	void HCRTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void HCRTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		HCR gen;
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
