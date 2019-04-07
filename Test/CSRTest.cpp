#include "CSRTest.h"
#include "RandomUtils.h"
#include "../CEX/CSR.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Prng::CSR;
	using Exception::CryptoRandomException;
	using Utility::IntegerTools;
	using Prng::SecureRandom;

	const std::string CSRTest::CLASSNAME = "CSRTest";
	const std::string CSRTest::DESCRIPTION = "CSR stress and random evaluation tests.";
	const std::string CSRTest::SUCCESS = "SUCCESS! All CSR tests have executed succesfully.";

	CSRTest::CSRTest()
		:
		m_progressEvent()
	{
	}

	CSRTest::~CSRTest()
	{
	}

	const std::string CSRTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CSRTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CSRTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("CSRTest: Passed CSR exception handling tests.."));

			CSR* gen = new CSR;
			Evaluate(gen);
			OnProgress(std::string("CSRTest: Passed CSR random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("CSRTest: Passed CSR stress tests.."));

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

	void CSRTest::Evaluate(IPrng* Rng)
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

	void CSRTest::Exception()
	{
		// test generate
		try
		{
			CSR gen;
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

	void CSRTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void CSRTest::Stress()
	{
		std::vector<byte> msg;
		SecureRandom rnd;
		CSR gen;
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
