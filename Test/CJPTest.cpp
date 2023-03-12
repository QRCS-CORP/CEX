#include "CJPTest.h"
#include "RandomUtils.h"
#include "../CEX/CJP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Provider::CJP;
	using Exception::CryptoRandomException;
	using Tools::IntegerTools;
	using Prng::SecureRandom;

	const std::string CJPTest::CLASSNAME = "CJPTest";
	const std::string CJPTest::DESCRIPTION = "CJP stress and random evaluation tests.";
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

			CJP* gen = new CJP;
			Evaluate(gen);
			OnProgress(std::string("CJPTest: Passed CJP random evaluation.."));
			delete gen;

			Stress();
			OnProgress(std::string("CJPTest: Passed CJP stress tests.."));

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

	void CJPTest::Evaluate(IProvider* Rng)
	{
		try
		{
			std::vector<uint8_t> smp(SAMPLE_SIZE);
			Rng->Generate(smp, 0, smp.size());
			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-CE1"));
		}
	}

	void CJPTest::Exception()
	{
		// test generate
		try
		{
			CJP gen;
			std::vector<uint8_t> rnd(16);
			// buffer is too small
			gen.Generate(rnd, 0, rnd.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE3"));
		}
		catch (CryptoRandomException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CJPTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void CJPTest::Stress()
	{
		std::vector<uint8_t> msg;
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
			catch (const std::exception&)
			{
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -CS1"));
			}
		}
	}
}
