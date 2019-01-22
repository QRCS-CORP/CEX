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

/*int jent_entropy_init(void)
{
	int i;
	uint64_t delta_sum = 0;
	uint64_t old_delta = 0;
	int time_backwards = 0;
	int count_mod = 0;
	int count_stuck = 0;
	struct rand_data ec;

	// We could perform statistical tests here, but the problem is
	// that we only have a few loop counts to do testing. These
	// loop counts may show some slight skew and we produce
	// false positives.
	// Moreover, only old systems show potentially problematic
	// jitter entropy that could potentially be caught here. But
	// the RNG is intended for hardware that is available or widely
	// used, but not old systems that are long out of favor. Thus,
	// no statistical tests.

	// We could add a check for system capabilities such as clock_getres or
	// check for CONFIG_X86_TSC, but it does not make much sense as the
	// following sanity checks verify that we have a high-resolution timer.
	// TESTLOOPCOUNT needs some loops to identify edge systems. 100 is
	// definitely too little.

#define TESTLOOPCOUNT 300
#define CLEARCACHE 100
	for (i = 0; (TESTLOOPCOUNT + CLEARCACHE) > i; i++) {
		uint64_t time = 0;
		uint64_t time2 = 0;
		uint64_t delta = 0;
		unsigned int lowdelta = 0;
		int stuck;

		// Invoke core entropy collection logic
		jent_get_nstime(&time);
		ec.prev_time = time;
		jent_lfsr_time(&ec, time, 0);
		jent_get_nstime(&time2);

		/// test whether timer works
		if (!time || !time2)
			return ENOTIME;
		delta = time2 - time;

		 // test whether timer is fine grained enough to provide
		 // delta even when called shortly after each other -- this
		 // implies that we also have a high resolution timer

		if (!delta)
			return ECOARSETIME;

		stuck = jent_stuck(&ec, delta);


		 // up to here we did not modify any variable that will be
		 // evaluated later, but we already performed some work. Thus we
		 // already have had an impact on the caches, branch prediction,
		 // etc. with the goal to clear it to get the worst case
		 // measurements.

		if (CLEARCACHE > i)
			continue;

		if (stuck)
			count_stuck++;

		// test whether we have an increasing timer
		if (!(time2 > time))
			time_backwards++;

		// use 32 bit value to ensure compilation on 32 bit arches
		lowdelta = time2 - time;
		if (!(lowdelta % 100))
			count_mod++;

		 // ensure that we have a varying delta timer which is necessary
		 // for the calculation of entropy -- perform this check
		 // only after the first loop is executed as we need to prime
		 // the old_data value

		if (delta > old_delta)
			delta_sum += (delta - old_delta);
		else
			delta_sum += (old_delta - delta);
		old_delta = delta;
	}

	 // we allow up to three times the time running backwards.
	 // CLOCK_REALTIME is affected by adjtime and NTP operations. Thus,
	 // if such an operation just happens to interfere with our test, it
	 // should not fail. The value of 3 should cover the NTP case being
	 // performed during our test run.
	if (3 < time_backwards)
		return ENOMONOTONIC;

	 // Variations of deltas of time must on average be larger
	 // than 1 to ensure the entropy estimation
	 // implied with 1 is preserved
	if ((delta_sum) <= 1)
		return EMINVARVAR;

	 // Ensure that we have variations in the time stamp below 10 for at least
	 // 10% of all checks -- on some platforms, the counter increments in
	 // multiples of 100, but not always
	if ((TESTLOOPCOUNT / 10 * 9) < count_mod)
		return ECOARSETIME;

	 // If we have more than 90% stuck results, then this Jitter RNG is
	 // likely to not work well.
	if (JENT_STUCK_INIT_THRES(TESTLOOPCOUNT) < count_stuck)
		return ESTUCK;

	return 0;
}*/
