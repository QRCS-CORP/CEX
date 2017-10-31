#ifndef CEXTEST_PRNGTEST_H
#define CEXTEST_PRNGTEST_H

#include "ITest.h"
#include "../CEX/IPrng.h"

namespace Test
{
	/// <summary>
	/// Tests the minimum to maximum ranged returns from a PRNG
	/// </summary>
	class PrngTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// PRNG operational range tests
		/// </summary>
		PrngTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~PrngTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		template<class T>
		static std::string ChiSquare(T* Rng, size_t SampleSize = 1024000)
		{
			// converges slowly, needs 1mb or more
			std::vector<byte> rnd(SampleSize);
			Rng->GetBytes(rnd);
			double x = TestUtils::ChiSquare(rnd) * 100;
			std::string status = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

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

			return status;
		}

		template<class T>
		static std::string MeanValue(T* Rng, size_t SampleSize = 102400)
		{
			// 100kb sample
			std::vector<byte> rnd(SampleSize);
			Rng->GetBytes(rnd);
			double x = TestUtils::MeanValue(rnd);
			std::string status = (std::string("Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

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

			return status;
		}

		void OnProgress(std::string Data);
	};
}

#endif