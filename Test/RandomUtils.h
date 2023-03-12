#ifndef CEXTEST_RANDOMUTILS_H
#define CEXTEST_RANDOMUTILS_H

#include "ITest.h"

namespace Test
{
	class RandomUtils final
	{
	public:

		static void Evaluate(const std::string &Name, std::vector<uint8_t> &Sample);

		template<class T>
		static std::string ChiSquare(T* Rng, size_t SampleSize = 1024000)
		{
			// converges slowly, needs 1mb or more
			std::vector<uint8_t> rnd(SampleSize);
			std::string status;
			double x;

			Rng->Generate(rnd);
			x = TestUtils::ChiSquare(rnd) * 100.0;
			status = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

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
		static std::string ChiSquareG(T* Generator, std::vector<uint8_t> &Seed, size_t SampleSize = 1024000)
		{
			// converges slowly, needs 1mb or more
			std::vector<uint8_t> rnd(SampleSize);
			std::string status;
			double x;

			Generator->Initialize(Seed);
			Generator->Generate(rnd);
			x = TestUtils::ChiSquare(rnd) * 100.0;
			status = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

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
			std::vector<uint8_t> rnd(SampleSize);
			std::string status;
			double x;

			Rng->Generate(rnd);
			x = TestUtils::MeanValue(rnd);
			status = (std::string("Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

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

		template<class T>
		static std::string MeanValueG(T* Generator, std::vector<uint8_t> &Seed, size_t SampleSize = 102400)
		{
			// 100kb sample
			std::vector<uint8_t> rnd(SampleSize);
			std::string status;
			double x;

			Generator->Initialize(Seed);
			Generator->Generate(rnd);
			x = TestUtils::MeanValue(rnd);
			status = (std::string("Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

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
	};
}
#endif