#include "RandomUtils.h"

namespace Test
{
	void RandomUtils::Evaluate(const std::string &Name, std::vector<byte> &Sample)
	{
		double x;
		std::string status;

		// mean value test
		x = TestUtils::MeanValue(Sample);

		status = (Name + std::string(": Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

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

		TestUtils::Print(std::string(status));

		// ChiSquare
		x = TestUtils::ChiSquare(Sample) * 100;
		status = (std::string(Name + ": ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

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
		TestUtils::Print(std::string(status));

		// ordered runs
		if (TestUtils::OrderedRuns(Sample))
		{
			throw TestException(std::string("Evaluate"), Name, std::string("Exception: Ordered runs test failure!"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(Sample))
		{
			throw TestException(std::string("Evaluate"), Name, std::string("Exception: Succesive zeroes test failure!"));
		}
	}
}
