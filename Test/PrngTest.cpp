#include "PrngTest.h"
#include "../CEX/BCR.h"
#include "../CEX/DCR.h"
#include "../CEX/HCR.h"

namespace Test
{
	const std::string PrngTest::DESCRIPTION = "Tests Prngs for valid minimum and maximum range responses.";
	const std::string PrngTest::FAILURE = "FAILURE! ";
	const std::string PrngTest::SUCCESS = "SUCCESS! All Prng range tests have executed succesfully.";

	PrngTest::PrngTest()
		:
		m_progressEvent()
	{
	}

	PrngTest::~PrngTest()
	{
	}

	std::string PrngTest::Run()
	{
		using namespace CEX::Prng;

		try
		{
			OnProgress(std::string("### PRNG Output Tests ###"));
			OnProgress(std::string("### Uses chisquare and mean value tests to evaluate output from each prng"));
			OnProgress(std::string(""));

			OnProgress(std::string("Testing the Block cipher Counter based Rng:"));
			BCR* rnd1 = new BCR();
			ChiSquare(rnd1);
			MeanValue(rnd1);
			delete rnd1;

			OnProgress(std::string("Testing the Digest Counter based Rng:"));
			DCR* rnd2 = new DCR();
			ChiSquare(rnd2);
			MeanValue(rnd2);
			delete rnd2;

			OnProgress(std::string("Testing the HMAC Counter based Rng:"));
			HCR* rnd3 = new HCR();
			ChiSquare(rnd3);
			MeanValue(rnd3);
			delete rnd3;

			OnProgress(std::string(".."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw FAILURE + " : " + ex.what();
		}
		catch (...)
		{
			throw FAILURE;
		}
	}

	void PrngTest::ChiSquare(Prng::IPrng* Rng)
	{
		// converges slowly, needs 1mb or more
		std::vector<byte> rnd(1024000);
		Rng->GetBytes(rnd);
		double x = TestUtils::ChiSquare(rnd) * 100;
		std::string ret = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

		if (x < 1.0 || x > 99.0)
			ret += std::string("(FAIL)");
		else if (x < 5.0 || x > 95.0)
			ret += std::string("(WARN)");
		else
			ret += std::string("(PASS)");

		OnProgress(ret);
	}

	void PrngTest::MeanValue(Prng::IPrng* Rng)
	{
		// 100kb sample
		std::vector<byte> rnd(102400);
		Rng->GetBytes(rnd);
		double x = TestUtils::MeanValue(rnd);
		std::string ret = (std::string("Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

		if (x < 122.5 || x > 132.5)
			ret += std::string("(FAIL)");
		else if (x < 125.0 || x > 130.0)
			ret += std::string("(WARN)");
		else
			ret += std::string("(PASS)");

		OnProgress(ret);
	}

	void PrngTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}