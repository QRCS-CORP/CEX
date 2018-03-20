#include "PrngTest.h"
#include "../CEX/BCR.h"
#include "../CEX/HCR.h"
#include "../CEX/ACP.h"
#include "../CEX/CJP.h"
#include "../CEX/CSP.h"
#include "../CEX/RDP.h"

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

	const std::string PrngTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &PrngTest::Progress()
	{
		return m_progressEvent;
	}

	std::string PrngTest::Run()
	{
		using namespace CEX::Prng;
		using namespace CEX::Provider;

		try
		{
			OnProgress(std::string("### PRNG Output Tests ###"));
			OnProgress(std::string("### Uses chisquare and mean value tests to evaluate output from each prng"));
			OnProgress(std::string(""));

			OnProgress(std::string("Testing the HMAC Counter based Rng:"));
			HCR* hcr = new HCR();
			OnProgress(ChiSquare(hcr));
			OnProgress(MeanValue(hcr));
			delete hcr;

			OnProgress(std::string("Testing the Block cipher Counter based Rng:"));
			BCR* bcr = new BCR();
			OnProgress(ChiSquare(bcr));
			OnProgress(MeanValue(bcr));
			delete bcr;

			OnProgress(std::string("Testing the Auto Collection Provider:"));
			ACP* acp = new ACP();
			OnProgress(ChiSquare(acp));
			OnProgress(MeanValue(acp));
			delete acp;

			// too slow for debug, but passes tests in every config
#if defined(CEX_NO_DEBUG)
			OnProgress(std::string("Testing the Cpu/Memory Jitter Provider:"));
			CJP* cjp = new CJP();
			OnProgress(ChiSquare(cjp, 10240));
			OnProgress(MeanValue(cjp, 10240));
			delete cjp;
#endif
			OnProgress(std::string("Testing the Crypto System Provider:"));
			CSP* csp = new CSP();
			OnProgress(ChiSquare(csp));
			OnProgress(MeanValue(csp));
			delete csp;

			OnProgress(std::string("Testing the RDRAND/RDSEED Provider:"));
			RDP* rdp = new RDP();
			OnProgress(ChiSquare(rdp));
			OnProgress(MeanValue(rdp));
			delete rdp;

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

	void PrngTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
