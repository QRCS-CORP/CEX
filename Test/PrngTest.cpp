#include "PrngTest.h"
// providers
#include "../CEX/ACP.h"
#include "../CEX/CJP.h"
#include "../CEX/CSP.h"
#include "../CEX/ECP.h"
#include "../CEX/RDP.h"
// generators
#include "../CEX/BCG.h"
#include "../CEX/CSG.h"
#include "../CEX/HCG.h"
// prngs
#include "../CEX/BCR.h"
#include "../CEX/CSR.h"
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
		using namespace CEX::Drbg;
		using namespace CEX::Prng;
		using namespace CEX::Provider;

		try
		{
			OnProgress(std::string("### Uses chisquare and mean value tests to evaluate output from each prng"));
			OnProgress(std::string(""));
			OnProgress(std::string("### PRNG Output Tests ###"));

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

			OnProgress(std::string(""));
			OnProgress(std::string("### Deterministic Pseujdo-Random Generator Output Tests ###"));
			std::vector<byte> seed(0);
			CSP rng;

			OnProgress(std::string("Testing the Block-Cipher Counter Generator (BCG):"));
			BCG* bcg = new BCG();
			auto ksb = bcg->LegalKeySizes()[0];
			seed.resize(ksb.KeySize() + ksb.NonceSize());
			OnProgress(ChiSquareG(bcg, seed));
			OnProgress(MeanValueG(bcg, seed));
			delete bcg;

			OnProgress(std::string("Testing the Customized SHAKE Generator (CSG):"));
			CSG* csg = new CSG();
			auto ksc = csg->LegalKeySizes()[0];
			seed.resize(ksc.KeySize());
			OnProgress(ChiSquareG(csg, seed));
			OnProgress(MeanValueG(csg, seed));
			delete csg;

			OnProgress(std::string("Testing the HMAC Counter Generator (BCG):"));
			HCG* hcg = new HCG(Digests::SHA256);
			auto ksh = hcg->LegalKeySizes()[0];
			seed.resize(ksh.KeySize());
			rng.Generate(seed);
			OnProgress(ChiSquareG(hcg, seed));
			OnProgress(MeanValueG(hcg, seed));
			delete hcg;

			OnProgress(std::string(""));
			OnProgress(std::string("### Entropy Provider Output Tests ###"));

			OnProgress(std::string("Testing the Auto Collection Provider (ACP):"));
			ACP* acp = new ACP();
			OnProgress(ChiSquare(acp));
			OnProgress(MeanValue(acp));
			delete acp;

			// too slow for debug, but passes tests
#if defined(CEX_NO_DEBUG)
			OnProgress(std::string("Testing the Cpu/Memory Jitter Provider (CJP):"));
			CJP* cjp = new CJP();
			OnProgress(ChiSquare(cjp, 10240));
			OnProgress(MeanValue(cjp, 10240));
			delete cjp;
#endif
			OnProgress(std::string("Testing the Crypto System Provider (CSP):"));
			CSP* csp = new CSP();
			OnProgress(ChiSquare(csp));
			OnProgress(MeanValue(csp));
			delete csp;

			OnProgress(std::string("Testing the RDRAND/RDSEED Provider (ECP):"));
			ECP* ecp = new ECP();
			OnProgress(ChiSquare(ecp));
			OnProgress(MeanValue(ecp));
			delete ecp;

			OnProgress(std::string("Testing the RDRAND/RDSEED Provider (RDP):"));
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
