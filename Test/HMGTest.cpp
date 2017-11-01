#include "HMGTest.h"
#include "../CEX/CSP.h"
#include "../CEX/HCG.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SHA256.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	const std::string HMGTest::DESCRIPTION = "HCG implementations vector comparison tests.";
	const std::string HMGTest::FAILURE = "FAILURE! ";
	const std::string HMGTest::SUCCESS = "SUCCESS! All HCG tests have executed succesfully.";

	HMGTest::HMGTest()
		:
		m_progressEvent()
	{
	}

	HMGTest::~HMGTest()
	{
	}

	const std::string HMGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HMGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HMGTest::Run()
	{
		try
		{
			CheckMac();
			OnProgress(std::string("HCG: Passed mac engine tests.."));
			CheckInit();
			OnProgress(std::string("HCG: Passed initialization tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	// test with each digest type, manually verified block alignments
	void HMGTest::CheckInit()
	{
		std::vector<byte> output(SAMPLE_SIZE);

		try
		{
			Digest::SHA256* dgt = new Digest::SHA256();
			Provider::CSP* pvd = new Provider::CSP();

			// test primitive instantiation
			Drbg::HCG ctd(dgt, pvd);
			size_t seedLen = ctd.LegalKeySizes()[0].KeySize();
			std::vector<byte> seed(seedLen, 0x01);
			size_t nonceLen = ctd.NonceSize();
			std::vector<byte> nonce(nonceLen, 0x02);
			size_t infoLen = ctd.DistributionCodeMax();
			std::vector<byte> info(infoLen, 0x03);

			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			delete dgt;
			delete pvd;

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			// test enumeration instantiation
			Drbg::HCG ctd(Enumeration::Digests::SHA512, CEX::Enumeration::Providers::CSP);
			std::vector<byte> info(ctd.DistributionCodeMax(), 0x01);
			std::vector<byte> nonce(ctd.NonceSize(), 0x02);
			// first legal key size
			std::vector<byte> seed(ctd.LegalKeySizes()[0].KeySize(), 0x03);
			// seed only
			ctd.Initialize(seed);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}

			// second legal key size
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x03);
			// set seed + nonce
			ctd.Initialize(seed, nonce);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}

			// third legal key size + nonce + info
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed enumeration instantiation test!");
		}
	}

	void HMGTest::CheckMac()
	{
		std::vector<byte> output(SAMPLE_SIZE);
		std::vector<byte> seed(0);
		std::vector<byte> nonce(0);
		std::vector<byte> info(0);

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Blake512, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Blake256, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Keccak256, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Keccak512, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::SHA256, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::SHA512, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Skein1024, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Skein256, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}

		try
		{
			Drbg::HCG ctd(Enumeration::Digests::Skein512, CEX::Enumeration::Providers::CSP);
			seed.resize(ctd.LegalKeySizes()[0].KeySize(), 0x01);
			nonce.resize(ctd.NonceSize(), 0x02);
			info.resize(ctd.DistributionCodeMax(), 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
			{
				throw TestException("HMGTest: Failed duplication test!");
			}
		}
		catch (...)
		{
			throw TestException("HMGTest: Failed primitive instantiation test!");
		}
	}

	bool HMGTest::CheckRuns(const std::vector<byte> &Input)
	{
		bool state = false;

		// indicates zeroed output or bad run
		for (size_t i = 0; i < Input.size() - 4; i += 4)
		{
			if (Input[i] == Input[i + 1] &&
				Input[i + 1] == Input[i + 2] &&
				Input[i + 2] == Input[i + 3])
			{
				state = true;
				break;
			}
		}

		return state;
	}

	void HMGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}