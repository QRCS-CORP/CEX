#include "DCGTest.h"
#include "../CEX/CSP.h"
#include "../CEX/DCG.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/SHA256.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	std::string DCGTest::Run()
	{
		try
		{
			CheckInit();
			OnProgress("DCG: Passed initialization tests..");

			// old tests do not meet minimum seed size requirements
			//Initialize();
			//CompareOutput(m_seed256[0], m_expected256[0]);
			//CompareOutput(m_seed256[1], m_expected256[1]);
			//OnProgress("DCG: Passed output comparison tests..");

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void DCGTest::CompareOutput(std::vector<byte> &Seed, std::vector<byte> &Expected)
	{
		std::vector<byte> output(Expected.size());
		Drbg::DCG ctd(Enumeration::Digests::SHA256);
		ctd.Initialize(Seed);

		for (int i = 0; i != 1024; i++)
			ctd.Generate(output);

		if (output != Expected)
			throw std::exception("DCGTest: Failed comparison test!");
	}

	void DCGTest::CheckInit()
	{
		std::vector<byte> info(32, 0x03);
		std::vector<byte> nonce(8, 0x02);
		std::vector<byte> output(SAMPLE_SIZE);
		std::vector<byte> seed(32, 0x01);

		try
		{
			Digest::SHA256* dgt = new Digest::SHA256();
			Provider::CSP* pvd = new Provider::CSP();

			// test primitive instantiation
			Drbg::DCG ctd(dgt);
			// first legal key size
			size_t seedLen = ctd.LegalKeySizes()[0].KeySize();
			seed.resize(seedLen, 0x01);
			ctd.Initialize(seed);
			ctd.Generate(output);

			delete dgt;
			delete pvd;

			if (CheckRuns(output))
				throw std::exception("DCGTest: Failed duplication test!");
		}
		catch (...)
		{
			throw std::exception("DCGTest: Failed primitive instantiation test!");
		}

		try
		{
			// test enumeration instantiation
			Drbg::DCG ctd(Enumeration::Digests::SHA512, CEX::Enumeration::Providers::CSP);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("DCGTest: Failed duplication test!");

			// second legal key size + nonce
			size_t seedLen = ctd.LegalKeySizes()[1].KeySize() - 8;
			seed.resize(seedLen, 0x01);
			nonce.resize(8, 0x02);
			ctd.Initialize(seed, nonce);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("DCGTest: Failed duplication test!");

			// third legal key size + nonce + info
			seedLen = (ctd.LegalKeySizes()[2].KeySize() / 2) - 8;
			seed.resize(seedLen, 0x01);
			info.resize(seedLen, 0x03);
			ctd.Initialize(seed, nonce, info);
			ctd.Generate(output);

			if (CheckRuns(output))
				throw std::exception("DCGTest: Failed duplication test!");

		}
		catch (...)
		{
			throw std::exception("DCGTest: Failed enumeration instantiation test!");
		}
	}

	bool DCGTest::CheckRuns(const std::vector<byte> &Input)
	{
		// indicates zeroed output or bad run
		for (size_t i = 0; i < Input.size() - 4; i += 4)
		{
			if (Input[i] == Input[i + 1] &&
				Input[i + 1] == Input[i + 2] &&
				Input[i + 2] == Input[i + 3])
					return true;
		}
		return false;
	}

	void DCGTest::Initialize()
	{
		const char* seed256Encoded[2] =
		{
			("0000000000000000"),
			("81dcfafc885914057876")
		};
		HexConverter::Decode(seed256Encoded, 2, m_seed256);

		// note: to match the old values, initialize m_reseedCounter to 32 (1 cycle for sha256) in DCG ctor
		// to run this test seed size check must be remmed in DCG::Initialize
		const char* exp256Encoded[2] =
		{
			("0d2d154263ca561a5b60bcb7c780ac78483cd7c057fcb0c99363b936f4524948"), // old: 587e2dfd597d086e47ddcd343eac983a5c913bef8c6a1a560a5c1bc3a74b0991
			("b0a48955fce5fa7af7544e154872451846847a2af2d69287043f6cb8a139c7f9")  // old: bdab3ca831b472a2fa09bd1bade541ef16c96640a91fcec553679a136061de98 
		};
		HexConverter::Decode(exp256Encoded, 2, m_expected256);
	}

	void DCGTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}