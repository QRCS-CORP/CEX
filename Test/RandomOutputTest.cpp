#include "RandomOutputTest.h"
#include "../CEX/FileStream.h"
#include "../CEX/IntegerTools.h"
// providers
#include "../CEX/ACP.h"
#include "../CEX/CJP.h"
#include "../CEX/CSP.h"
#include "../CEX/ECP.h"
#include "../CEX/RDP.h"
// drbgs
#include "../CEX/BCG.h"
#include "../CEX/CSG.h"
#include "../CEX/HCG.h"
// prngs
#include "../CEX/BCR.h"
#include "../CEX/CSR.h"
#include "../CEX/HCR.h"
// kdfs
#include "../CEX/SHAKE.h"

namespace Test
{
	using namespace CEX::Drbg;
	using namespace CEX::Kdf;
	using namespace CEX::Prng;
	using namespace CEX::Provider;

	const std::string RandomOutputTest::CLASSNAME = "RandomOutputTest";
	const std::string RandomOutputTest::DESCRIPTION = "Copies generator tmpr to a file for external testing.";
	const std::string RandomOutputTest::SUCCESS = "SUCCESS! All Random Output tests have executed succesfully.";
	const std::string RandomOutputTest::FOLDER = "C:/";

	RandomOutputTest::RandomOutputTest(const std::string &OutputFolder)
		:
		m_outputFolder(OutputFolder),
		m_progressEvent()
	{
	}

	RandomOutputTest::~RandomOutputTest()
	{
	}

	const std::string RandomOutputTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RandomOutputTest::Progress()
	{
		return m_progressEvent;
	}

	std::string RandomOutputTest::Run()
	{
		if (m_outputFolder.size() < 4)
		{
			throw TestException(CLASSNAME, std::string("Run"), std::string("Constructor"), std::string("The folder path is invalid!"));
		}

		try
		{
			// providers
			// cpu jitter is very slow, and not meant for such large samples..
			if (ENABLE_CJPTEST)
			{
				OnProgress(std::string("Collecting 10MB of random from Cpu Jitter Provider, this can take 1 hour or more.."));
				CJPGenerateFile(m_outputFolder + "cjp_10mb.txt", SAMPLE_SIZE);
				OnProgress(std::string("CPU Jitter Provider completed.."));
			}

			ACPGenerateFile(m_outputFolder + std::string("acp_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Auto Collection Provider (ACP) generated sample file succesfully.."));
			CSPGenerateFile(m_outputFolder + std::string("csp_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Crypto Service Provider (CSP) generated sample file succesfully.."));
			ECPGenerateFile(m_outputFolder + std::string("ecp_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Entropy Collection Provider (ECP) generated sample file succesfully...."));
			RDPGenerateFile(m_outputFolder + std::string("rdp_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("RDSeed Provider (RDP) generated sample file succesfully...."));

			// drbg's
			BCGGenerateFile(m_outputFolder + std::string("bcg_10mb.txt"), SAMPLE_SIZE, false);
			OnProgress(std::string("Block cipher Counter Generator (BCG) generated sample file succesfully.."));
			BCGGenerateFile(m_outputFolder + std::string("bcgp_10mb.txt"), SAMPLE_SIZE, true);
			OnProgress(std::string("Block cipher parallel Counter Generator (BCGP) generated sample file succesfully.."));
			CSGGenerateFile(m_outputFolder + std::string("csg_10mb.txt"), SAMPLE_SIZE, false);
			OnProgress(std::string("Custom SHAKE Generator (CSG) generated sample file succesfully.."));
			CSGGenerateFile(m_outputFolder + std::string("csgp_10mb.txt"), SAMPLE_SIZE, true);
			OnProgress(std::string("Custom SHAKE parallel Generator (CSGP) generated sample file succesfully.."));
			HCGGenerateFile(m_outputFolder + std::string("hcg_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("HMAC Counter Generator (HCG) generated sample file succesfully.."));

			// prngs
			BCRGenerateFile(m_outputFolder + std::string("bcr_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Block cipher Counter RNG (BCR) generated sample file succesfully.."));
			CSRGenerateFile(m_outputFolder + std::string("csr_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Custom SHAKE RNG (CSR) generated sample file succesfully.."));
			HCRGenerateFile(m_outputFolder + std::string("hcr_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Custom SHAKE RNG (CSR) generated sample file succesfully.."));

			// kdf
			SHAKEGenerateFile(m_outputFolder + std::string("shake_10mb.txt"), SAMPLE_SIZE);
			OnProgress(std::string("Custom SHAKE Generator (cSHAKE) generated sample file succesfully.."));

			OnProgress(std::string("All samples have been written successfully.."));

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

	// entropy providers

	void RandomOutputTest::ACPGenerateFile(std::string FilePath, size_t FileSize)
	{
		ACP pvd;
		std::vector<byte> tmpr(1024);
		size_t plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		}
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::CJPGenerateFile(std::string FilePath, size_t FileSize)
	{
		CJP pvd;
		std::vector<byte> tmpr(1024);
		size_t plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::CSPGenerateFile(std::string FilePath, size_t FileSize)
	{
		CSP pvd;
		std::vector<byte> tmpr(1024);
		size_t plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::ECPGenerateFile(std::string FilePath, size_t FileSize)
	{
		ECP pvd;
		std::vector<byte> tmpr(1024);
		size_t plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::RDPGenerateFile(std::string FilePath, size_t FileSize)
	{
		RDP pvd;
		std::vector<byte> tmpr(1024);
		size_t plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	// drbgs

	void RandomOutputTest::BCGGenerateFile(std::string FilePath, size_t FileSize, bool Parallel)
	{
		BCG gen(BlockCiphers::RHXS256, Providers::CSP, Parallel);
		CSP pvd;
		std::vector<byte> tmpk(gen.LegalKeySizes()[1].KeySize());
		std::vector<byte> tmpn(gen.LegalKeySizes()[1].NonceSize());
		std::vector<byte> tmpi(gen.LegalKeySizes()[1].InfoSize());
		const size_t PRCLEN = Parallel ? gen.ParallelBlockSize() : 1024;
		std::vector<byte> tmpr(PRCLEN);
		size_t plen;

		pvd.Generate(tmpk);
		pvd.Generate(tmpn);
		pvd.Generate(tmpi);
		SymmetricKey kp(tmpk, tmpn, tmpi);

		gen.Initialize(kp);

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::CSGGenerateFile(std::string FilePath, size_t FileSize, bool Parallel)
	{
		CSG gen(ShakeModes::SHAKE256, Providers::CSP, Parallel);
		CSP pvd;
		std::vector<byte> tmpk(gen.LegalKeySizes()[1].KeySize());
		std::vector<byte> tmpn(gen.LegalKeySizes()[1].NonceSize());
		std::vector<byte> tmpi(gen.LegalKeySizes()[1].InfoSize());
		const size_t PRCLEN = Parallel ? 4096 : 1024;
		std::vector<byte> tmpr(PRCLEN);
		size_t plen;

		pvd.Generate(tmpk);
		pvd.Generate(tmpn);
		pvd.Generate(tmpi);
		SymmetricKey kp(tmpk, tmpn, tmpi);

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);
		gen.Initialize(kp);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::HCGGenerateFile(std::string FilePath, size_t FileSize)
	{
		HCG gen(SHA2Digests::SHA256, Providers::CSP);
		CSP pvd;
		std::vector<byte> tmpk(gen.LegalKeySizes()[1].KeySize());
		std::vector<byte> tmpn(gen.LegalKeySizes()[1].NonceSize());
		std::vector<byte> tmpi(gen.LegalKeySizes()[1].InfoSize());
		std::vector<byte> tmpr(1024);
		size_t plen;

		pvd.Generate(tmpk);
		pvd.Generate(tmpn);
		pvd.Generate(tmpi);
		SymmetricKey kp(tmpk, tmpn, tmpi);

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);
		gen.Initialize(kp);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	// prngs

	void RandomOutputTest::BCRGenerateFile(std::string FilePath, size_t FileSize)
	{
		BCR gen(BlockCiphers::RHXS256, Providers::CSP, true);
		std::vector<byte> tmpr(1024);
		size_t plen;

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::CSRGenerateFile(std::string FilePath, size_t FileSize)
	{
		CSR gen(ShakeModes::SHAKE256, Providers::CSP);
		std::vector<byte> tmpr(1024);
		size_t plen;

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::HCRGenerateFile(std::string FilePath, size_t FileSize)
	{
		HCR gen(SHA2Digests::SHA256, Providers::CSP);
		std::vector<byte> tmpr(1024);
		size_t plen;

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::SHAKEGenerateFile(std::string FilePath, size_t FileSize)
	{
		Kdf::SHAKE gen(ShakeModes::SHAKE256);
		CSP pvd;
		std::vector<byte> tmpk(gen.LegalKeySizes()[1].KeySize());
		std::vector<byte> tmpn(gen.LegalKeySizes()[1].NonceSize());
		std::vector<byte> tmpi(gen.LegalKeySizes()[1].InfoSize());
		std::vector<byte> tmpr(1024);
		size_t plen;

		pvd.Generate(tmpk);
		pvd.Generate(tmpn);
		pvd.Generate(tmpi);
		SymmetricKey kp(tmpk, tmpn, tmpi);

		gen.Initialize(kp);

		plen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			gen.Generate(tmpr);
			size_t rmd = Utility::IntegerTools::Min(tmpr.size(), plen);
			fs.Write(tmpr, 0, rmd);
			plen -= rmd;
		} 
		while (plen != 0);

		fs.Flush();
		fs.Close();
	}

	void RandomOutputTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
