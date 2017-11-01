#include "RandomOutputTest.h"
#if defined(__AVX__)
#	include "../CEX/AHX.h"
#else
#	include "../CEX/RHX.h"
#endif
#include "../CEX/CJP.h"
#include "../CEX/BCG.h"
#include "../CEX/CSP.h"
#include "../CEX/DCG.h"
#include "../CEX/ECP.h"
#include "../CEX/FileStream.h"
#include "../CEX/HCG.h"
#include "../CEX/RDP.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	const std::string RandomOutputTest::DESCRIPTION = "Copies generator output to a file for external testing.";
	const std::string RandomOutputTest::FAILURE = "FAILURE! ";
	const std::string RandomOutputTest::SUCCESS = "SUCCESS! All Random Output tests have executed succesfully.";

	RandomOutputTest::RandomOutputTest()
		:
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
		const std::string FILEPATH = "C:/Users/John/Documents/Tests/";
		const size_t FILESIZE = 1024 * 1000 * 10;

		try
		{
			// providers
			//CJPGenerateFile(FILEPATH + "cjp_10mb.txt", FILESIZE); // can take an hour or more!
			//OnProgress(std::string("CPU Jitter Provider completed.."));
			CSPGenerateFile(FILEPATH + "csp_10mb.txt", FILESIZE);
			OnProgress(std::string("System Crypto Service Provider completed.."));
			ECPGenerateFile(FILEPATH + "ecp_10mb.txt", FILESIZE);
			OnProgress(std::string("Entropy Collection Provider completed.."));
			RDPGenerateFile(FILEPATH + "rdp_10mb.txt", FILESIZE);
			OnProgress(std::string("RDSeed Provider completed.."));

			// drbg's
			CMGGenerateFile(FILEPATH + "cmg_10mb.txt", FILESIZE);
			OnProgress(std::string("Counter Mode Generator completed.."));
			DCGGenerateFile(FILEPATH + "dcg_10mb.txt", FILESIZE);
			OnProgress(std::string("Digest Counter Generator completed.."));
			HMGGenerateFile(FILEPATH + "hmg_10mb.txt", FILESIZE);
			OnProgress(std::string("Hash based Mac Generator completed.."));

			OnProgress(std::string("Passed Finalize/Compute methods output comparison.."));

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

	void RandomOutputTest::CMGGenerateFile(std::string FilePath, size_t FileSize)
	{
		using namespace Cipher::Symmetric::Block;

		Digest::SHA512* dgt1 = new Digest::SHA512();
#if defined(__AVX__)
		AHX* cpr = new AHX(dgt1, 22);
#else
		RHX* cpr = new RHX(dgt1, 22);
#endif
		Digest::SHA512* dgt2 = new Digest::SHA512();
		Provider::CSP* pvd = new Provider::CSP();
		Drbg::BCG ctd(cpr, dgt2, pvd);

		std::vector<byte> seed(ctd.LegalKeySizes()[1].KeySize() - ctd.NonceSize());
		std::vector<byte> nonce(ctd.NonceSize());
		std::vector<byte> info(ctd.DistributionCodeMax());
		std::vector<byte> output(ctd.ParallelBlockSize());

		pvd->GetBytes(seed);
		pvd->GetBytes(nonce);
		pvd->GetBytes(info);
		ctd.ParallelProfile().IsParallel() = true;
		ctd.Initialize(seed, nonce, info);

		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			ctd.Generate(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete cpr;
		delete pvd;
	}

	void RandomOutputTest::DCGGenerateFile(std::string FilePath, size_t FileSize)
	{
		Digest::SHA256* dgt = new Digest::SHA256();
		Provider::CSP* pvd = new Provider::CSP();
		Drbg::DCG ctd(dgt, pvd);

		std::vector<byte> seed(ctd.LegalKeySizes()[1].KeySize());
		std::vector<byte> nonce(ctd.NonceSize());
		std::vector<byte> info(ctd.DistributionCodeMax());
		std::vector<byte> output(ctd.MaxRequestSize());

		pvd->GetBytes(seed);
		pvd->GetBytes(nonce);
		pvd->GetBytes(info);
		ctd.Initialize(seed, nonce, info);

		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			ctd.Generate(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete dgt;
		delete pvd;
	}

	void RandomOutputTest::HMGGenerateFile(std::string FilePath, size_t FileSize)
	{
		Digest::SHA256* dgt = new Digest::SHA256();
		Provider::CSP* pvd = new Provider::CSP();
		Drbg::HCG ctd(dgt, pvd);

		std::vector<byte> seed(ctd.LegalKeySizes()[1].KeySize());
		std::vector<byte> nonce(ctd.NonceSize());
		std::vector<byte> info(ctd.DistributionCodeMax());
		std::vector<byte> output(ctd.MaxRequestSize());

		pvd->GetBytes(seed);
		pvd->GetBytes(nonce);
		pvd->GetBytes(info);
		ctd.Initialize(seed, nonce, info);

		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			ctd.Generate(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete dgt;
	}

	void RandomOutputTest::CJPGenerateFile(std::string FilePath, size_t FileSize)
	{
		Provider::CJP* pvd = new Provider::CJP();
		std::vector<byte> output(1024);
		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd->GetBytes(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete pvd;
	}

	void RandomOutputTest::CSPGenerateFile(std::string FilePath, size_t FileSize)
	{
		Provider::CSP* pvd = new Provider::CSP();
		std::vector<byte> output(1024);
		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd->GetBytes(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete pvd;
	}

	void RandomOutputTest::ECPGenerateFile(std::string FilePath, size_t FileSize)
	{
		Provider::ECP* pvd = new Provider::ECP();
		std::vector<byte> output(1024);
		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd->GetBytes(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete pvd;
	}

	void RandomOutputTest::RDPGenerateFile(std::string FilePath, size_t FileSize)
	{
		Provider::RDP* pvd = new Provider::RDP();
		std::vector<byte> output(1024);
		size_t prcLen = FileSize;
		IO::FileStream fs(FilePath, IO::FileStream::FileAccess::Write);

		do
		{
			pvd->GetBytes(output);
			size_t rmd = Utility::IntUtils::Min(output.size(), prcLen);
			fs.Write(output, 0, rmd);
			prcLen -= rmd;
		} 
		while (prcLen != 0);

		fs.Flush();
		fs.Close();

		delete pvd;
	}

	void RandomOutputTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}