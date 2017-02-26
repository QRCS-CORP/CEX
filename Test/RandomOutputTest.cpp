#include "RandomOutputTest.h"
#include "../CEX/AHX.h"
#include "../CEX/CJP.h"
#include "../CEX/CMG.h"
#include "../CEX/CSP.h"
#include "../CEX/DCG.h"
#include "../CEX/ECP.h"
#include "../CEX/FileStream.h"
#include "../CEX/HMG.h"
#include "../CEX/RDP.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	std::string RandomOutputTest::Run()
	{
		const std::string FILEPATH = "C:/Users/John/Documents/Tests/";
		const size_t FILESIZE = 1024 * 1000 * 10;

		try
		{
			// providers
			//CJPGenerateFile(FILEPATH + "cjp_10mb.txt", FILESIZE); // can take an hour or more!
			//OnProgress("CPU Jitter Provider completed..");
			CSPGenerateFile(FILEPATH + "csp_10mb.txt", FILESIZE);
			OnProgress("System Crypto Service Provider completed..");
			ECPGenerateFile(FILEPATH + "ecp_10mb.txt", FILESIZE);
			OnProgress("Entropy Collection Provider completed..");
			RDPGenerateFile(FILEPATH + "rdp_10mb.txt", FILESIZE);
			OnProgress("RDSeed Provider completed..");

			// drbg's
			CMGGenerateFile(FILEPATH + "cmg_10mb.txt", FILESIZE);
			OnProgress("Counter Mode Generator completed..");
			DCGGenerateFile(FILEPATH + "dcg_10mb.txt", FILESIZE);
			OnProgress("Digest Counter Generator completed..");
			HMGGenerateFile(FILEPATH + "hmg_10mb.txt", FILESIZE);
			OnProgress("Hash based Mac Generator completed..");

			OnProgress("Passed Finalize/Compute methods output comparison..");

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

	void RandomOutputTest::CMGGenerateFile(std::string FilePath, size_t FileSize)
	{
		using namespace Cipher::Symmetric::Block;

		Digest::SHA512* dgt1 = new Digest::SHA512();
		AHX* cpr = new AHX(dgt1, 22);
		Digest::SHA512* dgt2 = new Digest::SHA512();
		Provider::CSP* pvd = new Provider::CSP();
		Drbg::CMG ctd(cpr, dgt2, pvd);

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
		Drbg::HMG ctd(dgt, pvd);

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

	void RandomOutputTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}