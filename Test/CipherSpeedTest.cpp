#include "CipherSpeedTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/ECB.h"
#include "../CEX/HBA.h"
#include "../CEX/ICM.h"
#include "../CEX/OFB.h"
#include "../CEX/ACS.h"
#include "../CEX/CSX256.h"
#include "../CEX/CSX512.h"
#include "../CEX/MCS.h"
#include "../CEX/RCS.h"
#include "../CEX/TSX256.h"
#include "../CEX/TSX512.h"
#include "../CEX/TSX1024.h"

namespace Test
{
	using namespace Cipher::Block;
	using namespace Cipher::Block::Mode;
	using namespace Cipher::Stream;
	using Enumeration::StreamAuthenticators;

	const std::string CipherSpeedTest::CLASSNAME = "CipherSpeedTest";
	const std::string CipherSpeedTest::DESCRIPTION = "Cipher Speed Tests.";
	const std::string CipherSpeedTest::MESSAGE = "COMPLETE! Speed tests have executed succesfully.";
	const bool CipherSpeedTest::HAS_AESNI = HasAESNI();

	CipherSpeedTest::CipherSpeedTest()
		:
		m_progressEvent()
	{
	}

	CipherSpeedTest::~CipherSpeedTest()
	{
	}

	const std::string CipherSpeedTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CipherSpeedTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CipherSpeedTest::Run()
	{
		try
		{
			OnProgress(std::string("### BLOCK CIPHER TESTS ###"));
			OnProgress(std::string("### Tests Rijndael, Serpent and Twofish ciphers"));
			OnProgress(std::string("### Uses pipelined and parallelized Electronic CodeBook Mode (ECB)"));
			OnProgress(std::string("### Each cipher test Encrypts 2GB of data; 100MB chunks * 20 iterations"));
			OnProgress(std::string(""));

			OnProgress(std::string("***RHX/ECB: (Rijndael) Monte Carlo test (K=256; R=14)***"));
			RHXSpeedTest();
			OnProgress(std::string("***SHX/ECB: (Serpent) Monte Carlo test (K=256; R=32)***"));
			SHXSpeedTest();

			OnProgress(std::string("### CIPHER MODE TESTS ###"));
			OnProgress(std::string("### Tests speeds of AES cipher mode implementations"));
			OnProgress(std::string("### Uses the standard rounds and a 256 bit key"));
			OnProgress(std::string(""));

			OnProgress(std::string("***AES-CBC Sequential Encryption***"));
			CBCSpeedTest(true, false);
			OnProgress(std::string("***AES-CBC Parallel Decryption***"));
			CBCSpeedTest(false, true);

			OnProgress(std::string("***AES-CFB Sequential Encryption***"));
			CFBSpeedTest(true, false);
			OnProgress(std::string("***AES-CFB Parallel Decryption***"));
			CFBSpeedTest(false, true);

			OnProgress(std::string("***AES-CTR Sequential Encryption***"));
			CTRSpeedTest(true, false);
			OnProgress(std::string("***AES-CTR Parallel Encryption***"));
			CTRSpeedTest(true, true);

			OnProgress(std::string("***AES-ICM Sequential Encryption***"));
			ICMSpeedTest(true, false);
			OnProgress(std::string("***AES-ICM Parallel Encryption***"));
			ICMSpeedTest(true, true);

			OnProgress(std::string("***AES-OFB Sequential Encryption***"));
			OFBSpeedTest(true, false);

			OnProgress(std::string("### AEAD Authenticated Cipher Modes ###"));
			OnProgress(std::string("### Tests speeds of HBA authenticated mode"));
			OnProgress(std::string("### Uses the standard rounds and a 256 bit key"));
			OnProgress(std::string(""));

			OnProgress(std::string("***AES-HBA Sequential Encryption***"));
			HBASpeedTest(true, false);
			OnProgress(std::string("***AES-HBA Parallel Encryption***"));
			HBASpeedTest(true, true);

			OnProgress(std::string("### STREAM CIPHER TESTS ###"));
			OnProgress(std::string("### Tests speeds of Salsa and ChaCha stream ciphers"));
			OnProgress(std::string("### Uses default of 20 rounds, 256 bit key"));
			OnProgress(std::string(""));

			OnProgress(std::string("***CSX256: Monte Carlo test (K=256; R=20)***"));
			CSX256SpeedTest();
#if defined(CEX_CHACHA512_STRONG)
			OnProgress(std::string("***CSX512: Monte Carlo test (K=512; R=80)***"));
#else
			OnProgress(std::string("***CSX512: Monte Carlo test (K=512; R=40)***"));
#endif
			CSX512SpeedTest();

			OnProgress(std::string("***MCS: Monte Carlo test (K=256; R=22)***"));
			MCSSpeedTest();

			OnProgress(std::string("***RCS: Monte Carlo test (K=256; R=22)***"));
			RCSSpeedTest();

			OnProgress(std::string("***TSX256: Monte Carlo test (K=256; R=72)***"));
			TSX256SpeedTest();
			OnProgress(std::string("***TSX512: Monte Carlo test (K=512; R=96)***"));
			TSX512SpeedTest();
			OnProgress(std::string("***TSX1024: Monte Carlo test (K=1024; R=120)***"));
			TSX1024SpeedTest();

			return MESSAGE;
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

	//*** Block Cipher Tests ***//

	void CipherSpeedTest::RHXSpeedTest(size_t KeySize)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			ECB* cpr = new ECB(eng);
			ParallelBlockLoop(cpr, true, true, MB100, KeySize, 0, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			ECB* cpr = new ECB(eng);
			ParallelBlockLoop(cpr, true, true, MB100, KeySize, 0, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	void CipherSpeedTest::SHXSpeedTest(size_t KeySize)
	{
		SHX* eng = new SHX();
		ECB* cpr = new ECB(eng);
		ParallelBlockLoop(cpr, true, true, MB100, KeySize, 0, 10, m_progressEvent);
		delete cpr;
		delete eng;
	}

	//*** Cipher Mode Tests ***//

	void CipherSpeedTest::CBCSpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			CBC* cpr = new CBC(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			CBC* cpr = new CBC(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	void CipherSpeedTest::CFBSpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			CFB* cpr = new CFB(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			CFB* cpr = new CFB(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	void CipherSpeedTest::CTRSpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			CTR* cpr = new CTR(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			CTR* cpr = new CTR(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	void CipherSpeedTest::ICMSpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			ICM* cpr = new ICM(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			ICM* cpr = new ICM(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	void CipherSpeedTest::OFBSpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			OFB* cpr = new OFB(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			OFB* cpr = new OFB(eng);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	//*** AEAD Mode Tests ***//

	void CipherSpeedTest::HBASpeedTest(bool Encrypt, bool Parallel)
	{
		if (HAS_AESNI)
		{
			AHX* eng = new AHX();
			HBA* cpr = new HBA(eng, StreamAuthenticators::HMACSHA256);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
		else
		{
			RHX* eng = new RHX();
			HBA* cpr = new HBA(eng, StreamAuthenticators::HMACSHA256);
			ParallelBlockLoop(cpr, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
			delete cpr;
			delete eng;
		}
	}

	//*** Stream Cipher Tests ***//

	void CipherSpeedTest::CSX256SpeedTest()
	{
		CSX256* cpr = new CSX256(StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 32, 8, 10, m_progressEvent);
		delete cpr;
	}

	void CipherSpeedTest::CSX512SpeedTest()
	{
		CSX512* cpr = new CSX512(StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 64, 0, 10, m_progressEvent);
		delete cpr;
	}

	void CipherSpeedTest::MCSSpeedTest()
	{
		MCS* cpr = new MCS(Enumeration::BlockCiphers::AES, StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 32, 16, 10, m_progressEvent);
		delete cpr;
	}

	void CipherSpeedTest::RCSSpeedTest()
	{
		if (HAS_AESNI)
		{
			ACS* cpr = new ACS(StreamAuthenticators::None);
			ParallelStreamLoop(cpr, 32, 32, 10, m_progressEvent);
			delete cpr;
		}
		else
		{
			RCS* cpr = new RCS(StreamAuthenticators::None);
			ParallelStreamLoop(cpr, 32, 32, 10, m_progressEvent);
			delete cpr;
		}
	}

	void CipherSpeedTest::TSX256SpeedTest()
	{
		TSX256* cpr = new TSX256(StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 32, 16, 10, m_progressEvent);
		delete cpr;
	}

	void CipherSpeedTest::TSX512SpeedTest()
	{
		TSX512* cpr = new TSX512(StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 64, 16, 10, m_progressEvent);
		delete cpr;
	}

	void CipherSpeedTest::TSX1024SpeedTest()
	{
		TSX1024* cpr = new TSX1024(StreamAuthenticators::None);
		ParallelStreamLoop(cpr, 128, 16, 10, m_progressEvent);
		delete cpr;
	}

	//*** Helpers ***//

	uint64_t CipherSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	bool CipherSpeedTest::HasAESNI()
	{
#if defined(__AVX__)
		CpuDetect dtc;

		return dtc.AVX() && dtc.AESNI();
#else
		return false;
#endif
	}

	void CipherSpeedTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	// Note: internal test, ignore
	void CipherSpeedTest::CounterSpeedTest()
	{
		const size_t LOOPS = 1000 * 1000 * 100;
		size_t itr = 0;
		size_t i = 0;
		uint64_t start = 0;
		std::vector<byte> ctr1(16, 0);
		std::vector<byte> ctr2(16, 0);
		std::vector<uint64_t> ctr3(2, 0);
		std::vector<byte> ctr4(16, 0);
		std::vector<byte> ctr5(16, 0);
		TestUtils::GetRandom(ctr1);
		std::memcpy(&ctr2[0], &ctr1[0], 16);
		std::memcpy(&ctr3[0], &ctr1[0], 16);
		std::memcpy(&ctr4[0], &ctr1[0], 16);
		std::memcpy(&ctr5[0], &ctr1[0], 16);

		// counter 1
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			i = ctr1.size();
			while (--i > 0 && ++ctr1[i] == 0) 
			{
			}

		} while (--itr != 0);

		std::string calc = TestUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(calc);


		// counter 2
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			i = ctr2.size() - 1;
			do
			{
				if (++ctr2[i] != 0)
				{
					break;
				}
				--i;
			} 
			while (i != 0);

		} 
		while (--itr != 0);

		calc = TestUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(calc);


		// counter 3
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			if (++ctr3[0] == 0)
			{
				++ctr3[1];
			}
		} 
		while (--itr != 0);

		calc = TestUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(calc);


		// counter 4
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			i = ctr4.size();
			do
			{
				--i;
				++ctr4[i];

				if (ctr4[i] != 0)
				{
					break;
				}
			} 
			while (i != 0);

		} 
		while (--itr != 0);

		calc = TestUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(calc);


		// counter 5
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			for (size_t j = ctr5.size() - 1, carry = 1; j > 0 && carry; j--)
			{
				carry = !++ctr5[j];
			}
		}
		while (--itr != 0);

		calc = TestUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(calc);
	}
}
