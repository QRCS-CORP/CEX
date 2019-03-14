#include "CipherSpeedTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#if defined(__AVX__)
#	include "../CEX/AHX.h"
#endif
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/ECB.h"
#include "../CEX/OFB.h"
#include "../CEX/ICM.h"
#include "../CEX/EAX.h"
#include "../CEX/GCM.h"
#include "../CEX/MCS.h"
#include "../CEX/CSX256.h"
#include "../CEX/CSX512.h"
#include "../CEX/TSX256.h"
#include "../CEX/TSX512.h"
#include "../CEX/TSX1024.h"
#include "../CEX/SHA512.h"

namespace Test
{
	using namespace Cipher::Block;
	using namespace Cipher::Stream;
	using Utility::IntegerTools;

	const std::string CipherSpeedTest::CLASSNAME = "CipherSpeedTest";
	const std::string CipherSpeedTest::DESCRIPTION = "Cipher Speed Tests.";
	const std::string CipherSpeedTest::MESSAGE = "COMPLETE! Speed tests have executed succesfully.";

	CipherSpeedTest::CipherSpeedTest()
		:
		m_hasAESNI(false),
		m_hasAVX(false),
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
			Initialize();

			OnProgress(std::string("### BLOCK CIPHER TESTS ###"));
			OnProgress(std::string("### Tests Rijndael, Serpent and Twofish ciphers"));
			OnProgress(std::string("### Uses pipelined and parallelized Electronic CodeBook Mode (ECB)"));
			OnProgress(std::string("### Each cipher test Encrypts 2GB of data; 100MB chunks * 20 iterations"));
			OnProgress(std::string(""));

#if defined(__AVX__)
			if (m_hasAESNI)
			{
				OnProgress(std::string("***AHX/ECB (AES-NI): Monte Carlo test (K=256; R=14)***"));
				AHXSpeedTest();
			}
			else
#endif
			{
				OnProgress(std::string("***RHX/ECB: (Rijndael) Monte Carlo test (K=256; R=14)***"));
				RHXSpeedTest();
			}

			OnProgress(std::string("***SHX/ECB: (Serpent) Monte Carlo test (K=256; R=32)***"));
			SHXSpeedTest();

			OnProgress(std::string("### CIPHER MODE TESTS ###"));
			OnProgress(std::string("### Tests speeds of AES cipher mode implementations"));
			OnProgress(std::string("### Uses the standard rounds and a 256 bit key"));
			OnProgress(std::string(""));

			IBlockCipher* engine;
#if defined(__AVX__)
			if (m_hasAESNI)
			{
				engine = new AHX();
			}
			else
#endif
			{
				engine = new RHX();
			}

			OnProgress(std::string("***AES-CBC Sequential Encryption***"));
			CBCSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-CBC Parallel Decryption***"));
			CBCSpeedTest(engine, false, true);

			OnProgress(std::string("***AES-CFB Sequential Encryption***"));
			CFBSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-CFB Parallel Decryption***"));
			CFBSpeedTest(engine, false, true);

			OnProgress(std::string("***AES-CTR Sequential Encryption***"));
			CTRSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-CTR Parallel Encryption***"));
			CTRSpeedTest(engine, true, true);

			OnProgress(std::string("***AES-ICM Sequential Encryption***"));
			ICMSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-ICM Parallel Encryption***"));
			ICMSpeedTest(engine, true, true);

			OnProgress(std::string("***AES-OFB Sequential Encryption***"));
			OFBSpeedTest(engine, true, false);

			OnProgress(std::string("### AEAD Authenticated Cipher Modes ###"));
			OnProgress(std::string("### Tests speeds of EAX and GCM authenticated modes"));
			OnProgress(std::string("### Uses the standard rounds and a 256 bit key"));
			OnProgress(std::string(""));

			OnProgress(std::string("***AES-EAX Sequential Encryption***"));
			EAXSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-EAX Parallel Encryption***"));
			EAXSpeedTest(engine, true, true);

			OnProgress(std::string("***AES-GCM Sequential Encryption***"));
			GCMSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-GCM Parallel Encryption***"));
			GCMSpeedTest(engine, true, true);

			if (engine != nullptr)
			{
				delete engine;
			}

			OnProgress(std::string("### STREAM CIPHER TESTS ###"));
			OnProgress(std::string("### Tests speeds of Salsa and ChaCha stream ciphers"));
			OnProgress(std::string("### Uses default of 20 rounds, 256 bit key"));
			OnProgress(std::string(""));

			OnProgress(std::string("***MCS: Monte Carlo test (K=256; R=22)***"));
			MCSSpeedTest();

			OnProgress(std::string("***CSX256: Monte Carlo test (K=256; R=20)***"));
			CSX256SpeedTest();
#if defined(CEX_CHACHA512_STRONG)
			OnProgress(std::string("***CSX512: Monte Carlo test (K=512; R=80)***"));
#else
			OnProgress(std::string("***CSX512: Monte Carlo test (K=512; R=40)***"));
#endif
			CSX512SpeedTest();

			OnProgress(std::string("***TSX256: Monte Carlo test (K=256; R=72)***"));
			Threefish256SpeedTest();
			OnProgress(std::string("***TSX512: Monte Carlo test (K=512; R=96)***"));
			Threefish512SpeedTest();
			OnProgress(std::string("***TSX1024: Monte Carlo test (K=1024; R=120)***"));
			Threefish1024SpeedTest();

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

#if defined(__AVX__)
	void CipherSpeedTest::AHXSpeedTest()
	{
		AHX* engine = new AHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, 32, 16, 20, m_progressEvent);
		delete cipher;
		delete engine;
	}
#endif

	void CipherSpeedTest::RHXSpeedTest(size_t KeySize)
	{
		RHX* engine = new RHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, KeySize, 16, 20, m_progressEvent);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::SHXSpeedTest(size_t KeySize)
	{
		SHX* engine = new SHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, KeySize, 16, 20, m_progressEvent);
		delete cipher;
		delete engine;
	}

	//*** Cipher Mode Tests ***//

	void CipherSpeedTest::CBCSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CBC* cipher = new Mode::CBC(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::CFBSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CFB* cipher = new Mode::CFB(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::CTRSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CTR* cipher = new Mode::CTR(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::ICMSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::ICM* cipher = new Mode::ICM(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::OFBSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::OFB* cipher = new Mode::OFB(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	//*** IEAD Mode Tests ***//

	void CipherSpeedTest::EAXSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::EAX* cipher = new Mode::EAX(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::GCMSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::GCM* cipher = new Mode::GCM(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 12, 10, m_progressEvent);
		delete cipher;
	}

	//*** Stream Cipher Tests ***//

	void CipherSpeedTest::MCSSpeedTest()
	{
		MCS* cipher = new MCS(Enumeration::BlockCiphers::RHXS256, Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::CSX256SpeedTest()
	{
		CSX256* cipher = new CSX256(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 32, 8, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::CSX512SpeedTest()
	{
		CSX512* cipher = new CSX512(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 64, 0, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish256SpeedTest()
	{
		TSX256* cipher = new TSX256(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 32, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish512SpeedTest()
	{
		TSX512* cipher = new TSX512(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 64, 16, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish1024SpeedTest()
	{
		TSX1024* cipher = new TSX1024(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 128, 16, 10, m_progressEvent);
		delete cipher;
	}

	//*** Helpers ***//

	uint64_t CipherSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void CipherSpeedTest::Initialize()
	{
		try
		{
			CpuDetect detect;
			m_hasAESNI = detect.AESNI();
			m_hasAVX = detect.AVX();
		}
		catch (const std::exception)
		{
			m_hasAESNI = false;
			m_hasAVX = false;
		}
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
