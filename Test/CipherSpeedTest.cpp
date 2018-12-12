#include "CipherSpeedTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntUtils.h"
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
#include "../CEX/OCB.h"
#include "../CEX/ChaCha256.h"
#include "../CEX/ChaCha512.h"
#include "../CEX/Threefish256.h"
#include "../CEX/Threefish512.h"
#include "../CEX/Threefish1024.h"
#include "../CEX/SHA512.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;
	using namespace Cipher::Symmetric::Stream;
	using Utility::IntUtils;

	const std::string CipherSpeedTest::DESCRIPTION = "Cipher Speed Tests.";
	const std::string CipherSpeedTest::FAILURE = "FAILURE! ";
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
			OnProgress(std::string("### Tests speeds of EAX, GCM, and OCB authenticated modes"));
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

			OnProgress(std::string("***AES-OCB Sequential Encryption***"));
			OCBSpeedTest(engine, true, false);
			OnProgress(std::string("***AES-OCB Parallel Encryption***"));
			OCBSpeedTest(engine, true, true);

			if (engine != nullptr)
			{
				delete engine;
			}

			OnProgress(std::string("### STREAM CIPHER TESTS ###"));
			OnProgress(std::string("### Tests speeds of Salsa and ChaCha stream ciphers"));
			OnProgress(std::string("### Uses default of 20 rounds, 256 bit key"));
			OnProgress(std::string(""));
			OnProgress(std::string("***ChaCha256: Monte Carlo test (K=256; R=20)***"));
			ChaCha256SpeedTest();
#if defined(CEX_CHACHA512_STRONG)
			OnProgress(std::string("***ChaCha512: Monte Carlo test (K=512; R=80)***"));
#else
			OnProgress(std::string("***ChaCha512: Monte Carlo test (K=512; R=40)***"));
#endif
			ChaCha512SpeedTest();

			OnProgress(std::string("***Threefish256: Monte Carlo test (K=256; R=72)***"));
			Threefish256SpeedTest();
			OnProgress(std::string("***Threefish512: Monte Carlo test (K=512; R=96)***"));
			Threefish512SpeedTest();
			OnProgress(std::string("***Threefish1024: Monte Carlo test (K=1024; R=120)***"));
			Threefish1024SpeedTest();

			return MESSAGE;
		}
		catch (std::exception const &ex)
		{
			return FAILURE + " : " + ex.what();
		}
		catch (...)
		{
			return FAILURE + " : Unknown Error";
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

	void CipherSpeedTest::OCBSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::OCB* cipher = new Mode::OCB(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 12, 10, m_progressEvent);
		delete cipher;
	}

	//*** Stream Cipher Tests ***//

	void CipherSpeedTest::ChaCha256SpeedTest()
	{
		ChaCha256* cipher = new ChaCha256(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 32, 8, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::ChaCha512SpeedTest()
	{
		ChaCha512* cipher = new ChaCha512(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 64, 0, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish256SpeedTest()
	{
		Threefish256* cipher = new Threefish256(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 32, 0, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish512SpeedTest()
	{
		Threefish512* cipher = new Threefish512(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 64, 0, 10, m_progressEvent);
		delete cipher;
	}

	void CipherSpeedTest::Threefish1024SpeedTest()
	{
		Threefish1024* cipher = new Threefish1024(Enumeration::StreamAuthenticators::None);
		ParallelStreamLoop(cipher, 128, 0, 10, m_progressEvent);
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
			Common::CpuDetect detect;
			m_hasAESNI = detect.AESNI();
			m_hasAVX = detect.AVX();
		}
		catch (...)
		{
			m_hasAESNI = false;
			m_hasAVX = false;
		}
	}

	void CipherSpeedTest::OnProgress(std::string Data)
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
