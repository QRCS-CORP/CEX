#include "CipherSpeedTest.h"
#include "../CEX/Cpu.h"
#if defined (AESNI_AVAILABLE)
#include "../CEX/AHX.h"
#endif
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/THX.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/OFB.h"
#include "../CEX/SHA512.h"
#include "../CEX/ChaCha.h"
#include "../CEX/Salsa20.h"

namespace Test
{
	std::string CipherSpeedTest::Run()
	{
		using namespace CEX::Cipher::Symmetric::Block::Mode;

		try
		{
			Initialize();

#if defined (AESNI_AVAILABLE)
			OnProgress("***AHX/CTR (AES-NI): Monte Carlo test (K=256; R=14)***");
			AHXSpeedTest();
#else
			OnProgress("***RHX/CTR: (Rijndael) Monte Carlo test (K=256; R=14)***");
			RHXSpeedTest();
#endif

			OnProgress("***SHX/CTR: (Serpent) Monte Carlo test (K=256; R=32)***");
			SHXSpeedTest();
			OnProgress("***THX/CTR: (Twofish) Monte Carlo test (K=256; R=16)***");
			THXSpeedTest();
			OnProgress("***Salsa20: Monte Carlo test (K=256; R=20)***");
			SalsaSpeedTest();
			OnProgress("***ChaCha: Monte Carlo test (K=256; R=20)***");
			ChaChaSpeedTest();

#if defined (AESNI_AVAILABLE)
			OnProgress("### CBC and CFB Parallel Decryption Speed Tests: 10 loops * 100MB ###");
			OnProgress("***AHX: CBC Decryption test (K=256; R=14)***");
			CEX::Cipher::Symmetric::Block::IBlockCipher* engine = new CEX::Cipher::Symmetric::Block::AHX();
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, true, 32, 16, 10);
			OnProgress("***AHX: CFB Decryption test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, true, 32, 16, 10);

			OnProgress("### AHX Sequential Mode Speed Tests: 10 loops * 100MB ###");
			OnProgress("***AHX: CTR Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CTR(engine), MB100, false, 32, 16, 10);
			OnProgress("***AHX: CBC Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, false, 32, 16, 10);
			OnProgress("***AHX: CFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, false, 32, 16, 10);
			OnProgress("***AHX: OFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::OFB(engine), MB100, false, 32, 16, 10);
#else
			OnProgress("### CBC and CFB Parallel Decryption Speed Tests: 10 loops * 100MB ###");
			OnProgress("***RHX: CBC Decryption test (K=256; R=14)***");
			CEX::Cipher::Symmetric::Block::IBlockCipher* engine =  new CEX::Cipher::Symmetric::Block::RHX();
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, true, 32, 16, 10);
			OnProgress("***RHX: CFB Decryption test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, true, 32, 16, 10);

			OnProgress("### RHX Sequential Mode Speed Tests: 10 loops * 100MB ###");
			OnProgress("***RHX: CTR Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CTR(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: CBC Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: CFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: OFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::OFB(engine), MB100, false, 32, 16, 10);
#endif
			delete engine;

			return MESSAGE;
		}
		catch (std::string &ex)
		{
			return FAILURE + " : " + ex;
		}
		catch (...)
		{
			return FAILURE + " : Internal Error";
		}
	}

	uint64_t CipherSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void CipherSpeedTest::Initialize()
	{
		for (unsigned int i = 0; i < m_key256.size(); i++)
			m_key256[i] = (byte)i;
		for (unsigned int i = 15; i > 0; i--)
			m_iv[i] = (byte)i;
	}

	void CipherSpeedTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void CipherSpeedTest::ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(true, keyParams);
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(const_cast<char*>(calc.c_str()));
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string glen = CEX::Utility::IntUtils::ToString(len / GB1);
		std::string mbps = CEX::Utility::IntUtils::ToString((rate / MB1));
		std::string secs = CEX::Utility::IntUtils::ToString((double)dur / 1000.0);
		std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void CipherSpeedTest::ParallelModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, bool Parallel, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		std::vector<byte> buffer1(16, 0);
		std::vector<byte> buffer2(16, 0);
		SampleSize -= (SampleSize % 16);

		if (!Parallel)
		{
			Cipher->Initialize(true, keyParams);
			Cipher->IsParallel() = false;
		}
		else
		{
			Cipher->Initialize(false, keyParams);
			Cipher->IsParallel() = true;
			buffer1.resize(Cipher->ParallelBlockSize());
			buffer2.resize(Cipher->ParallelBlockSize());
		}

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(const_cast<char*>(calc.c_str()));
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string mbps = CEX::Utility::IntUtils::ToString(rate / MB1);
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string secs = CEX::Utility::IntUtils::ToString((double)dur / 1000.0);
		std::string resp = std::string("1GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");

		delete Cipher;
	}

	void CipherSpeedTest::ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(keyParams);
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < DATA_SIZE)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(const_cast<char*>(calc.c_str()));
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * DATA_SIZE;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string mbps = CEX::Utility::IntUtils::ToString((rate / MB1));
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string secs = CEX::Utility::IntUtils::ToString((double)dur / 1000.0);
		std::string resp = std::string("1GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void CipherSpeedTest::AHXSpeedTest()
	{
#if defined (AESNI_AVAILABLE)
		// note: requires large data to reach best speed due to 
		// os management of thread queues, overclock, hyperthreading etc.
		// best results are obtained when looping test to +100GB.
		// on an hp all-in-one i7-6700T/12GB-1600 -> k:256, r:14, l:1GB, t:0.117, avg: 8547 MB per second!

		//for (int i = 0; i < 100; ++i)
		//{
			CEX::Cipher::Symmetric::Block::AHX* engine = new CEX::Cipher::Symmetric::Block::AHX();//r14
			CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
			// default is 64k * cpu count, w/ ni, keep within l2 cache size, but large enough to offset parallel loop setup cost
			cipher->ParallelBlockSize() = cipher->ProcessorCount() * 32000;
			ParallelBlockLoop(cipher, MB100, 32);
			delete cipher;
			delete engine;
		//}
#endif
	}

	void CipherSpeedTest::ChaChaSpeedTest()
	{
		CEX::Cipher::Symmetric::Stream::ChaCha* cipher = new CEX::Cipher::Symmetric::Stream::ChaCha();
		ParallelStreamLoop(cipher, 32, 8);
		delete cipher;
	}

	void CipherSpeedTest::RHXSpeedTest(size_t KeySize)
	{
		CEX::Cipher::Symmetric::Block::RHX* engine = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, KeySize);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::SalsaSpeedTest()
	{
		CEX::Cipher::Symmetric::Stream::Salsa20* cipher = new CEX::Cipher::Symmetric::Stream::Salsa20();
		ParallelStreamLoop(cipher, 32, 8);
		delete cipher;
	}

	void CipherSpeedTest::SHXSpeedTest(size_t KeySize)
	{
		CEX::Cipher::Symmetric::Block::SHX* engine = new CEX::Cipher::Symmetric::Block::SHX();
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, KeySize);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::THXSpeedTest(size_t KeySize)
	{
		CEX::Cipher::Symmetric::Block::THX* engine = new CEX::Cipher::Symmetric::Block::THX();
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, KeySize);
		delete cipher;
		delete engine;
	}
}