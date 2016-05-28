#include "SpeedTest.h"
#include "Cpu.h"
#if defined (AESNI_AVAILABLE)
#include "AHX.h"
#endif
#include "RHX.h"
#include "SHX.h"
#include "THX.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "OFB.h"
#include "SHA512.h"
#include "Salsa20.h"

namespace Test
{
	std::string SpeedTest::Run()
	{
		using namespace CEX::Cipher::Symmetric::Block::Mode;

		try
		{
			Initialize();

			OnProgress("### Parallel CTR Mode Speed Tests: 10 loops * 100MB ###");
#if defined (AESNI_AVAILABLE)
			OnProgress("***AES-NI (AHX): Monte Carlo test (K=256; R=14)***");
			AHXSpeedTest();
#endif
			OnProgress("***RHX: Monte Carlo test (K=256; R=14)***");
			RDXSpeedTest();
			OnProgress("***RHX: Monte Carlo test (K=512; R=22)***");
			RHXSpeedTest();
			OnProgress("***SHX: Monte Carlo test (K=256; R=32)***");
			SPXSpeedTest();
			OnProgress("***SHX: Monte Carlo test (K=512; R=40)***");
			SHXSpeedTest();
			OnProgress("***THX: Monte Carlo test (K=256; R=16)***");
			TFXSpeedTest();
			OnProgress("***THX: Monte Carlo test (K=512; R=20)***");
			THXSpeedTest();
			OnProgress("***Salsa20: Monte Carlo test (K=256; R=20)***");
			SalsaSpeedTest();

			OnProgress("### CBC and CFB Parallel Decryption Speed Tests: 10 loops * 100MB ###");
			CEX::Cipher::Symmetric::Block::IBlockCipher* engine =  new CEX::Cipher::Symmetric::Block::RHX();
			OnProgress("***RHX: CBC Decryption test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, true, 32, 16);
			OnProgress("***RHX: CFB Decryption test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, true, 32, 16);

			OnProgress("### RHX Standard Mode Speed Tests: 10 loops * 100MB ###");
			OnProgress("***RHX: CTR Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CTR(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: CBC Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CBC(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: CFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::CFB(engine), MB100, false, 32, 16, 10);
			OnProgress("***RHX: OFB Encrypt test (K=256; R=14)***");
			ParallelModeLoop(new CEX::Cipher::Symmetric::Block::Mode::OFB(engine), MB100, false, 32, 16, 10);
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

	uint64_t SpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void SpeedTest::Initialize()
	{
		for (unsigned int i = 0; i < m_key256.size(); i++)
			m_key256[i] = (byte)i;
		for (unsigned int i = 15; i > 0; i--)
			m_iv[i] = (byte)i;
	}

	void SpeedTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void SpeedTest::ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(true, keyParams);
		//Cipher->ParallelBlockSize() = Cipher->ProcessorCount() * 32000;
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();
		const char* name = Cipher->Engine()->Name();
		size_t rounds = Cipher->Engine()->Rounds();

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
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string secs = CEX::Utility::IntUtils::ToString((double)dur / 1000.0);
		std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void SpeedTest::ParallelModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, bool Parallel, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		std::vector<byte> buffer1(16, 0);
		std::vector<byte> buffer2(16, 0);
		const char* name = Cipher->Engine()->Name();
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
			//Cipher->ParallelBlockSize() = MB10;
			buffer1.resize(Cipher->ParallelBlockSize());
			buffer2.resize(Cipher->ParallelBlockSize());
		}

		uint64_t start = TestUtils::GetTimeMs64();
		size_t rounds = Cipher->Engine()->Rounds();

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

	void SpeedTest::ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(keyParams);
		//Cipher->ParallelBlockSize() = MB1;
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();
		const char *name = Cipher->Name();
		uint64_t rounds = Cipher->Rounds();

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

	void SpeedTest::AHXSpeedTest()
	{
#if defined (AESNI_AVAILABLE)
		// note: requires large data to reach best speed due to 
		// os management of thread queues, overclock, hyperthreading etc.
		// best results are obtained when looping test to +100GB.
		// on an hp all-in-one i7-6700T/12GB-1600 -> h:4926, l:1690, avg: 4634 MB per second!

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

	void SpeedTest::RDXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::RHX* engine = new CEX::Cipher::Symmetric::Block::RHX(16, 14);//b16, r14
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 32);
		delete cipher;
		delete engine;
	}

	void SpeedTest::RHXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512* sha512 = new CEX::Digest::SHA512();
		CEX::Cipher::Symmetric::Block::RHX* engine = new CEX::Cipher::Symmetric::Block::RHX(sha512, Rounds);//b16, r22
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 64);
		delete cipher;
		delete sha512;
		delete engine;
	}

	void SpeedTest::SalsaSpeedTest()
	{
		CEX::Cipher::Symmetric::Stream::Salsa20* cipher = new CEX::Cipher::Symmetric::Stream::Salsa20();
		ParallelStreamLoop(cipher, 32, 8);
		delete cipher;
	}

	void SpeedTest::SHXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512* sha512 = new CEX::Digest::SHA512();
		CEX::Cipher::Symmetric::Block::SHX* engine = new CEX::Cipher::Symmetric::Block::SHX(sha512, Rounds);
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 64);
		delete cipher;
		delete sha512;
		delete engine;
	}

	void SpeedTest::SPXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::SHX* engine = new CEX::Cipher::Symmetric::Block::SHX();
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 32);
		delete cipher;
		delete engine;
	}

	void SpeedTest::THXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512* sha512 = new CEX::Digest::SHA512();
		CEX::Cipher::Symmetric::Block::THX* engine = new CEX::Cipher::Symmetric::Block::THX(sha512, Rounds);
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 64);
		delete cipher;
		delete sha512;
		delete engine;
	}

	void SpeedTest::TFXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::THX* engine = new CEX::Cipher::Symmetric::Block::THX();
		CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
		ParallelBlockLoop(cipher, MB100, 32);
		delete cipher;
		delete engine;
	}
}