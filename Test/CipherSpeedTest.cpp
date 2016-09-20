#include "CipherSpeedTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/THX.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/ECB.h"
#include "../CEX/OFB.h"
#include "../CEX/ICM.h"
#include "../CEX/SHA512.h"
#include "../CEX/ChaCha.h"
#include "../CEX/Salsa20.h"


namespace Test
{
	using namespace CEX::Cipher::Symmetric::Block;
	using namespace CEX::Cipher::Symmetric::Stream;

	std::string CipherSpeedTest::Run()
	{
		try
		{
			Initialize();

			OnProgress("### BLOCK CIPHER TESTS ###");
			OnProgress("### Tests Rijndael, Serpent and Twofish ciphers");
			OnProgress("### Uses pipelined and parallelized Electronic CodeBook Mode (ECB)");
			OnProgress("### Each cipher test Encrypts 2GB of data; 100MB chunks * 20 iterations");
			OnProgress("");

			if (m_hasAESNI)
			{
				OnProgress("***AHX/ECB (AES-NI): Monte Carlo test (K=256; R=14)***");
				AHXSpeedTest();
			}
			else
			{
				OnProgress("***RHX/ECB: (Rijndael) Monte Carlo test (K=256; R=14)***");
				RHXSpeedTest();
			}

			OnProgress("***SHX/ECB: (Serpent) Monte Carlo test (K=256; R=32)***");
			SHXSpeedTest();

			OnProgress("***THX/ECB: (Twofish) Monte Carlo test (K=256; R=16)***");
			THXSpeedTest();


			OnProgress("### CIPHER MODE TESTS ###");
			OnProgress("### Tests speeds of AES cipher mode implementations");
			OnProgress("### Uses the standard rounds and a 256 bit key");
			OnProgress("");

			IBlockCipher* engine;
			if (m_hasAESNI)
				engine = new AHX();
			else
				engine = new RHX();
			
			OnProgress("***AES-CBC Sequential Encryption***");
			CBCSpeedTest(engine, true, false);
			OnProgress("***AES-CBC Parallel Decryption***");
			CBCSpeedTest(engine, false, true);

			OnProgress("***AES-CFB Sequential Encryption***");
			CFBSpeedTest(engine, true, false);
			OnProgress("***AES-CFB Parallel Decryption***");
			CFBSpeedTest(engine, false, true);

			OnProgress("***AES-CTR Sequential Encryption***");
			CTRSpeedTest(engine, true, false);
			OnProgress("***AES-CTR Parallel Encryption***");
			CTRSpeedTest(engine, true, true);

			OnProgress("***AES-ICM Sequential Encryption***");
			ICMSpeedTest(engine, true, false);
			OnProgress("***AES-ICM Parallel Encryption***");
			ICMSpeedTest(engine, true, true);

			OnProgress("***AES-OFB Sequential Encryption***");
			OFBSpeedTest(engine, true, false);
			delete engine;


			OnProgress("### STREAM CIPHER TESTS ###");
			OnProgress("### Tests speeds of Salsa and ChaCha stream ciphers");
			OnProgress("### Uses default of 20 rounds, 256 bit key");
			OnProgress("");

			OnProgress("***Salsa20: Monte Carlo test (K=256; R=20)***");
			SalsaSpeedTest();
			OnProgress("***ChaCha: Monte Carlo test (K=256; R=20)***");
			ChaChaSpeedTest();

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

	//*** Block Cipher Tests ***//

	void CipherSpeedTest::AHXSpeedTest()
	{
		AHX* engine = new AHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, 32, 16, 20);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::RHXSpeedTest(size_t KeySize)
	{
		RHX* engine = new RHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, KeySize, 16, 20);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::SHXSpeedTest(size_t KeySize)
	{
		SHX* engine = new SHX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, KeySize, 16, 20);
		delete cipher;
		delete engine;
	}

	void CipherSpeedTest::THXSpeedTest(size_t KeySize)
	{
		THX* engine = new THX();
		Mode::ECB* cipher = new Mode::ECB(engine);
		ParallelBlockLoop(cipher, true, true, MB100, KeySize, 16, 20);
		delete cipher;
		delete engine;
	}

	//*** Cipher Mode Tests ***//

	void CipherSpeedTest::CBCSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CBC* cipher = new Mode::CBC(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10);
		delete cipher;
	}

	void CipherSpeedTest::CFBSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CFB* cipher = new Mode::CFB(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10);
		delete cipher;
	}

	void CipherSpeedTest::CTRSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::CTR* cipher = new Mode::CTR(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10);
		delete cipher;
	}

	void CipherSpeedTest::ICMSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::ICM* cipher = new Mode::ICM(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10);
		delete cipher;
	}

	void CipherSpeedTest::OFBSpeedTest(IBlockCipher* Engine, bool Encrypt, bool Parallel)
	{
		Mode::OFB* cipher = new Mode::OFB(Engine);
		ParallelBlockLoop(cipher, Encrypt, Parallel, MB100, 32, 16, 10);
		delete cipher;
	}

	//*** Stream Cipher Tests ***//

	void CipherSpeedTest::ChaChaSpeedTest()
	{
		ChaCha* cipher = new ChaCha();
		ParallelStreamLoop(cipher, 32, 8, 10);
		delete cipher;
	}

	void CipherSpeedTest::SalsaSpeedTest()
	{
		Salsa20* cipher = new Salsa20();
		ParallelStreamLoop(cipher, 32, 8, 10);
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
			CEX::Common::CpuDetect detect;
			m_hasAESNI = detect.HasAES();
			m_hasSSE = detect.HasMinIntrinsics();
		}
		catch (...)
		{
			m_hasAESNI = false;
			m_hasSSE = false;
		}
	}

	void CipherSpeedTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void CipherSpeedTest::ParallelBlockLoop(Mode::ICipherMode* Cipher, bool Encrypt, bool Parallel, size_t SampleSize, size_t KeySize, size_t IvSize, size_t Loops)
	{
		CEX::Common::KeyParams keyParams;
		size_t blkSze = Parallel ? Cipher->ParallelBlockSize() : Cipher->BlockSize();
		std::vector<byte> buffer1(blkSze, 0);
		std::vector<byte> buffer2(blkSze, 0);

		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(Encrypt, keyParams);
		Cipher->IsParallel() = Parallel;
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				Cipher->Transform(buffer1, 0, buffer2, 0);
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

	void CipherSpeedTest::ParallelStreamLoop(IStreamCipher* Cipher, size_t KeySize, size_t IvSize, size_t Loops)
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
				Cipher->Transform(buffer1, 0, buffer2, 0);
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

	void CipherSpeedTest::WideModeLoop(IBlockCipher* Engine, size_t SampleSize, bool Parallel, size_t KeySize, size_t IvSize, size_t Loops)
	{
		std::vector<byte> buffer1(IvSize, 0);
		std::vector<byte> buffer2(IvSize, 0);
		SampleSize -= (SampleSize % IvSize);
		Mode::CBC cipher(Engine);
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);

		if (!Parallel)
		{
			cipher.Initialize(true, keyParams);
			cipher.IsParallel() = false;
		}
		else
		{
			cipher.Initialize(false, keyParams);
			cipher.IsParallel() = true;
			buffer1.resize(cipher.ParallelBlockSize());
			buffer2.resize(cipher.ParallelBlockSize());
		}

		uint64_t start = TestUtils::GetTimeMs64();

		if (IvSize == 128)
		{
			for (size_t i = 0; i < Loops; ++i)
			{
				size_t counter = 0;
				uint64_t lstart = TestUtils::GetTimeMs64();

				while (counter < SampleSize)
				{
					cipher.Transform128(buffer1, 0, buffer2, 0);
					counter += buffer1.size();
				}
				std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				OnProgress(const_cast<char*>(calc.c_str()));
			}
		}
		else
		{
			for (size_t i = 0; i < Loops; ++i)
			{
				size_t counter = 0;
				uint64_t lstart = TestUtils::GetTimeMs64();

				while (counter < SampleSize)
				{
					cipher.Transform64(buffer1, 0, buffer2, 0);
					counter += buffer1.size();
				}
				std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				OnProgress(const_cast<char*>(calc.c_str()));
			}
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
		memcpy(&ctr2[0], &ctr1[0], 16);
		memcpy(&ctr3[0], &ctr1[0], 16);
		memcpy(&ctr4[0], &ctr1[0], 16);
		memcpy(&ctr5[0], &ctr1[0], 16);

		// counter 1
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			i = ctr1.size();
			while (--i >= 0 && ++ctr1[i] == 0) {}

		} while (--itr != 0);

		std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(const_cast<char*>(calc.c_str()));


		// counter 2
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			i = ctr2.size() - 1;
			do
			{
				if (++ctr2[i] != 0)
					break;
				--i;
			} while (i != 0);

		} while (--itr != 0);

		calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(const_cast<char*>(calc.c_str()));


		// counter 3
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			if (++ctr3[0] == 0)
				++ctr3[1];

		} while (--itr != 0);

		calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(const_cast<char*>(calc.c_str()));


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
					break;
			} while (i != 0);

		} while (--itr != 0);

		calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(const_cast<char*>(calc.c_str()));


		// counter 5
		itr = LOOPS;
		start = TestUtils::GetTimeMs64();

		do
		{
			for (size_t j = ctr5.size() - 1, carry = 1; j >= 0 && carry; j--)
				carry = !++ctr5[j];

		} while (--itr != 0);

		calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - start) / 1000.0);
		OnProgress(const_cast<char*>(calc.c_str()));
	}

}