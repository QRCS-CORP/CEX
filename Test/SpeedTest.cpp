#include "SpeedTest.h"
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
			OnProgress("***RHX: Monte Carlo test (K=256; R=14)***");
			RDXSpeedTest();
			OnProgress("***RHX: Monte Carlo test (K=1920; R=22)***");
			RHXSpeedTest();
			OnProgress("***SHX: Monte Carlo test (K=256; R=32)***");
			SPXSpeedTest();
			OnProgress("***SHX: Monte Carlo test (K=1920; R=40)***");
			SHXSpeedTest();
			OnProgress("***THX: Monte Carlo test (K=256; R=16)***");
			TFXSpeedTest();
			OnProgress("***THX: Monte Carlo test (K=1920; R=20)***");
			THXSpeedTest();
			OnProgress("***Salsa20: Monte Carlo test (K=256; R=20)***");
			SalsaSpeedTest();

			OnProgress("### CBC and CFB Parallel Decryption Speed Tests: 10 loops * 100MB ###");
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			OnProgress("***RHX: CBC Decryption test (K=256; R=14)***");

			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::CBC(eng), MB100, true, 32, 16);
			OnProgress("***RHX: CFB Decryption test (K=256; R=14)***");
			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::CFB(eng), MB100, true, 32, 16);

			OnProgress("### RHX Standard Mode Speed Tests: 1 loop * 100MB ###");
			OnProgress("***RHX: CTR Encrypt test (K=256; R=14)***");
			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::CTR(eng), MB100, false, 32, 16, 1);
			OnProgress("***RHX: CBC Encrypt test (K=256; R=14)***");
			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::CBC(eng), MB100, false, 32, 16, 1);
			OnProgress("***RHX: CFB Encrypt test (K=256; R=14)***");
			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::CFB(eng), MB100, false, 32, 16, 1);
			OnProgress("***RHX: OFB Encrypt test (K=256; R=14)***");
			CipherModeLoop(&CEX::Cipher::Symmetric::Block::Mode::OFB(eng), MB100, false, 32, 16, 1);

			delete eng;

			return MESSAGE;
		}
		catch (std::string ex)
		{
			return FAILURE + " : " + ex;
		}
		catch (...)
		{
			return FAILURE + " : Internal Error";
		}
	}

	void SpeedTest::CipherModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, unsigned int SampleSize, bool Parallel, int KeySize, int IvSize, int Loops)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		std::vector<byte> buffer1(16, 0);
		std::vector<byte> buffer2(16, 0);
		const char *name = Cipher->Engine()->Name();
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
			Cipher->ParallelBlockSize() = MB10;
			buffer1.resize(Cipher->ParallelBlockSize());
			buffer2.resize(Cipher->ParallelBlockSize());
		}

		uint64_t start = TestUtils::GetTimeMs64();
		uint32_t rounds = Cipher->Engine()->Rounds();

		for (unsigned int i = 0; i < LOOPS; ++i)
		{
			unsigned int counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			std::string resp = name + std::string(" Loop: ") + calc + "s";
			OnProgress(const_cast<char*>(resp.c_str()));
		}

		uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
		std::string calc = GetRate(start, dlen);
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + CEX::Utility::IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	std::string SpeedTest::GetRate(uint64_t StartTime, uint64_t DataSize)
	{
		uint64_t duration = (TestUtils::GetTimeMs64() - StartTime) / 1000;
		double dsze = (double)DataSize;
		double rate = dsze / ((double)duration / 60.0);

		return CEX::Utility::IntUtils::ToString(rate);
	}

	void SpeedTest::Initialize()
	{
		for (unsigned int i = 0; i < _key256.size(); i++)
			_key256[i] = i;
		for (unsigned int i = 15; i > 0; i--)
			_iv[i] = i;
	}

	void SpeedTest::ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, unsigned int SampleSize, unsigned int KeySize, unsigned int IvSize)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(true, keyParams);
		Cipher->ParallelBlockSize() = MB10;
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();
		const char *name = Cipher->Engine()->Name();
		uint32_t rounds = Cipher->Engine()->Rounds();

		for (unsigned int i = 0; i < LOOPS; ++i)
		{
			unsigned int counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			std::string resp = name + std::string(" Loop: ") + calc + "s";
			OnProgress(const_cast<char*>(resp.c_str()));
		}

		uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
		std::string calc = GetRate(start, dlen);
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + CEX::Utility::IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void SpeedTest::ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher *Cipher, int KeySize, int IvSize)
	{
		CEX::Common::KeyParams keyParams;
		TestUtils::GetRandomKey(keyParams, KeySize, IvSize);
		Cipher->Initialize(keyParams);
		Cipher->ParallelBlockSize() = MB10;
		Cipher->IsParallel() = true;
		std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
		std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
		uint64_t start = TestUtils::GetTimeMs64();
		const char *name = Cipher->Name();
		uint64_t rounds = Cipher->Rounds();

		for (unsigned int i = 0; i < LOOPS; ++i)
		{
			unsigned int counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < DATA_SIZE)
			{
				Cipher->Transform(buffer1, buffer2);
				counter += buffer1.size();
			}
			std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			std::string resp = name + std::string(" Loop: ") + calc + "s";
			OnProgress(const_cast<char*>(resp.c_str()));
		}

		uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
		std::string calc = GetRate(start, dlen);
		std::string klen = CEX::Utility::IntUtils::ToString(KeySize * 8);
		std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + CEX::Utility::IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void SpeedTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}

	void SpeedTest::RDXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::RHX cipher;
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 32);
	}

	void SpeedTest::RHXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512 sha512;
		CEX::Cipher::Symmetric::Block::RHX cipher(&sha512, Rounds);
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 192);
	}

	void SpeedTest::SalsaSpeedTest()
	{
		CEX::Cipher::Symmetric::Stream::Salsa20 cipher;
		ParallelStreamLoop(&cipher, 32, 8);
	}

	void SpeedTest::SHXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512 sha512;
		CEX::Cipher::Symmetric::Block::SHX cipher(&sha512, Rounds);
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 192);
	}

	void SpeedTest::SPXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::SHX cipher;
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 32);
	}

	void SpeedTest::THXSpeedTest(int Rounds)
	{
		CEX::Digest::SHA512 sha512;
		CEX::Cipher::Symmetric::Block::THX cipher(&sha512, Rounds);
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 192);
	}

	void SpeedTest::TFXSpeedTest()
	{
		CEX::Cipher::Symmetric::Block::THX cipher;
		CEX::Cipher::Symmetric::Block::Mode::CTR cipherMode(&cipher);
		ParallelBlockLoop(&cipherMode, MB100, 32);
	}
}