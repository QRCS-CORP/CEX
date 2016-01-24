#ifndef _CEXTEST_SpeedTest_H
#define _CEXTEST_SpeedTest_H

#include "ITest.h"
#include "KeyParams.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"
#include "CTR.h"
#include "SHA512.h"
#include "Salsa20.h"
#include "ICipherMode.h"
#include "IStreamCipher.h"

namespace Test
{
	using CEX::Cipher::Symmetric::Block::Mode::ICipherMode;
	using CEX::Cipher::Symmetric::Stream::IStreamCipher;
	using CEX::Common::KeyParams;
	using CEX::Cipher::Symmetric::Block::Mode::CTR; 
	using CEX::Digest::SHA512;
	using CEX::Cipher::Symmetric::Block::RHX;
	using CEX::Cipher::Symmetric::Block::SHX; 
	using CEX::Cipher::Symmetric::Block::THX;
	using CEX::Cipher::Symmetric::Stream::Salsa20;

	/// <summary>
	/// Cipher Speed Tests
	/// </summary>
	class SpeedTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Cipher Speed Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string MESSAGE = "COMPLETE! HX tests have executed succesfully.";
		const unsigned int MB1 = 1000000;
		const unsigned int MB10 = 10000000;
		const unsigned int MB100 = 100000000;
		const unsigned int GB1 = 1000000000;
		const unsigned int DATA_SIZE = MB100;
		const unsigned int LOOPS = 10;

		TestEventHandler _progressEvent;
		std::vector<byte> _key256;
		std::vector<byte> _key1536;
		std::vector<byte> _iv;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		SpeedTest()
			:
			_iv(16, 0),
			_key256(32, 0),
			_key1536(192, 0)
		{
			for (unsigned int i = 0; i < _key256.size(); i++)
				_key256[i] = i;
			for (unsigned int i = 15; i > 0; i--)
				_iv[i] = i;
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
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
				RHX* eng = new RHX();
				OnProgress("***RHX: CBC Decryption test (K=256; R=14)***");

				CipherModeLoop(&CBC(eng), MB100, true, 32, 16);
				OnProgress("***RHX: CFB Decryption test (K=256; R=14)***");
				CipherModeLoop(&CFB(eng), MB100, true, 32, 16);

				OnProgress("### RHX Standard Mode Speed Tests: 1 loop * 100MB ###");
				OnProgress("***RHX: CTR Encrypt test (K=256; R=14)***");
				CipherModeLoop(&CTR(eng), MB100, false, 32, 16, 1);
				OnProgress("***RHX: CBC Encrypt test (K=256; R=14)***");
				CipherModeLoop(&CBC(eng), MB100, false, 32, 16, 1);
				OnProgress("***RHX: CFB Encrypt test (K=256; R=14)***");
				CipherModeLoop(&CFB(eng), MB100, false, 32, 16, 1);
				OnProgress("***RHX: OFB Encrypt test (K=256; R=14)***");
				CipherModeLoop(&OFB(eng), MB100, false, 32, 16, 1);

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

	private:
		std::string GetRate(uint64_t StartTime, uint64_t DataSize)
		{
			uint64_t duration = (TestUtils::GetTimeMs64() - StartTime) / 1000;
			double dsze = (double)DataSize;
			double rate = dsze / ((double)duration / 60.0);

			return IntUtils::ToString(rate);
		}

		void ParallelBlockLoop(ICipherMode *Cipher, unsigned int SampleSize, unsigned int KeySize, unsigned int IvSize = 16)
		{
			KeyParams keyParams;
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
				std::string calc = IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				std::string resp = name + std::string(" Loop: ") + calc + "s";
				OnProgress(const_cast<char*>(resp.c_str()));
			}

			uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
			std::string calc = GetRate(start, dlen);
			std::string klen = IntUtils::ToString(KeySize * 8);
			std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
			OnProgress(const_cast<char*>(resp.c_str()));
			OnProgress("");
		}

		void ParallelStreamLoop(IStreamCipher *Cipher, int KeySize, int IvSize = 16)
		{
			KeyParams keyParams;
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
				std::string calc = IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				std::string resp = name + std::string(" Loop: ") + calc + "s";
				OnProgress(const_cast<char*>(resp.c_str()));
			}

			uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
			std::string calc = GetRate(start, dlen);
			std::string klen = IntUtils::ToString(KeySize * 8);
			std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
			OnProgress(const_cast<char*>(resp.c_str()));
			OnProgress("");
		}

		void CipherModeLoop(ICipherMode* Cipher, unsigned int SampleSize, bool Parallel = false, int KeySize = 32, int IvSize = 16, int Loops = 10)
		{
			KeyParams keyParams;
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
				std::string calc = IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				std::string resp = name + std::string(" Loop: ") + calc + "s";
				OnProgress(const_cast<char*>(resp.c_str()));
			}

			uint64_t dlen = (LOOPS * DATA_SIZE) / GB1;
			std::string calc = GetRate(start, dlen);
			std::string klen = IntUtils::ToString(KeySize * 8);
			std::string resp = name + std::string(" (key=") + klen + std::string("-bit, rounds=") + IntUtils::ToString(rounds) + ") -> " + calc + " gb/minute]";
			OnProgress(const_cast<char*>(resp.c_str()));
			OnProgress("");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}

		void RDXSpeedTest()
		{
			RHX cipher;
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 32);
		}

		void RHXSpeedTest(int Rounds = 22)
		{
			SHA512 sha512;
			RHX cipher(&sha512, Rounds);
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 192);
		}

		void SalsaSpeedTest()
		{
			Salsa20 cipher;
			ParallelStreamLoop(&cipher, 32, 8);
		}

		void SHXSpeedTest(int Rounds = 40)
		{
			SHA512 sha512;
			SHX cipher(&sha512, Rounds);
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 192);
		}

		void SPXSpeedTest()
		{
			SHX cipher;
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 32);
		}

		void THXSpeedTest(int Rounds = 20)
		{
			SHA512 sha512;
			THX cipher(&sha512, Rounds);
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 192);
		}

		void TFXSpeedTest()
		{
			THX cipher;
			CTR cipherMode(&cipher);
			ParallelBlockLoop(&cipherMode, MB100, 32);
		}
	};
}

#endif