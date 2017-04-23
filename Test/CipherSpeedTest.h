#ifndef _CEXTEST_CIPHERSPEEDTEST_H
#define _CEXTEST_CIPHERSPEEDTEST_H

#include "ITest.h"
#include "../CEX/IAeadMode.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
	/// <summary>
	/// Cipher Speed Tests
	/// </summary>
	class CipherSpeedTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string MESSAGE;
		static const uint64_t KB1 = 1000;
		static const uint64_t MB1 = KB1 * 1000;
		static const uint64_t MB10 = MB1 * 10;
		static const uint64_t MB100 = MB1 * 100;
		static const uint64_t GB1 = MB1 * 1000;
		static const uint64_t DATA_SIZE = MB100;
		static const uint64_t DEF_ITERATIONS = 10;
		static const uint64_t DEF_IVSIZE = 16;
		static const uint64_t DEF_KEYSIZE = 32;

		bool m_hasAESNI;
		bool m_hasAVX;
		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Initialize this class
		/// </summary>
		CipherSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherSpeedTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		template<typename T>
		static void ParallelBlockLoop(T* Cipher, bool Encrypt, bool Parallel, size_t SampleSize, size_t KeySize, size_t IvSize, size_t Loops, TestEventHandler &Handler)
		{
			size_t blkSze = Parallel ? Cipher->ParallelBlockSize() : Cipher->BlockSize();
			std::vector<byte> buffer1(blkSze, 0);
			std::vector<byte> buffer2(blkSze, 0);

			Key::Symmetric::SymmetricKey keyParam = TestUtils::GetRandomKey(KeySize, IvSize);
			Cipher->Initialize(Encrypt, keyParam);
			Cipher->ParallelProfile().IsParallel() = Parallel;
			uint64_t start = TestUtils::GetTimeMs64();

			for (size_t i = 0; i < Loops; ++i)
			{
				size_t counter = 0;
				uint64_t lstart = TestUtils::GetTimeMs64();

				while (counter < SampleSize)
				{
					Cipher->Transform(buffer1, 0, buffer2, 0, buffer1.size());
					counter += buffer1.size();
				}
				std::string calc = TestUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				Handler(calc);
			}

			uint64_t dur = TestUtils::GetTimeMs64() - start;
			uint64_t len = Loops * SampleSize;
			uint64_t rate = GetBytesPerSecond(dur, len);
			std::string glen = TestUtils::ToString(len / GB1);
			std::string mbps = TestUtils::ToString((rate / MB1));
			std::string secs = TestUtils::ToString((double)dur / 1000.0);
			std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(resp);
			Handler(std::string(""));
		}

		template<typename T>
		void ParallelStreamLoop(T* Cipher, size_t KeySize, size_t IvSize, size_t Loops, TestEventHandler &Handler)
		{
			Key::Symmetric::SymmetricKey keyParam = TestUtils::GetRandomKey(KeySize, IvSize);
			Cipher->Initialize(keyParam);
			Cipher->ParallelProfile().IsParallel() = true;
			std::vector<byte> buffer1(Cipher->ParallelBlockSize(), 0);
			std::vector<byte> buffer2(Cipher->ParallelBlockSize(), 0);
			uint64_t start = TestUtils::GetTimeMs64();

			for (size_t i = 0; i < Loops; ++i)
			{
				size_t counter = 0;
				uint64_t lstart = TestUtils::GetTimeMs64();

				while (counter < DATA_SIZE)
				{
					Cipher->Transform(buffer1, 0, buffer2, 0, buffer1.size());
					counter += buffer1.size();
				}
				std::string calc = TestUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				Handler(const_cast<char*>(calc.c_str()));
			}

			uint64_t dur = TestUtils::GetTimeMs64() - start;
			uint64_t len = Loops * DATA_SIZE;
			uint64_t rate = GetBytesPerSecond(dur, len);
			std::string mbps = TestUtils::ToString((rate / MB1));
			std::string secs = TestUtils::ToString((double)dur / 1000.0);
			std::string resp = std::string("1GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(const_cast<char*>(resp.c_str()));
			Handler("");
		}

#if defined(__AVX__)
		void AHXSpeedTest();
#endif
		void CBCSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void CFBSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void CTRSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void ChaChaSpeedTest();
		void CounterSpeedTest();
		void EAXSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void GCMSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		static uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void ICMSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void Initialize();
		void OCBSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void OFBSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void OnProgress(std::string Data);
		void RHXSpeedTest(size_t KeySize = 32);
		void SalsaSpeedTest();
		void SHXSpeedTest(size_t KeySize = 32);
		void THXSpeedTest(size_t KeySize = 32);
	};
}

#endif