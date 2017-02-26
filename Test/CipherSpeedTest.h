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
		const std::string DESCRIPTION = "Cipher Speed Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string MESSAGE = "COMPLETE! Speed tests have executed succesfully.";
		static constexpr uint64_t KB1 = 1000;
		static constexpr uint64_t MB1 = KB1 * 1000;
		static constexpr uint64_t MB10 = MB1 * 10;
		static constexpr uint64_t MB100 = MB1 * 100;
		static constexpr uint64_t GB1 = MB1 * 1000;
		static constexpr uint64_t DATA_SIZE = MB100;
		static constexpr uint64_t DEFITER = 10;

		TestEventHandler m_progressEvent;
		bool m_hasAESNI;
		bool m_hasSSE;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		CipherSpeedTest()
			:
			m_hasAESNI(false),
			m_hasSSE(false)
		{
		}

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
				std::string calc = IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				Handler(const_cast<char*>(calc.c_str()));
			}

			uint64_t dur = TestUtils::GetTimeMs64() - start;
			uint64_t len = Loops * SampleSize;
			uint64_t rate = GetBytesPerSecond(dur, len);
			std::string glen = IntUtils::ToString(len / GB1);
			std::string mbps = IntUtils::ToString((rate / MB1));
			std::string secs = IntUtils::ToString((double)dur / 1000.0);
			std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(const_cast<char*>(resp.c_str()));
			Handler("");
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
					Cipher->Transform(buffer1, 0, buffer2, 0);
					counter += buffer1.size();
				}
				std::string calc = IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				Handler(const_cast<char*>(calc.c_str()));
			}

			uint64_t dur = TestUtils::GetTimeMs64() - start;
			uint64_t len = Loops * DATA_SIZE;
			uint64_t rate = GetBytesPerSecond(dur, len);
			std::string mbps = IntUtils::ToString((rate / MB1));
			std::string secs = IntUtils::ToString((double)dur / 1000.0);
			std::string resp = std::string("1GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(const_cast<char*>(resp.c_str()));
			Handler("");
		}


		void AHXSpeedTest();
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
		void OnProgress(char* Data);
		void RHXSpeedTest(size_t KeySize = 32);
		void SalsaSpeedTest();
		void SHXSpeedTest(size_t KeySize = 32);
		void THXSpeedTest(size_t KeySize = 32);
		void WideModeLoop(Cipher::Symmetric::Block::IBlockCipher* Engine, size_t SampleSize, bool Parallel = false, size_t KeySize = 32, size_t IvSize = 128, size_t Loops = DEFITER);
	};
}

#endif