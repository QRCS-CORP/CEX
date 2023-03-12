#ifndef CEXTEST_CIPHERSPEEDTEST_H
#define CEXTEST_CIPHERSPEEDTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Cipher Speed Tests
	/// </summary>
	class CipherSpeedTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
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
		static const bool HAS_AESNI;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		CipherSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherSpeedTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run() override;

	private:

		template<typename T>
		static void ParallelBlockLoop(T* Cipher, bool Encrypt, bool Parallel, size_t SampleSize, size_t KeySize, size_t IvSize, size_t Loops, TestEventHandler &Handler)
		{
			const size_t BLKLEN = Parallel ? Cipher->ParallelBlockSize() : 16;
			const size_t ALNLEN = SampleSize - (SampleSize % BLKLEN);
			std::vector<uint8_t> buffer1(BLKLEN, 0x00);
			std::vector<uint8_t> buffer2(BLKLEN, 0x00);
			std::string glen;
			std::string mbps;
			std::string resp;
			std::string secs;
			uint64_t dur;
			uint64_t len;
			uint64_t lstart;
			uint64_t rate;
			uint64_t start;
			size_t i;
			size_t lctr;

			Cipher::SymmetricKey* keyParam = TestUtils::GetRandomKey(KeySize, IvSize);
			Cipher->Initialize(Encrypt, *keyParam);
			Cipher->ParallelProfile().IsParallel() = Parallel;
			start = TestUtils::GetTimeMs64();

			for (i = 0; i < Loops; ++i)
			{
				lctr = 0;
				lstart = TestUtils::GetTimeMs64();

				while (lctr < ALNLEN)
				{
					Cipher->Transform(buffer1, 0, buffer2, 0, buffer1.size());
					lctr += buffer1.size();
				}
			}

			dur = TestUtils::GetTimeMs64() - start;
			len = static_cast<uint64_t>(Loops) * SampleSize;
			rate = GetBytesPerSecond(dur, len);
			glen = TestUtils::ToString(len / GB1);
			mbps = TestUtils::ToString((rate / MB1));
			secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
			resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(resp);
			Handler(std::string(""));
			delete keyParam;
		}

		template<typename T>
		void ParallelStreamLoop(T* Cipher, size_t KeySize, size_t IvSize, size_t Loops, TestEventHandler &Handler)
		{
			const size_t ALNLEN = DATA_SIZE - (DATA_SIZE % Cipher->ParallelBlockSize());
			std::vector<uint8_t> buffer1(Cipher->ParallelBlockSize(), 0x00);
			std::vector<uint8_t> buffer2(Cipher->ParallelBlockSize(), 0x00);
			std::string mbps;
			std::string resp;
			std::string secs;
			uint64_t dur;
			uint64_t len;
			uint64_t lstart;
			uint64_t rate;
			uint64_t start;
			size_t counter;
			size_t i;

			Cipher::SymmetricKey* keyParam = TestUtils::GetRandomKey(KeySize, IvSize);
			Cipher->Initialize(true, *keyParam);
			Cipher->ParallelProfile().IsParallel() = true;
			start = TestUtils::GetTimeMs64();

			for (i = 0; i < Loops; ++i)
			{
				counter = 0;
				lstart = TestUtils::GetTimeMs64();

				while (counter < ALNLEN)
				{
					Cipher->Transform(buffer1, 0, buffer2, 0, buffer1.size());
					counter += buffer1.size();
				}
			}

			dur = TestUtils::GetTimeMs64() - start;
			len = Loops * DATA_SIZE;
			rate = GetBytesPerSecond(dur, len);
			mbps = TestUtils::ToString((rate / MB1));
			secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
			resp = std::string("1GB in " + secs + " seconds, avg. " + mbps + " MB per Second");
			Handler(const_cast<char*>(resp.c_str()));
			Handler("");
			delete keyParam;
		}

		void CBCSpeedTest(bool Encrypt, bool Parallel);
		void CFBSpeedTest(bool Encrypt, bool Parallel);
		void CTRSpeedTest(bool Encrypt, bool Parallel);
		void CSX256SpeedTest();
		void CSX512SpeedTest();
		void RCSSpeedTest();
		void TSX256SpeedTest();
		void TSX512SpeedTest();
		void TSX1024SpeedTest();
		void CounterSpeedTest();
		void HBASpeedTest(bool Encrypt, bool Parallel);
		static uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void ICMSpeedTest(bool Encrypt, bool Parallel);
		void OFBSpeedTest(bool Encrypt, bool Parallel);
		void OnProgress(const std::string &Data);
		void RHXSpeedTest(size_t KeySize = 32);
		void SHXSpeedTest(size_t KeySize = 32);
	};
}

#endif
