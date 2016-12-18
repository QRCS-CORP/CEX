#ifndef _CEXTEST_CIPHERSPEEDTEST_H
#define _CEXTEST_CIPHERSPEEDTEST_H

#include "ITest.h"
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
		void AHXSpeedTest();
		void CBCSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void CFBSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void CTRSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void ChaChaSpeedTest();
		void CounterSpeedTest();
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void ICMSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void Initialize();
		void OFBSpeedTest(Cipher::Symmetric::Block::IBlockCipher* Engine, bool Encrypt, bool Parallel);
		void ParallelBlockLoop(Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, bool Encrypt, bool Parallel, size_t SampleSize, size_t KeySize, size_t IvSize = 16, size_t Loops = DEFITER);
		void ParallelStreamLoop(Cipher::Symmetric::Stream::IStreamCipher* Cipher, size_t KeySize, size_t IvSize = 16, size_t Loops = DEFITER);
		void OnProgress(char* Data);
		void RHXSpeedTest(size_t KeySize = 32);
		void SalsaSpeedTest();
		void SHXSpeedTest(size_t KeySize = 32);
		void THXSpeedTest(size_t KeySize = 32);
		void WideModeLoop(Cipher::Symmetric::Block::IBlockCipher* Engine, size_t SampleSize, bool Parallel = false, size_t KeySize = 32, size_t IvSize = 128, size_t Loops = DEFITER);
	};
}

#endif