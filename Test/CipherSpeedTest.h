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
		std::vector<byte> m_key256;
		std::vector<byte> m_key1536;
		std::vector<byte> m_iv;

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
			m_iv(16, 0),
			m_key256(32, 0),
			m_key1536(192, 0)
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void Initialize();
		void ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, size_t KeySize, size_t IvSize = 16, size_t Loops = DEFITER);
		void ParallelModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, size_t SampleSize, bool Parallel = false, size_t KeySize = 32, size_t IvSize = 16, size_t Loops = DEFITER);
		void ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, size_t KeySize, size_t IvSize = 16, size_t Loops = DEFITER);
		void OnProgress(char* Data);
		void AHXSpeedTest();
		void ChaChaSpeedTest();
		void RHXSpeedTest(size_t KeySize = 32);
		void SalsaSpeedTest();
		void SHXSpeedTest(size_t KeySize = 32);
		void THXSpeedTest(size_t KeySize = 32);
	};
}

#endif