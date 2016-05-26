#ifndef _CEXTEST_SpeedTest_H
#define _CEXTEST_SpeedTest_H

#include "ITest.h"
#include "ICipherMode.h"
#include "IStreamCipher.h"

namespace Test
{
	/// <summary>
	/// Cipher Speed Tests
	/// </summary>
	class SpeedTest : public ITest
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

		SpeedTest()
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
		void ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, unsigned int SampleSize, unsigned int KeySize, unsigned int IvSize = 16, unsigned int Loops = DEFITER);
		void ParallelModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, unsigned int SampleSize, bool Parallel = false, int KeySize = 32, int IvSize = 16, unsigned int Loops = DEFITER);
		void ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, int KeySize, int IvSize = 16, unsigned int Loops = DEFITER);
		void OnProgress(char* Data);
		void AHXSpeedTest();
		void RDXSpeedTest();
		void RHXSpeedTest(int Rounds = 22);
		void SalsaSpeedTest();
		void SHXSpeedTest(int Rounds = 40);
		void SPXSpeedTest();
		void THXSpeedTest(int Rounds = 20);
		void TFXSpeedTest();
	};
}

#endif