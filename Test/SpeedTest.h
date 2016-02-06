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

		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CipherModeLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, unsigned int SampleSize, bool Parallel = false, int KeySize = 32, int IvSize = 16, int Loops = 10);
		std::string GetRate(uint64_t StartTime, uint64_t DataSize);
		void Initialize();
		void ParallelBlockLoop(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, unsigned int SampleSize, unsigned int KeySize, unsigned int IvSize = 16);
		void ParallelStreamLoop(CEX::Cipher::Symmetric::Stream::IStreamCipher *Cipher, int KeySize, int IvSize = 16);
		void OnProgress(char* Data);
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