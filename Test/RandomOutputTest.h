#ifndef CEXTEST_RANDOMOUTPUTTEST_H
#define CEXTEST_RANDOMOUTPUTTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Copies generator output to a file for external testing
	/// </summary>
	class RandomOutputTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const std::string FOLDER;

		// set this to true test the slower cpu jitter provider
		const bool ENABLE_CJPTEST = false;
		// 10MB: the sample file output size
		const size_t SAMPLE_SIZE = 1024 * 1000 * 10;

		std::string m_outputFolder;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CMAC vectors for equality
		/// </summary>
		RandomOutputTest(const std::string &OutputFolder);

		/// <summary>
		/// Destructor
		/// </summary>
		~RandomOutputTest();

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
		std::string Run() override;

	private:

		// entropy providers
		void ACPGenerateFile(std::string FilePath, size_t FileSize);
		void CJPGenerateFile(std::string FilePath, size_t FileSize);
		void CSPGenerateFile(std::string FilePath, size_t FileSize);
		void ECPGenerateFile(std::string FilePath, size_t FileSize);
		void RDPGenerateFile(std::string FilePath, size_t FileSize);
		// drbgs
		void BCGGenerateFile(std::string FilePath, size_t FileSize);
		void CSGGenerateFile(std::string FilePath, size_t FileSize, bool Parallel);
		void HCGGenerateFile(std::string FilePath, size_t FileSize);
		// prngs
		void CSRGenerateFile(std::string FilePath, size_t FileSize);
		void BCRGenerateFile(std::string FilePath, size_t FileSize);
		void HCRGenerateFile(std::string FilePath, size_t FileSize);
		// kdfs
		void SHAKEGenerateFile(std::string FilePath, size_t FileSize);

		void OnProgress(const std::string &Data);
	};
}

#endif
