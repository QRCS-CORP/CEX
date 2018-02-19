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

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CMAC vectors for equality
		/// </summary>
		RandomOutputTest();

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

		void CMGGenerateFile(std::string FilePath, size_t FileSize);
		void DCGGenerateFile(std::string FilePath, size_t FileSize);
		void HMGGenerateFile(std::string FilePath, size_t FileSize);
		void CJPGenerateFile(std::string FilePath, size_t FileSize);
		void CSPGenerateFile(std::string FilePath, size_t FileSize);
		void ECPGenerateFile(std::string FilePath, size_t FileSize);
		void RDPGenerateFile(std::string FilePath, size_t FileSize);
		void OnProgress(std::string Data);
	};
}

#endif
