#ifndef CEXTEST_DCGTEST_H
#define CEXTEST_DCGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// DCG output comparison test.
	/// <para></para>
	/// </summary>
	class DCGTest final : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t SAMPLE_SIZE = 1024;

		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_seed256;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		DCGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~DCGTest();

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

		void CheckInit();
		void OnProgress(std::string Data);
		bool OrderedRuns(const std::vector<byte> &Input);
	};
}

#endif
