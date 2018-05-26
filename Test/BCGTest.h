#ifndef CEXTEST_CMGTEST_H
#define CEXTEST_CMGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// BCG output comparison test.
	/// <para>Compares drbg output with CTR mode encrypting all zeroes input.</para>
	/// </summary>
	class BCGTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t SAMPLE_SIZE = 1024;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		BCGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~BCGTest();

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
		void CompareOutput();
		void OnProgress(std::string Data);
		bool OrderedRuns(const std::vector<byte> &Input);
	};
}

#endif
