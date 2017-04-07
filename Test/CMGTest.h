#ifndef _CEXTEST_DRBGTEST_H
#define _CEXTEST_DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// CMG output comparison test.
	/// <para>Compares drbg output with CTR mode encrypting all zeroes input.</para>
	/// </summary>
	class CMGTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CMG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All CMG tests have executed succesfully.";
		const size_t SAMPLE_SIZE = 1024;

		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		CMGTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~CMGTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CheckInit();
		bool CheckRuns(const std::vector<byte> &Input);
		void CompareOutput();
		void OnProgress(std::string Data);
	};
}

#endif
