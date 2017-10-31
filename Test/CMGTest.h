#ifndef CEXTEST_DRBGTEST_H
#define CEXTEST_DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// BCG output comparison test.
	/// <para>Compares drbg output with CTR mode encrypting all zeroes input.</para>
	/// </summary>
	class CMGTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t SAMPLE_SIZE = 1024;

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
		CMGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CMGTest();

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
