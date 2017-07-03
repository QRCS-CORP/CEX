#ifndef _CEXTEST_HMGTEST_H
#define _CEXTEST_HMGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// HCG output comparison test.
	/// <para></para>
	/// </summary>
	class HMGTest : public ITest
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
		HMGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HMGTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CheckInit();
		void CheckMac();
		bool CheckRuns(const std::vector<byte> &Input);
		void OnProgress(std::string Data);
	};
}

#endif
