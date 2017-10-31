#ifndef CEXTEST_DCGTEST_H
#define CEXTEST_DCGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// DCG output comparison test.
	/// <para></para>
	/// </summary>
	class DCGTest : public ITest
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
		DCGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~DCGTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CheckInit();
		bool CheckRuns(const std::vector<byte> &Input);
		void OnProgress(std::string Data);
	};
}

#endif
