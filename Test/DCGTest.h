#ifndef _CEXTEST_DCGTEST_H
#define _CEXTEST_DCGTEST_H

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
		const std::string DESCRIPTION = "DCG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All DCG tests have executed succesfully.";
		const size_t SAMPLE_SIZE = 1024;

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
		DCGTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~DCGTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CheckInit();
		bool CheckRuns(const std::vector<byte> &Input);
		void CompareOutput(std::vector<byte> &Seed, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif
