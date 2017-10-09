#ifndef _CEXTEST_SERPENTTEST_H
#define _CEXTEST_SERPENTTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
    /// Serpent implementation vector comparison tests.
    /// <para>Using official vector sets from Nessie: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/"/>
    /// The full Nessie verified vector tests, including 100 and 1000 round Monte Carlo Tests:
    /// 128 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors"/>
    /// 192 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors"/>
    /// 256 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors"/></para>
    /// </summary>
    class SerpentTest : public ITest
    {
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

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
		/// Compares known answer Serpent vectors for equality (NESSIE)
		/// </summary>
		SerpentTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SerpentTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, size_t Count = 100);
		void CompareOutput();
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void OnProgress(std::string Data);
    };
}

#endif

