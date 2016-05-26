#ifndef _CEXTEST_TWOFISHTEST_H
#define _CEXTEST_TWOFISHTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// TwoFish implementation vector comparison tests.
    /// <para>Using the complete official TwoFish vectors: 
	/// <see href="https://www.schneier.com/twofish.html"/></para>
    /// </summary>
    class TwofishTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "Official Twofish Known Answer Tests (over 60,000 rounds).";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All Twofish tests have executed succesfully.";

		TestEventHandler m_progressEvent;
        std::vector<byte> m_plainText;
        
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
		/// Compares known answer TwoFish vectors for equality
		/// </summary>
		TwofishTest()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~TwofishTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

    private:
		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, bool Encrypt = true, unsigned int Count = 10000);
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif
