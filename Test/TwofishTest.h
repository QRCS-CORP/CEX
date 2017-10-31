#ifndef CEXTEST_TWOFISHTEST_H
#define CEXTEST_TWOFISHTEST_H

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
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<byte> m_plainText;
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
		/// Compares known answer TwoFish vectors for equality
		/// </summary>
		TwofishTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~TwofishTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

    private:
		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, bool Encrypt = true, size_t Count = 10000);
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
