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
    class TwofishTest final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<byte> m_plainText;
		TestEventHandler m_progressEvent;
        
    public:

		/// <summary>
		/// Compares known answer TwoFish vectors for equality
		/// </summary>
		TwofishTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~TwofishTest();

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

		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, bool Encrypt = true, size_t Count = 10000);
		void CompareOutput(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
