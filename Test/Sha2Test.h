#ifndef CEXTEST_SHA2TEST_H
#define CEXTEST_SHA2TEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
    /// <summary>
    /// Tests the SHA-2 digest implementation using vector comparisons.
	/// <para>Using vectors from NIST SHA2 Documentation:
    /// <para><see href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf"/></para>
    /// </summary>
    class SHA2Test final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_exp256;
		std::vector<std::vector<byte>> m_exp512;
		std::vector<std::vector<byte>> m_message;
		TestEventHandler m_progressEvent;

    public:

		/// <summary>
		/// Known answer tests using the NIST SHA-2 KAT vectors
		/// </summary>
		SHA2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~SHA2Test();

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

		void CompareVector(Digest::IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TreeParamsTest();
    };
}

#endif

