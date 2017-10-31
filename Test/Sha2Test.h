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
    class SHA2Test : public ITest
    {
    private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_expected512;
		std::vector<std::vector<byte>> m_message;
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
		/// Known answer tests using the NIST SHA-2 KAT vectors
		/// </summary>
		SHA2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~SHA2Test();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareVector(Digest::IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TreeParamsTest();
    };
}

#endif

