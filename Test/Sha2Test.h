#ifndef _CEXTEST_SHA2TEST_H
#define _CEXTEST_SHA2TEST_H

#include "ITest.h"
#include "IDigest.h"

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
		const std::string DESCRIPTION = "Tests SHA-2 256/512 with NIST KAT vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SHA-2 tests have executed succesfully.";

		std::vector<std::vector<byte>> _expected256;
		std::vector<std::vector<byte>> _expected512;
		std::vector<std::vector<byte>> _message;
		TestEventHandler _progressEvent;

    public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Known answer tests using the NIST SHA-2 KAT vectors
		/// </summary>
		SHA2Test()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~SHA2Test()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareVector(CEX::Digest::IDigest *Digest, std::vector<byte> Input, std::vector<byte> Expected);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif

