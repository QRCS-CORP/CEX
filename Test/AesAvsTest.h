#ifndef _CEXTEST_AESAVSTEST_H
#define _CEXTEST_AESAVSTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
    /// Tests the Rijndael implementation using the NIST AESAVS vectors.
    /// <para>Using vector sets from: AESAVS certification package: <see href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf"/></para>
    /// </summary>
    class AesAvsTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
		const std::string FAILURE = "FAILURE: ";
		const std::string SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";

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
		/// NIST AESAVS known answer vector tests
		/// </summary>
		AesAvsTest() {}

		/// <summary>
		/// Destructor
		/// </summary>
		~AesAvsTest() {}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void OnProgress(char* Data);
    };
}

#endif
