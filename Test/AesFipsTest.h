#ifndef _CEXTEST_AESFIPSTEST_H
#define _CEXTEST_AESFIPSTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Rijndael implementation vector comparison tests.
    /// <para>Test vectors from the NIST standard tests contained in the AES specification document FIPS 197:
    /// <see href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"/> and the 
    /// Monte Carlo AES tests from the Brian Gladman's vector set:
    /// <see href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"/></para>
    /// </summary>
    class AesFipsTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "NIST AES specification FIPS 197 Known Answer Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! AES tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _keys;
        std::vector<std::vector<byte>> _plainText;
        std::vector<std::vector<byte>> _cipherText;
        
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
		/// Compares known answer Rijndael vectors for equality (FIPS 197)
		/// </summary>
		AesFipsTest()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~AesFipsTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif
