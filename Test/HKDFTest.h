#ifndef _CEXTEST_HKDFTEST_H
#define _CEXTEST_HKDFTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Tests the HKDF Drbg implementation using vector comparisons.
    /// <para>Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
	/// <see href="http://tools.ietf.org/html/rfc5869"/></para>
    /// </summary>
    class HKDFTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "HKDF RFC 5869 SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _ikm;
        std::vector<std::vector<byte>> _info;
        std::vector<std::vector<byte>> _output;
        std::vector<std::vector<byte>> _salt;
        
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
		/// Compares known answer HKDF Drbg vectors for equality
		/// </summary>
		HKDFTest()
        {
        }


		/// <summary>
		/// Destructor
		/// </summary>
		~HKDFTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

    private:
		void CompareVector(int Size, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Info, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif
