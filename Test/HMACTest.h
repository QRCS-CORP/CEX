#ifndef _CEXTEST_HMACTEST_H
#define _CEXTEST_HMACTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
    /// HMAC implementation vector comparison tests.
    /// <para>Using vectors from: RFC 4321: Test Vectors for SHA-2 224, 256, 384, and 512 HMACs:
    /// <see href="http://tools.ietf.org/html/rfc4231"/></para>
    /// </summary>
    class HMACTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "RFC 4321 Test Vectors for HMAC SHA224, SHA256, SHA384, and SHA512.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All HMAC tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _expected256;
		std::vector<std::vector<byte>> _expected512;
        std::vector<std::vector<byte>> _keys;
        std::vector<std::vector<byte>> _input;

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
		/// Compares known answer SHA-2 HMAC vectors for equality
		/// </summary>
		HMACTest()
        {

        }

		/// <summary>
		/// Destructor
		/// </summary>
		~HMACTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareAccess(std::vector<byte> &Key);
		void CompareVector256(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected);
		void CompareVector512(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif

