#ifndef _CEXTEST_CIPHERMODETEST_H
#define _CEXTEST_CIPHERMODETEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Cipher Mode implementations vector comparison test sets.
    /// <para>Using vectors from :NIST Special Publication 800-38A:
    /// <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf"/></para>
    /// </summary>
    class CipherModeTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "NIST SP800-38A KATs testing CBC, CFB, CTR, ECB, and OFB modes.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Cipher Mode tests have executed succesfully.";

		TestEventHandler _progressEvent;
        std::vector<std::vector<byte>> _keys;
        std::vector<std::vector<byte>> _vectors;
        std::vector<std::vector<std::vector<byte>>> _input;
        std::vector<std::vector<std::vector<byte>>> _output;

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
		/// Compares known answer Cipher Mode vectors for equality (NIST 800-38A)
		/// </summary>
		CipherModeTest()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherModeTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareCBC(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareCFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareCTR(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareECB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void CompareOFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif
