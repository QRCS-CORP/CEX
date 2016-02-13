#ifndef _CEXTEST_KECCAKTEST_H
#define _CEXTEST_KECCAKTEST_H

#include "ITest.h"
#include "IDigest.h"

namespace Test
{
    /// <summary>
	/// Tests the SHA-3 digest implementation using vector comparisons.
    /// <para> Using vectors from the Bouncy Castle SHA3 digest and HMAC KAT tests:
    /// <see href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/SHA3DigestTest.java"/>
    /// Includes vectors from:
    /// <see href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf"/>
    /// A linking resource:
    /// <see href="http://www.di-mgt.com.au/sha_testvectors.html"/>
    /// NIST Secure Hash Standard documentation: 
    /// <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf"/>
    /// </summary>
    class KeccakTest : public ITest
    {
    private:
		const std::string DESCRIPTION = "Keccak Vector KATs; tests SHA-3 224/256/384/512 and HMACs.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All Keccak tests have executed succesfully.";

        std::vector<std::vector<byte>> _messages;
        std::vector<std::vector<byte>> _expected224;
        std::vector<std::vector<byte>> _expected256;
        std::vector<std::vector<byte>> _expected288;
        std::vector<std::vector<byte>> _expected384;
        std::vector<std::vector<byte>> _expected512;
        std::vector<std::vector<byte>> _macKeys;
        std::vector<std::vector<byte>> _macData;
        std::vector<std::vector<byte>> _mac224;
        std::vector<std::vector<byte>> _mac256;
        std::vector<std::vector<byte>> _mac384;
        std::vector<std::vector<byte>> _mac512;
        std::vector<byte> _truncKey;
        std::vector<byte> _truncData;
        std::vector<byte> _trunc224;
        std::vector<byte> _trunc256;
        std::vector<byte> _trunc384;
        std::vector<byte> _trunc512;
        std::vector<byte> _xtremeData;
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
        /// A range of Vector KATs; tests SHA-3 224/256/384/512 and HMACs
        /// </summary>
		KeccakTest()
        {
        }
        
		/// <summary>
		/// Destructor
		/// </summary>
		~KeccakTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

    private:
		void CompareVector(CEX::Digest::IDigest* Digest, std::vector<std::vector<byte>> &Expected);
		void CompareDoFinal(CEX::Digest::IDigest* Digest);
		void CompareHMAC(CEX::Digest::IDigest* Digest, std::vector<std::vector<byte>> &Expected, std::vector<byte> &TruncExpected);
		void Initialize();
		void OnProgress(char* Data);
    };
}

#endif
