#ifndef _CEXTEST_KECCAKTEST_H
#define _CEXTEST_KECCAKTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using CEX::Digest::IDigest;

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

		std::vector<std::vector<byte>> m_messages;
		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_expected512;
		std::vector<std::vector<byte>> m_macKeys;
		std::vector<std::vector<byte>> m_macData;
		std::vector<std::vector<byte>> m_mac256;
		std::vector<std::vector<byte>> m_mac512;
		std::vector<byte> m_truncKey;
		std::vector<byte> m_truncData;
		std::vector<byte> m_trunc256;
		std::vector<byte> m_trunc512;
		std::vector<byte> m_xtremeData;
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
		/// A range of Vector KATs; tests SHA-3 256/512 and HMACs
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
		void CompareVector(IDigest* Digest, std::vector<std::vector<byte>> &Expected);
		void CompareDoFinal(IDigest* Digest);
		void CompareHMAC(IDigest* Digest, std::vector<std::vector<byte>> &Expected, std::vector<byte> &TruncExpected);
		void Initialize();
		void OnProgress(char* Data);
		void TreeParamsTest();
	};
}

#endif
