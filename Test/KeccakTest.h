#ifndef CEXTEST_KECCAKTEST_H
#define CEXTEST_KECCAKTEST_H

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
	class KeccakTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_messages;
		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_expected512;
		std::vector<std::vector<byte>> m_expected1024;
		std::vector<std::vector<byte>> m_macKeys;
		std::vector<std::vector<byte>> m_macData;
		std::vector<std::vector<byte>> m_mac256;
		std::vector<std::vector<byte>> m_mac512;
		std::vector<std::vector<byte>> m_mac1024;
		std::vector<byte> m_truncKey;
		std::vector<byte> m_truncData;
		std::vector<byte> m_trunc256;
		std::vector<byte> m_trunc512;
		std::vector<byte> m_trunc1024;
		std::vector<byte> m_xtremeData;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// A range of Vector KATs; tests SHA-3 256/512 and HMACs
		/// </summary>
		KeccakTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~KeccakTest();

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

		void CompareVector(IDigest* Digest, std::vector<std::vector<byte>> &Expected);
		void CompareDoFinal(IDigest* Digest);
		void CompareHMAC(IDigest* Digest, std::vector<std::vector<byte>> &Expected, std::vector<byte> &TruncExpected);
		void Initialize();
		void OnProgress(std::string Data);
		void TreeParamsTest();
	};
}

#endif
