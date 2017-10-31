#ifndef CEXTEST_SALSATEST_H
#define CEXTEST_SALSATEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Salsa20 implementation vector comparison tests.
    /// <para>Using the BouncyCastle vectors:
    /// <see href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-ext-jdk15on/1.51/org/bouncycastle/crypto/test/SalsaTest.java"/></para>
    /// </summary>
    class SalsaTest : public ITest
    {
    private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_cipherText;
		std::vector<std::vector<byte>> m_iv;
		std::vector<std::vector<byte>> m_key;
		std::vector<byte> m_plainText;
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
		/// Compares known answer Salsa20 vectors for equality
		/// </summary>
		SalsaTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SalsaTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();
        
    private:
		void CompareParallel();
		void CompareVector(int Rounds, std::vector<byte> &Key, std::vector<byte> &Vector, std::vector<byte> &Input, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
