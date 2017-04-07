#ifndef _CEXTEST_SALSATEST_H
#define _CEXTEST_SALSATEST_H

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
		const std::string DESCRIPTION = "Salsa20 Known Answer Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Salsa20 tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_cipherText;
		std::vector<std::vector<byte>> m_iv;
		std::vector<std::vector<byte>> m_key;
		std::vector<byte> m_plainText;

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
		SalsaTest()
        {
        }

		/// <summary>
		/// Destructor
		/// </summary>
		~SalsaTest()
		{
		}

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
