#ifndef CEXTEST_AESFIPSTEST_H
#define CEXTEST_AESFIPSTEST_H

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
    class AesFipsTest final : public ITest
    {
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<std::vector<byte>> m_cipherText;
        std::vector<std::vector<byte>> m_keys;
        std::vector<std::vector<byte>> m_plainText;
		TestEventHandler m_progressEvent;
		bool m_testNI;

    public:

		/// <summary>
		/// Compares known answer Rijndael vectors for equality (FIPS 197)
		/// </summary>
		explicit AesFipsTest(bool TestNI = false);

		/// <summary>
		/// Destructor
		/// </summary>
		~AesFipsTest();

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

		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
#if defined(__AVX__)
		void CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
		void CompareMonteCarloNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
#endif
		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
