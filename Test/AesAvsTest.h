#ifndef CEXTEST_AESAVSTEST_H
#define CEXTEST_AESAVSTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
    /// Tests the Rijndael implementation using the NIST AESAVS vectors.
    /// <para>Using vector sets from: AESAVS certification package: <see href="http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf"/></para>
    /// </summary>
    class AesAvsTest final : public ITest
    {
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;
		bool m_testNI;

    public:

		/// <summary>
		/// NIST AESAVS known answer vector tests
		/// </summary>
		explicit AesAvsTest(bool TestNI = false);

		/// <summary>
		/// Destructor
		/// </summary>
		~AesAvsTest();

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
#if defined(__AVX__)
		void CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output);
#endif
		void OnProgress(std::string Data);
    };
}

#endif
