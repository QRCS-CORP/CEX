#ifndef CEXTEST_HKDFTEST_H
#define CEXTEST_HKDFTEST_H

#include "ITest.h"

namespace Test
{
    /// <summary>
	/// Tests the HKDF implementation using vector comparisons.
    /// <para>Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
	/// <see href="http://tools.ietf.org/html/rfc5869"/></para>
    /// </summary>
    class HKDFTest final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<std::vector<byte>> m_key;
        std::vector<std::vector<byte>> m_info;
        std::vector<std::vector<byte>> m_output;
		TestEventHandler m_progressEvent;
        std::vector<std::vector<byte>> m_salt;
        
    public:

		/// <summary>
		/// Compares known answer HKDF Drbg vectors for equality
		/// </summary>
		HKDFTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HKDFTest();

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

		void CompareVector(int Size, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Info, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TestInit();
    };
}

#endif
