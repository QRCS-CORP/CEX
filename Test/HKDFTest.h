#ifndef CEXTEST_HKDFTEST_H
#define CEXTEST_HKDFTEST_H

#include "ITest.h"
#include "../CEX/IKDF.h"

namespace Test
{
	using Kdf::IKdf;

    /// <summary>
	/// Tests the HKDF implementation using exception handling, parameter checks, stress and KAT tests.
    /// <para>Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF) 
	/// <see href="http://tools.ietf.org/html/rfc5869"/></para>
    /// </summary>
    class HKDFTest final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 32 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 100;

		std::vector<std::vector<byte>> m_expected;
        std::vector<std::vector<byte>> m_key;
        std::vector<std::vector<byte>> m_info;
		TestEventHandler m_progressEvent;
        std::vector<std::vector<byte>> m_salt;
        
    public:

		/// <summary>
		/// Compares known answer HKDF vectors for equality
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

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to kdf output
		/// </summary>
		/// 
		/// <param name="Generator">The kdf generator instance</param>
		/// <param name="Salt">The salt array</param>
		/// <param name="Key">The input key</param>
		/// <param name="Info">The info array</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IKdf* Generator, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Info, std::vector<byte> &Expected);

		/// <summary>
		/// Test the different initialization options
		/// </summary>
		/// 
		/// <param name="Generator">The kdf generator instance</param>
		void Params(IKdf* Generator);

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Generator">The kdf generator instance</param>
		void Stress(IKdf* Generator);

    private:

		void Initialize();
		void OnProgress(std::string Data);

    };
}

#endif
