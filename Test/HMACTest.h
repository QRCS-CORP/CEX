#ifndef CEXTEST_HMACTEST_H
#define CEXTEST_HMACTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

    /// <summary>
    /// HMAC implementation vector comparison tests.
    /// <para>Using vectors from: RFC 4321: Test Vectors for SHA-2 224, 256, 384, and 512 HMACs:
    /// <see href="http://tools.ietf.org/html/rfc4231"/></para>
    /// </summary>
    class HMACTest final : public ITest
    {
    private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 64 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 100;

        std::vector<std::vector<uint8_t>> m_expected;
        std::vector<std::vector<uint8_t>> m_key;
        std::vector<std::vector<uint8_t>> m_message;
		TestEventHandler m_progressEvent;

    public:

		/// <summary>
		/// Compares known answer SHA-2 HMAC vectors for equality
		/// </summary>
		HMACTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HMACTest();

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
		/// Tests the compact forms of the HMAC functions
		/// </summary>
		void Ancillary();

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to mac output
		/// </summary>
		/// 
		/// <param name="Generator">The mac generator instance</param>
		/// <param name="Message">The message array</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IMac* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected);

		/// <summary>
		/// Test the different initialization options
		/// </summary>
		/// 
		/// <param name="Generator">The mac generator instance</param>
		void Params(IMac* Generator);

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Generator">The mac generator instance</param>
		void Stress(IMac* Generator);

    private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif

