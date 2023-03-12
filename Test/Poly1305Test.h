#ifndef CEXTEST_POLY1305TEST_H
#define CEXTEST_POLY1305TEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// The Poly1305 implementation KAT, stress, and exception handling tests
	/// </summary>
	/// 
	/// <remarks>
	/// <description>References:</description>
	/// <list type="number">
	/// <item><description>RFC 7539: <a href="https://tools.ietf.org/html/rfc7539">ChaChaP20 and Poly1305</a> for IETF Protocols.</description></item>
	/// <item><description>ChaCha20 and Poly1305 for IETF protocols: <a href="https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-10">draft-irtf-cfrg-chacha20-poly1305-10</a>.</description></item>
	/// <item><description>The cryptographic library: <a href="https://github.com/jedisct1/libsodium">LibSodium</a>.</description></item>
	/// <item><description>ChaCha20 and Poly1305 based Cipher Suites for TLS: <a href="https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04">draft-agl-tls-chacha20poly1305-04</a>.</description></item>
	/// </list>
	/// </remarks>
	class Poly1305Test final : public ITest
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
		/// Initialize the GMAC tests
		/// </summary>
		Poly1305Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~Poly1305Test();

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
		/// Compare known answer test vectors to Poly1305 output
		/// </summary>
		/// 
		/// <param name="Generator">The mac generator instance</param>
		/// <param name="Key">The mac key</param>
		/// <param name="Message">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void Kat(IMac* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected);

		/// <summary>
		/// Test the different initialization options
		/// </summary>
		/// 
		/// <param name="Generator">The mac generator instance</param>
		void Params(IMac* Generator);

		/// <summary>
		/// Compare output between access functions Compute and Update/Finalize in a looping [TEST_CYCLES] stress-test
		/// </summary>
		void Stress(IMac* Generator);

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
