#ifndef CEXTEST_GMACTEST_H
#define CEXTEST_GMACTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// Test the GMAC implementation with vectores from:
	/// NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The GMAC Mode for Authentication.
	/// </summary>
	class GMACTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 64 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 100;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_message;
		std::vector<std::vector<byte>> m_nonce;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize the GMAC tests
		/// </summary>
		GMACTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~GMACTest();

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
		/// Compare known answer test vectors to mac output
		/// </summary>
		/// 
		/// <param name="Key">The generator key</param>
		/// <param name="Nonce">The generator nonce</param>
		/// <param name="Message">The message array</param>
		/// <param name="Expected">The expected mac code</param>
		void Kat(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Message, std::vector<byte> &Expected);

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
