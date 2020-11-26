#ifndef CEXTEST_KPATEST_H
#define CEXTEST_KPATEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// KPA implementation vector comparison tests
	///
	/// </summary>
	class KPATest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 64 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 100;

		std::vector<byte> m_custom;
		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_message;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer SHA-2 KMAC vectors for equality
		/// </summary>
		KPATest();

		/// <summary>
		/// Destructor
		/// </summary>
		~KPATest();

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
		/// <param name="Generator">The mac generator instance</param>
		/// <param name="Key">The input generator key</param>
		/// <param name="Custom">The customization array</param>
		/// <param name="Message">The message array</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Custom, std::vector<byte> &Message, std::vector<byte> &Expected);

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

