#ifndef CEXTEST_KDF2DRBGTEST_H
#define CEXTEST_KDF2DRBGTEST_H

#include "ITest.h"
#include "../CEX/IKDF.h"

namespace Test
{
	using Kdf::IKdf;

	/// <summary>
	/// Tests the KDF2 implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para>Using the official Kats from RFC 6070: <see href="https://tools.ietf.org/html/rfc6070"/>.</para>
	/// </summary>
	class KDF2Test final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 31 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 100;

		std::vector<std::vector<uint8_t>> m_expected;
		std::vector<std::vector<uint8_t>> m_key;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer KDF2 Drbg vectors for equality
		/// </summary>
		KDF2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~KDF2Test();

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
		/// <param name="Key">The input key</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IKdf* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Expected);
		
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
		void OnProgress(const std::string &Data);
	};
}

#endif
