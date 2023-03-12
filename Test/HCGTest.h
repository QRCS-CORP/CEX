#ifndef CEXTEST_HMGTEST_H
#define CEXTEST_HMGTEST_H

#include "ITest.h"
#include "../CEX/IDrbg.h"

namespace Test
{
	using Drbg::IDrbg;

	/// <summary>
	/// Tests the HMAC Counter Generator (HCG) implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para></para>
	/// </summary>
	class HCGTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 65536;
		static const size_t MINM_ALLOC = 1024;
		// 2MB sample, should be 100MB or more for accuracy
		// Note: the sample size must be evenly divisible by 8.
		static const size_t SAMPLE_SIZE = 2048000;
		static const size_t TEST_CYCLES = 10;

		std::vector<std::vector<uint8_t>> m_expected;
		std::vector<std::vector<uint8_t>> m_key;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		HCGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HCGTest();

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
		///  Test DRBG output using chisquare, mean value, and ordered runs tests
		/// </summary>
		/// 
		/// <param name="Rng">The DRBG instance</param>
		void Evaluate(IDrbg* Rng);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to DRBG output
		/// </summary>
		/// 
		/// <param name="Rng">The DRBG instance</param>
		/// <param name="Key">The input key</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IDrbg* Rng, std::vector<uint8_t> &Key, std::vector<uint8_t> &Expected);

		/// <summary>
		/// Test the auto re-seeding mechanism
		/// </summary>
		void Reseed();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		void Stress();

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
