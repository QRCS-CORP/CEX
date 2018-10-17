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
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 65536;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 10;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
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
		///  Test drbg output using chisquare, mean value, and ordered runs tests
		/// </summary>
		void Evaluate(IDrbg* Rng);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to drbg output
		/// </summary>
		/// 
		/// <param name="Rng">The drbg instance</param>
		/// <param name="Key">The input key</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Expected);

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		void Stress();

	private:

		void Initialize();
		void OnProgress(std::string Data);
		bool OrderedRuns(const std::vector<byte> &Input);
	};
}

#endif
