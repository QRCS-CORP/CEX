#ifndef CEXTEST_CMGTEST_H
#define CEXTEST_CMGTEST_H

#include "ITest.h"
#include "../CEX/IDrbg.h"

namespace Test
{
	using Drbg::IDrbg;

	/// <summary>
	/// Tests the Block Cipher Counter mode Generator (BCG) implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para>Compares DRBG output with CTR mode encrypting all zeroes input.</para>
	/// </summary>
	class BCGTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		// 2MB sample, should be 100MB or more for accuracy
		// Note: the sample size must be evenly divisible by 8.
		static const size_t SAMPLE_SIZE = 2048000;
		static const size_t TEST_CYCLES = 100;

		std::vector <std::vector<byte>> m_expected;
		std::vector <std::vector<byte>> m_key;
		std::vector <std::vector<byte>> m_nonce;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		BCGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~BCGTest();

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
		/// <param name="Nonce">The input nonce</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected);

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
