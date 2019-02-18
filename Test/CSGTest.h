#ifndef CEXTEST_CSGTEST_H
#define CEXTEST_CSGTEST_H

#include "ITest.h"
#include "../CEX/IDrbg.h"

namespace Test
{
	using Drbg::IDrbg;

	/// <summary>
	/// Tests the CSHAKE Generator (CSG) implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para>Test using the official NIST references contained in:
	/// NIST cSHAKE KATs: <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf">cSHAKE example values</a>
	/// SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></para>
	/// </summary>
	class CSGTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 65536;
		static const size_t MINM_ALLOC = 1024;
		// 2MB sample, should be 100MB or more for accuracy
		// Note: the sample size must be evenly divisible by 8.
		static const size_t SAMPLE_SIZE = 248000;
		static const size_t TEST_CYCLES = 100;

		std::vector<byte> m_custom;
		std::vector<std::vector<byte>> m_expected;
		std::vector < std::vector<byte>> m_info;
		std::vector<std::vector<byte>> m_key;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		CSGTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CSGTest();

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
		void Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Expected);

		/// <summary>
		/// Compare known answer test vectors to DRBG output
		/// </summary>
		/// 
		/// <param name="Rng">The DRBG instance</param>
		/// <param name="Key">The input key</param>
		/// <param name="Custom">The customization string</param>
		/// <param name="Info">The information string</param>
		/// <param name="Expected">The expected output</param>
		void Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Custom, std::vector<byte> &Info, std::vector<byte> &Expected);

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
