#ifndef CEXTEST_SHA2TEST_H
#define CEXTEST_SHA2TEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using Digest::IDigest;

    /// <summary>
    /// Tests the SHA2 implementations using exception handling, parameter checks, stress and KAT tests.
	/// <para>Using vectors from NIST SHA2 Documentation:
    /// <para><see href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf"/></para>
    /// </summary>
    class SHA2Test final : public ITest
    {
    private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t TEST_CYCLES = 25;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_message;
		TestEventHandler m_progressEvent;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// Known answer tests using the NIST SHA-2 KAT vectors
		/// </summary>
		SHA2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~SHA2Test();

		//~~~Accessors~~~//

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		//~~~Public Functions~~~//

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Tests the SHA2 component functions
		/// </summary>
		void Ancillary();

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to cipher output
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		/// <param name="Input">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void Kat(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected);

		/// <summary>
		/// Compares synchronous to parallel random-sized, pseudo-random arrays in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Parallel(IDigest* Digest);

		/// <summary>
		/// Compare SHA-256 vectorized, compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void PermutationR64();

		/// <summary>
		/// Compare SHA-512 compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void PermutationR80();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Stress(IDigest* Digest);

		/// <summary>
		/// Test SHA2 TreeParams construction and serialization
		/// </summary>
        void TreeParams();

    private:

		void Initialize();
		void OnProgress(const std::string &Data);

    };
}

#endif

