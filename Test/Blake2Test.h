#ifndef CEXTEST_BLAKE2TEST_H
#define CEXTEST_BLAKE2TEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using Digest::IDigest;

	/// <summary>
	/// Tests the Blake2 implementations using exception handling, parameter checks, stress and KAT tests.
	/// <para>Tests all vectors from the official Blake2 submission:
	/// <see href="https://github.com/BLAKE2/BLAKE2/tree/master/testvectors"/></para>
	/// </summary>
	class Blake2Test final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const std::string DMK_INP;
		static const std::string DMK_KEY;
		static const std::string DMK_HSH;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t TEST_CYCLES = 25;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_message;
		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// Blake2 Vector KATs from the official submission package
		/// </summary>
		Blake2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~Blake2Test();

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
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare Blake2-512 known answer test vectors to sequential cipher output
		/// </summary>
		void KatBlake2B();

		/// <summary>
		/// Compare Blake2-512 known answer test vectors to parallel cipher output
		/// </summary>
		void KatBlake2BP();

		/// <summary>
		/// Compare Blake2-256 known answer test vectors to sequential cipher output
		/// </summary>
		void KatBlake2S();

		/// <summary>
		/// Compare Blake2-256 known answer test vectors to parallel cipher output
		/// </summary>
		void KatBlake2SP();

		/// <summary>
		/// Compares synchronous to parallel random-sized, pseudo-random arrays in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Parallel(IDigest* Digest);

		/// <summary>
		/// Compare Blake2-256 vectorized, compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void PermutationR10P512();

		/// <summary>
		/// Compare Blake2-512 vectorized, compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void PermutationR12P1024();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Stress(IDigest* Digest);

		/// <summary>
		/// Test Blake2 TreeParams construction and serialization
		/// </summary>
		void TreeParams();

	private:

		void OnProgress(std::string Data);
	};
}
#endif
