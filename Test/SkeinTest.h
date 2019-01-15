#ifndef CEXTEST_SKEINTEST_H
#define CEXTEST_SKEINTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using Digest::IDigest;

	/// <summary>
	/// Tests the Skein implementations using exception handling, parameter checks, stress and KAT tests.
	/// <para>Tests the 256, 512, and 1024 bit versions of Skein against known test vectors from the skein 1.3 document, appendix C:
    /// <see href="http://www.skein-hash.info/sites/default/files/skein1.3.pdf"/></para>
	/// </summary>
	class SkeinTest final : public ITest
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
		/// Known answer tests for the 256, 512, and 1024 bit versions of Skein
		/// </summary>
		SkeinTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SkeinTest();

		//~~~Accessors~~~//

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

		//~~~Public Functions~~~//

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to digest output
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
		/// Compare Skein-256 compact and unrolled permutation functions for equivalence.
		/// </summary>
		void PermutationR72();

		/// <summary>
		/// Compare Skein-512 compact and unrolled permutation functions for equivalence.
		/// </summary>
		void PermutationR80();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Stress(IDigest* Digest);

		/// <summary>
		/// Test Skein TreeParams construction and serialization
		/// </summary>
		void TreeParams();

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
