#ifndef CEXTEST_SKEINTEST_H
#define CEXTEST_SKEINTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using Digest::IDigest;

	/// <summary>
	/// Tests the Skein digest implementation using vector comparisons.
	/// <para>Tests the 256, 512, and 1024 bit versions of Skein against known test vectors from the skein 1.3 document, appendix C:
    /// <see href="http://www.skein-hash.info/sites/default/files/skein1.3.pdf"/></para>
	/// </summary>
	class SkeinTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_expected512;
		std::vector<std::vector<byte>> m_expected1024;
		std::vector<std::vector<byte>> m_message256;
		std::vector<std::vector<byte>> m_message512;
		std::vector<std::vector<byte>> m_message1024;
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
		/// Compare known answer test vectors to digest output
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		/// <param name="Input">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void CompareVectorSkein(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected);

		/// <summary>
		/// Tests inner and outer parallel loop variances in the update function
		/// </summary>
		/// 
		/// <param name="Digest1">The primary digest instance pointer</param>
		/// <param name="Digest2">The comparison digest instance pointer</param>
		void EvaluateParallelSkein(IDigest* Digest1, IDigest* Digest2);

		/// <summary>
		/// Compare Skein-256 compact and unrolled permutation functions for equivalence.
		/// </summary>
		void EvaluatePermutationSkein256();

		/// <summary>
		/// Compare Skein-512 compact and unrolled permutation functions for equivalence.
		/// </summary>
		void EvaluatePermutationSkein512();

		/// <summary>
		/// Compare Skein-1024 compact and unrolled permutation functions for equivalence.
		/// </summary>
		void EvaluatePermutationSkein1024();

	private:

		void Initialize();
		void OnProgress(std::string Data);
		void EvaluateTreeParams();
	};
}

#endif
