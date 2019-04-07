#ifndef CEXTEST_KECCAKTEST_H
#define CEXTEST_KECCAKTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using CEX::Digest::IDigest;

	/// <summary>
	/// Tests the Keccak implementations using exception handling, parameter checks, stress and KAT tests.
	/// </summary>
	class KeccakTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t TEST_CYCLES = 25;

		std::vector<std::vector<byte>> m_message;
		std::vector<std::vector<byte>> m_expected;
		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// A range of Vector KATs; tests SHA-3 256/512 and HMACs
		/// </summary>
		KeccakTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~KeccakTest();

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
		/// Tests the Keccak component functions
		/// </summary>
		void Ancillary();

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Tests the 256/512/1024 bit version of the keccak message digest for correct operation,
		/// using selected vectors from the NIST Fips202 and alternative references.
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance</param>
		/// <param name="Message">The input message array</param>
		/// <param name="Expected">The expected known output</param>
		///
		/// <remarks>
		/// Fips202: <see href = "http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf"/>,
		/// ref(0) : <see href = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg0.pdf"/>
		/// ref(1600) : <see href = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf"/>
		/// ref(24, 448) : <see href = "https://www.di-mgt.com.au/sha_testvectors.html" / >
		/// </remarks>
		void Kat(IDigest* Digest, std::vector<byte> &Message, std::vector<byte> &Expected);

		/// <summary>
		/// Compares synchronous to parallel random-sized, pseudo-random arrays in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Parallel(IDigest* Digest);

		/// <summary>
		/// Compare KeccakP24 vectorized, compact and unrolled permutation functions for equivalence
		/// </summary>
		void PermutationR24();

		/// <summary>
		/// Compare KeccakP48 vectorized, compact and unrolled permutation functions for equivalence
		/// </summary>
		void PermutationR48();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Digest">The digest instance pointer</param>
		void Stress(IDigest* Digest);

		/// <summary>
		/// Test Keccak TreeParams construction and serialization
		/// </summary>
		void TreeParams();

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
