#ifndef CEXTEST_CSGTEST_H
#define CEXTEST_CSGTEST_H

#include "ITest.h"
#include "../CEX/IDrbg.h"

namespace Test
{
	/// <summary>
	/// CSG output comparison test.
	/// <para>Test using the official NIST references contained in:
	/// NIST cSHAKE KATs: <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf">cSHAKE example values</a>
	/// SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></para>
	/// </summary>
	class CSGTest final : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<byte> m_custom;
		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_seed;
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

	private:

		void CheckInit();
		void CompareOutput(Drbg::IDrbg* Generator, std::vector<byte> &Seed, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		bool OrderedRuns(const std::vector<byte> &Input);
	};
}

#endif
