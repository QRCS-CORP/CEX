#ifndef CEXTEST_KMACTEST_H
#define CEXTEST_KMACTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	/// <summary>
	/// KMAC implementation vector comparison tests.
	///
	/// <para>SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a>
	/// Using vectors from the official NIST SP800-185 vector set:
	/// <a href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf">KMAC example values</a></para>
	/// </summary>
	class KMACTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_custom;
		std::vector<std::vector<byte>> m_expected;
		std::vector<byte> m_key;
		std::vector<std::vector<byte>> m_message;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer SHA-2 KMAC vectors for equality
		/// </summary>
		KMACTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~KMACTest();

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

		void CompareVector(Mac::IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif

