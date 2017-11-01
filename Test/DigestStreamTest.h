#ifndef CEXTEST_DIGESTSTREAMTEST_H
#define CEXTEST_DIGESTSTREAMTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the DigestStream class output against direct output from a digest instance
	/// </summary>
	class DigestStreamTest final : public ITest
	{
	private:

		const std::string DESCRIPTION = "DigestStream output test; compares output from SHA 256/512 digests and DigestStream.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All DigestStream tests have executed succesfully.";

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compare DigestStream output to the digest output
		/// </summary>
		DigestStreamTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~DigestStreamTest()
		{
		}

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

		void CompareOutput(Enumeration::Digests Engine);
		void OnProgress(std::string Data);
	};
}

#endif
