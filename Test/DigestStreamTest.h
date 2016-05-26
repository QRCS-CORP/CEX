#ifndef _CEXTEST_DIGESTSTREAMTEST_H
#define _CEXTEST_DIGESTSTREAMTEST_H

#include "ITest.h"
#include "IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the DigestStream class output against direct output from a digest instance
	/// </summary>
	class DigestStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "DigestStream output test; compares output from SHA 256/512 digests and DigestStream.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All DigestStream tests have executed succesfully.";

		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

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
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareOutput(CEX::Enumeration::Digests Engine);
		void OnProgress(char* Data);
	};
}

#endif
