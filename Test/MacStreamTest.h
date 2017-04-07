#ifndef _CEXTEST_MACSTREAMTEST_H
#define _CEXTEST_MACSTREAMTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	/// <summary>
	/// Tests the MacStream class output against direct output from an HMAC instance
	/// </summary>
	class MacStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "MacStream output test; compares output from an SHA-2 512 HMAC and MacStream.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All MacStream tests have executed succesfully.";

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
		/// Compare MacStream output to Mac instance output
		/// </summary>
		MacStreamTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~MacStreamTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareOutput(Mac::IMac* Engine1, Mac::IMac* Engine2);
		void CmacDescriptionTest();
		void HmacDescriptionTest();
		void OnProgress(std::string Data);
	};
}

#endif
