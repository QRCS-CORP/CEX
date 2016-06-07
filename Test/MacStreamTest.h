#ifndef _CEXTEST_MACSTREAMTEST_H
#define _CEXTEST_MACSTREAMTEST_H

#include "ITest.h"
#include "../CEX/CSPPrng.h"
#include "../CEX/IMac.h"
#include "../CEX/CMAC.h"
#include "../CEX/HMAC.h"
#include "../CEX/VMAC.h"
#include "../CEX/SHA256.h"
#include "../CEX/RHX.h"
#include "../CEX/MacStream.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/IByteStream.h"

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
		void CompareOutput(CEX::Mac::IMac* Engine);
		void CmacDescriptionTest();
		void HmacDescriptionTest();
		void OnProgress(char* Data);
		void VmacDescriptionTest();
	};
}

#endif
