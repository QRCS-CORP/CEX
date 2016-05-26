#ifndef _CEXTEST_MACSTREAMTEST_H
#define _CEXTEST_MACSTREAMTEST_H

#include "ITest.h"
#include "CSPPrng.h"
#include "IMac.h"
#include "CMAC.h"
#include "HMAC.h"
#include "VMAC.h"
#include "SHA256.h"
#include "RHX.h"
#include "MacStream.h"
#include "MemoryStream.h"
#include "IByteStream.h"

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

		TestEventHandler _progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

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
