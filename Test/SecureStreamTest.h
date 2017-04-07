#ifndef _CEXTEST_SECURESTREAMTEST_H
#define _CEXTEST_SECURESTREAMTEST_H

#include "ITest.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureStream.h"

namespace Test
{
	/// <summary>
	/// SecureStream test; compares reads and writes, and serialization
	/// </summary>
	class SecureStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SecureStream test; compares serialization, reads and writes";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SecureStream tests have executed succesfully.";

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
		/// Initialize this class
		/// </summary>
		SecureStreamTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SecureStreamTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareSerial();
				OnProgress(std::string("SymmetricKeyGenerator: Passed serialization tests.."));
				CheckAccess();
				OnProgress(std::string("SymmetricKeyGenerator: Passed read/write comparison tests.."));

				return SUCCESS;
			}
			catch (std::exception const &ex)
			{
				throw TestException(std::string(FAILURE + " : " + ex.what()));
			}
			catch (...)
			{
				throw TestException(std::string(FAILURE + " : Internal Error"));
			}
		}

	private:

		void CheckAccess();
		void CompareSerial();
		void OnProgress(std::string Data);
	};
}

#endif
