#ifndef _CEXTEST_SYMMETRICKEYTEST_H
#define _CEXTEST_SYMMETRICKEYTEST_H

#include "ITest.h"

namespace Test
{
	using namespace Key::Symmetric;
	using namespace IO;

	/// <summary>
	/// SymmetricKey test; checks constructors, access, and serialization of SymmetricKey and SymmetricSecureKey
	/// </summary>
	class SymmetricKeyTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SymmetricKey test; checks constructors, access, and serialization.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SymmetricKey tests have executed succesfully.";

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
		SymmetricKeyTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SymmetricKeyTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CheckInit();
				OnProgress("SymmetricKeyTest: Passed initialization tests..");
				CheckAccess();
				OnProgress("SymmetricKeyTest: Passed output comparison tests..");
				CompareSerial();
				OnProgress("SymmetricKeyTest: Passed key serialization tests..");

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
		void CheckInit();
		void CompareSerial();
		void OnProgress(char* Data);
	};
}

#endif
