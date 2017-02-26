#ifndef _CEXTEST_SP20DRBGTEST_H
#define _CEXTEST_SP20DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// SBG output comparison test.
	/// <para>Compares drbg output with Salsa20 encrypting all zeroes input.</para>
	/// </summary>
	class SBGTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SBG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SBG tests have executed succesfully.";

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
		/// Compares known answer SBG Drbg vectors for equality
		/// </summary>
		SBGTest()
		{
		}


		/// <summary>
		/// Destructor
		/// </summary>
		~SBGTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareOutput();
		void OnProgress(char* Data);
	};
}

#endif
