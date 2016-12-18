#ifndef _CEXTEST_PADDINGTEST_H
#define _CEXTEST_PADDINGTEST_H

#include "ITest.h"
#include "../CEX/IPadding.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	/// <summary>
	/// Tests each Padding mode for valid output
	/// </summary>
	class PaddingTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Cipher Padding output Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Cipher Padding tests have executed succesfully.";

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
		/// Compares padding modes for valid output
		/// </summary>
		PaddingTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~PaddingTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareOutput(Padding::IPadding* Padding);
		void OnProgress(char* Data);
	};
}

#endif
