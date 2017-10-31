#ifndef CEXTEST_PADDINGTEST_H
#define CEXTEST_PADDINGTEST_H

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
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

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
		PaddingTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~PaddingTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareOutput(Padding::IPadding* Padding);
		void OnProgress(std::string Data);
	};
}

#endif
