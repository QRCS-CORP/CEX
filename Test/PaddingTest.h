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
	class PaddingTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares padding modes for valid output
		/// </summary>
		PaddingTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~PaddingTest();

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

		void CompareOutput(Padding::IPadding* Padding);
		void OnProgress(std::string Data);
	};
}

#endif
