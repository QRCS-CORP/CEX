#ifndef CEXTEST_PADDINGTEST_H
#define CEXTEST_PADDINGTEST_H

#include "ITest.h"
#include "../CEX/IPadding.h"

namespace Test
{
	using namespace Cipher::Block;

	/// <summary>
	/// Tests each Padding mode for valid operation
	/// </summary>
	class PaddingTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// Compares padding modes for valid output
		/// </summary>
		PaddingTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~PaddingTest();

		//~~~Accessors~~~//

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		//~~~Public Functions~~~//

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		void Kat(Padding::IPadding* Padding);
		void OnProgress(const std::string &Data);
	};
}

#endif
