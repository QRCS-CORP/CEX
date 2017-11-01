#ifndef CEXTEST_MACSTREAMTEST_H
#define CEXTEST_MACSTREAMTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	/// <summary>
	/// Tests the MacStream class output against direct output from an HMAC instance
	/// </summary>
	class MacStreamTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compare MacStream output to Mac instance output
		/// </summary>
		MacStreamTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~MacStreamTest();

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
		std::string Run() override;;

	private:

		void CompareCmac();
		void CompareHmac();
		void CmacDescriptionTest();
		void HmacDescriptionTest();
		void OnProgress(std::string Data);
	};
}

#endif
