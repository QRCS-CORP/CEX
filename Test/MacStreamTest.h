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

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
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
		/// Test initialization using a CMAC description
		/// </summary>
		void DescriptionCMAC();

		/// <summary>
		/// Test initialization using a HMAC description
		/// </summary>
		void DescriptionHMAC();

		/// <summary>
		/// Evaluate correct operation using a CMAC description
		/// </summary>
		void EvaluateCMAC();

		/// <summary>
		/// Evaluate correct operation using a HMAC description
		/// </summary>
		void EvaluateHMAC();

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;;

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif
