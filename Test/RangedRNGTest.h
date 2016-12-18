#ifndef _CEXTEST_RANGEDRNGTEST_H
#define _CEXTEST_RANGEDRNGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests the minimum to maximum ranged returns from a PRNG
	/// </summary>
	class RangedRngTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Tests Prngs for valid minimum and maximum range responses.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All Prng range tests have executed succesfully.";

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
		/// PRNG operational range tests
		/// </summary>
		RangedRngTest() {}

		/// <summary>
		/// Destructor
		/// </summary>
		virtual ~RangedRngTest() {}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void EvaluateRange();
		void OnProgress(char* Data);
	};
}

#endif