#ifndef _CEXTEST_PRNGTEST_H
#define _CEXTEST_PRNGTEST_H

#include "ITest.h"
#include "../CEX/IPrng.h"

namespace Test
{
	/// <summary>
	/// Tests the minimum to maximum ranged returns from a PRNG
	/// </summary>
	class PrngTest : public ITest
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
		/// PRNG operational range tests
		/// </summary>
		PrngTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~PrngTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void ChiSquare(Prng::IPrng* Rng);
		void MeanValue(Prng::IPrng* Rng);
		void OnProgress(std::string Data);
	};
}

#endif