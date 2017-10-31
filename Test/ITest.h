#ifndef CEXTEST_ITEST_H
#define CEXTEST_ITEST_H

#include "TestCommon.h"
#include "TestEventHandler.h"

namespace Test
{
	using namespace CEX;

	/// <summary>
	/// Test Interface
	/// </summary>
	class ITest
	{
	public:
		// *** Properties *** //

		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() = 0;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() = 0;

		// *** Constructor *** //

		/// <summary>
		/// CTor: Initialize this class
		/// </summary>
		ITest() {}

		/// <summary>
		/// Destructor
		/// </summary>
		virtual ~ITest() {}

		// *** Public Methods *** //

		/// <summary>
		/// Start the test
		/// </summary>
		virtual std::string Run() = 0;
	};
}

#endif

