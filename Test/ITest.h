#ifndef CEXTEST_ITEST_H
#define CEXTEST_ITEST_H

#include "TestCommon.h"
#include "TestEventHandler.h"

// New Test Naming convention:
// object -> specifier
// Object Words:
// equality, exception, permutation, stress, vector
// Domain Specifiers:
// domain generic/specific name
//
// ex. 1) compare permutation skein256 => Permutation256() 
// ex. 2) evaluate vector sha256 => Vector256()
// ex. 3) stress-test blake256 => Stress256()
//
// Common Names:
// Equalityxxx -> test variations of a function for equivalence
// Exception -> test classes exception handling
// Parallel -> test parallel to synchronous operations for equivalence
// Stress -> test the function under stress
// Vector -> KAT test naming

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

