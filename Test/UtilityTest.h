#ifndef CEXTEST_UTILITYTEST_H
#define CEXTEST_UTILITYTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Utiities test; unit tests for utility functions
	/// </summary>
	class UtilityTest : public ITest
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
		/// Initialize this class
		/// </summary>
		UtilityTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~UtilityTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		template<class T>
		T rol(T x, unsigned int c)
		{
			return (x << c) | (x >> ((sizeof(T) * 8) - c));
		}

		template<class T>
		T ror(T x, unsigned int c)
		{
			return (x >> c) | (x << ((sizeof(T) * 8) - c));
		}

		void EndianConversions();
		void RotationCheck();
		void OperationsCheck();
		void OnProgress(std::string Data);
	};
}

#endif
