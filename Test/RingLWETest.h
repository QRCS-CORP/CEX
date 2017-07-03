#ifndef _CEXTEST_RINGLWETEST_H
#define _CEXTEST_RINGLWETEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// 
	/// </summary>
	class RingLWETest : public ITest
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
		/// 
		/// </summary>
		RingLWETest();

		/// <summary>
		/// Destructor
		/// </summary>
		~RingLWETest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void OnProgress(std::string Data);
		void StressLoop();
		void SerializationCompare();
	};
}

#endif
