#ifndef CEXTEST_SECURESTREAMTEST_H
#define CEXTEST_SECURESTREAMTEST_H

#include "ITest.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureStream.h"

namespace Test
{
	/// <summary>
	/// SecureStream test; compares reads and writes, and serialization
	/// </summary>
	class SecureStreamTest : public ITest
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
		SecureStreamTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SecureStreamTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void CheckAccess();
		void CompareSerial();
		void OnProgress(std::string Data);
	};
}

#endif
