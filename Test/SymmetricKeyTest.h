#ifndef CEXTEST_SYMMETRICKEYTEST_H
#define CEXTEST_SYMMETRICKEYTEST_H

#include "ITest.h"

namespace Test
{
	using namespace Key::Symmetric;
	using namespace IO;

	/// <summary>
	/// SymmetricKey test; checks constructors, access, and serialization of SymmetricKey and SymmetricSecureKey
	/// </summary>
	class SymmetricKeyTest : public ITest
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
		SymmetricKeyTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SymmetricKeyTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void CheckAccess();
		void CheckInit();
		void CompareSerial();
		void OnProgress(std::string Data);
	};
}

#endif
