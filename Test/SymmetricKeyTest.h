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
	class SymmetricKeyTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		SymmetricKeyTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SymmetricKeyTest();

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
		std::string Run() override;

	private:

		void CheckAccess();
		void CheckInit();
		void CompareSerial();
		void OnProgress(std::string Data);
	};
}

#endif
