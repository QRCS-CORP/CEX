#ifndef _CEXTEST_SYMMETRICKEYGENERATORTEST_H
#define _CEXTEST_SYMMETRICKEYGENERATORTEST_H

#include "ITest.h"
#include "../CEX/ISymmetricKey.h"

namespace Test
{
	/// <summary>
	/// Tests key generator initialization and access methods
	/// </summary>
	class SymmetricKeyGeneratorTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SymmetricKeyGenerator test; verifies initialization and access methods.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SymmetricKeyGenerator tests have executed succesfully.";

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
		SymmetricKeyGeneratorTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SymmetricKeyGeneratorTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CheckAccess();
		void CheckInit();
		bool IsGoodRun(const std::vector<byte> &Input);
		bool IsValidKey(Key::Symmetric::ISymmetricKey &KeyParam);
		void OnProgress(char* Data);
	};
}

#endif
