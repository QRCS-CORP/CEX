#ifndef CEXTEST_SYMMETRICKEYGENERATORTEST_H
#define CEXTEST_SYMMETRICKEYGENERATORTEST_H

#include "ITest.h"
#include "../CEX/ISymmetricKey.h"

namespace Test
{
	/// <summary>
	/// Tests key generator initialization and access methods
	/// </summary>
	class SymmetricKeyGeneratorTest final : public ITest
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
		SymmetricKeyGeneratorTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SymmetricKeyGeneratorTest();

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
		virtual std::string Run() override;

	private:

		void CheckAccess();
		void CheckInit();
		bool IsGoodRun(const std::vector<byte> &Input);
		bool IsValidKey(Key::Symmetric::ISymmetricKey &KeyParam);
		void OnProgress(std::string Data);
	};
}

#endif
