#ifndef CEXTEST_SYMMETRICKEYTEST_H
#define CEXTEST_SYMMETRICKEYTEST_H

#include "ITest.h"

namespace Test
{
	using namespace Cipher;
	using namespace IO;

	/// <summary>
	/// SymmetricKey test; checks constructors, access, and serialization of SymmetricKey and SymmetricSecureKey
	/// </summary>
	class SymmetricKeyTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MINM_ALLOC = 32;
		static const size_t MAXM_ALLOC = 128;
		static const size_t TEST_CYCLES = 100;

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

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Test each initialization configuration for correct operation
		/// </summary>
		void Initialization();

		/// <summary>
		/// Compare serialization output
		/// </summary>
		void Serialization();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		void Stress();

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif
