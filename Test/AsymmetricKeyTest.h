#ifndef CEXTEST_ASYMMETRICKEYTEST_H
#define CEXTEST_ASYMMETRICKEYTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// SymmetricKey test; checks constructors, initialization, and serialization of AsymmetricKey and AsymmetricSecureKey
	/// </summary>
	class AsymmetricKeyTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MINM_ALLOC = 32;
		static const size_t MAXM_ALLOC = 10240;
		static const size_t TEST_CYCLES = 100;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		AsymmetricKeyTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AsymmetricKeyTest();

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
