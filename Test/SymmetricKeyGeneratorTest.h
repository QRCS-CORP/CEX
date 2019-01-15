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

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MINM_ALLOC = 1;
		static const size_t MAXM_ALLOC = 10240;
		static const size_t SAMPLE_SIZE = 1024000;
		static const size_t TEST_CYCLES = 100;

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

		/// <summary>
		///  Test drbg output using chisquare, mean value, and ordered runs tests
		/// </summary>
		void Evaluate();

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		void Stress();

	private:

		void Evaluate(const std::string &Name, std::vector<byte> &Sample);
		void OnProgress(const std::string &Data);
	};
}

#endif
