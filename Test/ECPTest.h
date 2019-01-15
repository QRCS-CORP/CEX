#ifndef CEXTEST_ECPTEST_H
#define CEXTEST_ECPTEST_H

#include "ITest.h"
#include "../CEX/IProvider.h"

namespace Test
{
	using Provider::IProvider;

	/// <summary>
	/// Tests the system entropy collection provider output with random sampling analysis, and stress tests
	/// </summary>
	class ECPTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t MINM_ALLOC = 1024;
		static const size_t SAMPLE_SIZE = 1024000;
		static const size_t TEST_CYCLES = 10;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer CMAC vectors for equality
		/// </summary>
		ECPTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ECPTest();

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
		///  Test drbg output using chisquare, mean value, and ordered runs tests
		/// </summary>
		void Evaluate(IProvider* Rng);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		void Stress();

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif
