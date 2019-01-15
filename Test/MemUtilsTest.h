#ifndef CEXTEST_MEMUTILSTEST_H
#define CEXTEST_MEMUTILSTEST_H

#include "ITest.h"
//#if defined(__AVX__)
#	include "../CEX/UInt128.h"
//#endif
#if defined(__AVX2__)
#	include "../CEX/UInt256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/UInt512.h"
#endif

namespace Test
{
	/// <summary>
	/// Tests the MemoryTools SIMD implementations
	/// </summary>
	class MemUtilsTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const std::string TESTSIZE;
		static const size_t KB1 = 1024;
		static const size_t KB8 = KB1 * 8;
		static const size_t KB16 = KB1 * 16;
		static const size_t MB1 = 1000 * KB1;
		static const size_t MB10 = 10 * MB1;
		static const size_t MB100 = 10 * MB10;
		static const size_t GB1 = 10 * MB100;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		MemUtilsTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~MemUtilsTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Evaluate memory operations for correct operation
		/// </summary>
		void Evaluate();

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		void OnProgress(const std::string &Data);

	};
}

#endif
