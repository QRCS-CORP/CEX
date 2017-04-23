#ifndef _CEXTEST_MEMUTILSTEST_H
#define _CEXTEST_MEMUTILSTEST_H

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
	/// Tests the MemUtils SIMD implementations
	/// </summary>
	class MemUtilsTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
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
		MemUtilsTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~MemUtilsTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void PostPerfResult(uint64_t Duration, uint64_t Length, const std::string &Message);
		void OnProgress(std::string Data);
		void UtilsCompare();
	};
}

#endif
