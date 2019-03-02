#ifndef CEXTEST_STREAMCIPHERTEST_H
#define CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "../CEX/CipherStream.h"

namespace Test
{
	using Processing::CipherStream;

	static const std::string CLASSNAME;
	static const std::string DESCRIPTION;
	static const std::string SUCCESS;
	static const size_t MAXM_ALLOC = 102400;
	static const size_t MINM_ALLOC = 128;
	static const size_t TEST_CYCLES = 100;

	/// <summary>
	/// Tests the CipherStream Processer
	/// </summary>
	class CipherStreamTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string CLASSNAME;
		static const std::string SUCCESS;
		static const int32_t DEF_BLOCK = 64000;
		static const int32_t MIN_ALLOC = 4096;
		static const int32_t MAX_ALLOC = 8192;
		static const int32_t TEST_CYCLES = 10;

		size_t m_processorCount;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		CipherStreamTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherStreamTest();

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
		/// Test file stream access (manual)
		/// </summary>
		void File();

		/// <summary>
		/// Test memory stream access
		/// </summary>
		void Memory();

		/// <summary>
		/// Test stream modes for correct operation
		/// </summary>
		void Parallel(CipherStream* Cipher);

		/// <summary>
		/// Test parameters for correct operation
		/// </summary>
		void Parameters();
		
		/// <summary>
		/// Test transformation and inverse with random in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Stress(CipherStream* Cipher);

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif

