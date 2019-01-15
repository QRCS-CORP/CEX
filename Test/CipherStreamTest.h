#ifndef CEXTEST_STREAMCIPHERTEST_H
#define CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "../CEX/CipherDescription.h"
#include "../CEX/CipherStream.h"

namespace Test
{
	using Processing::CipherDescription;
	using Processing::CipherStream;

	static const std::string CLASSNAME;
	static const std::string DESCRIPTION;
	static const std::string SUCCESS;

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
		/// Test cipher desription initialization
		/// </summary>
		void Description(CipherDescription* Description);

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
		void Mode(CipherStream* Cipher);

		/// <summary>
		/// Test parameters for correct operation
		/// </summary>
		void Parameters();

		/// <summary>
		/// Serialization tests
		/// </summary>
		void Serialization();

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif

