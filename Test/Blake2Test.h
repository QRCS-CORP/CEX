#ifndef _BLAKE2TEST_BLAKETEST_H
#define _BLAKE2TEST_BLAKETEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests the Blake2 digest implementation using vector comparisons.
	/// <para>Tests all vectors from the official Blake2 submission:
	/// <see href="https://github.com/BLAKE2/BLAKE2/tree/master/testvectors"/></para>
	/// </summary>
	class Blake2Test : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const std::string DMK_INP;
		static const std::string DMK_KEY;
		static const std::string DMK_HSH;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_message;
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
		/// Blake2 Vector KATs from the official submission package
		/// </summary>
		Blake2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~Blake2Test();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void Blake2BTest();
		void Blake2BPTest();
		void Blake2STest();
		void Blake2SPTest();
		void MacParamsTest();
		void TreeParamsTest();
		void OnProgress(std::string Data);
	};
}
#endif
