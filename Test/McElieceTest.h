#ifndef _CEXTEST_MCELIECETEST_H
#define _CEXTEST_MCELIECETEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// McEliece key generation, encryption, and decryption tests
	/// </summary>
	class McElieceTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

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
		/// 
		/// </summary>
		McElieceTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~McElieceTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void OnProgress(std::string Data);
		void StressLoop();
		void SerializationCompare();
	};
}

#endif
