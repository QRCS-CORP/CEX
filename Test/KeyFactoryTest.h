#ifndef _CEXTEST_KEYFACTORYTEST_H
#define _CEXTEST_KEYFACTORYTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests factory extraction and serialization methods on various structs and the KeyFactory class
	/// </summary>
	class KeyFactoryTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "KeyFactory test; tests factory extraction and serialization methods.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All KeyFactory tests have executed succesfully.";

		TestEventHandler _progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compare KeyFactory output to Mac instance output
		/// </summary>
		KeyFactoryTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~KeyFactoryTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareKeySerialization();
		void CompareKeyExtraction();
		void CompareCipherKey();
		void CompareMessageHeader();
		void OnProgress(char* Data);
	};
}

#endif
