#ifndef _CEXTEST_ISCPRSGTEST_H
#define _CEXTEST_ISCPRSGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// ISCRsg known answer tests
	/// <para>Vectors from <see href="https://github.com/vibornoff/asmcrypto.js/blob/7683d4dd5faab740f4317858842079568857c2ad/test/isaac.js"/> and
	/// mirrored by author: (block reversed order) <see href="http://burtleburtle.net/bob/rand/randvect.txt"/></para>
	/// </summary>
	class ISCRsgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "ISAAC Known Answer Test Vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All ISCRsg tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<uint> m_expected;

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
		/// Compares known answer ISCRsg vectors for equality
		/// </summary>
		ISCRsgTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~ISCRsgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector();
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif