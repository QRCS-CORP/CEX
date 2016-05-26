#ifndef _CEXTEST_BLAKETEST_H
#define _CEXTEST_BLAKETEST_H

#include "ITest.h"
#include "IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the Blake digest implementation using vector comparisons.
	/// <para>Using vectors from the Blake SHA-3 submission package:
	/// <see href="http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html"/></para>
	/// </summary>
	class BlakeTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Blake Vector KATs; tests Blake 256/512 digests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All Blake tests have executed succesfully.";

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
		/// Blake Vector KATs from the Blake SHA-3 submission package
		/// </summary>
		BlakeTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~BlakeTest() 
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(CEX::Digest::IDigest *Digest, std::vector<byte> Input, std::vector<byte> Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}
#endif
