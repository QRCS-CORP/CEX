#ifndef _CEXTEST_KDF2DRBGTEST_H
#define _CEXTEST_KDF2DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests the KDF2 Drbg implementation using vector comparisons.
	/// </summary>
	class KDF2DrbgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "KDF2 Drbg SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All KDF2 Drbg tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<byte> _output;
		std::vector<byte> _salt;

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
		/// Compares known answer KDF2 Drbg vectors for equality
		/// </summary>
		KDF2DrbgTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~KDF2DrbgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(std::vector<byte> &Salt, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif
