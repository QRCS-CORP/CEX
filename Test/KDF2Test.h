#ifndef _CEXTEST_KDF2DRBGTEST_H
#define _CEXTEST_KDF2DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests the KDF2 implementation using vector comparisons.
	/// <para>Using the official Kats from RFC 6070: <see href="https://tools.ietf.org/html/rfc6070"/>.</para>
	/// </summary>
	class KDF2Test : public ITest
	{
	private:
		const std::string DESCRIPTION = "KDF2 Drbg SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All KDF2 Drbg tests have executed succesfully.";

		std::vector<byte> m_key;
		std::vector<byte> m_output;
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
		/// Compares known answer KDF2 Drbg vectors for equality
		/// </summary>
		KDF2Test()
			:
			m_key(0),
			m_output(0)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~KDF2Test()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(std::vector<byte> &Salt, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TestInit();
	};
}

#endif
