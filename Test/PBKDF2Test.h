#ifndef _CEXTEST_PBKDF2DRBGTEST_H
#define _CEXTEST_PBKDF2DRBGTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the PBKDF2 implementation using vector comparisons.
	/// <para>Using the official Kats from RFC 6070: https://tools.ietf.org/html/rfc6070 .</para>
	/// </summary>
	class PBKDF2Test : public ITest
	{
	private:
		const std::string DESCRIPTION = "PBKDF2 SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All PBKDF2 tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_output;
		std::vector<std::vector<byte>> m_salt;

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
		/// Compares known answer PBKDF2 Drbg vectors for equality
		/// </summary>
		PBKDF2Test()
			:
			m_key(2),
			m_output(0),
			m_salt(2)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~PBKDF2Test()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(size_t Size, size_t Iterations, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(char* Data);
		void TestInit();
	};
}

#endif
