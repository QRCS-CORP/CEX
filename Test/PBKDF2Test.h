#ifndef _CEXTEST_PBKDF2DRBGTEST_H
#define _CEXTEST_PBKDF2DRBGTEST_H

#include "ITest.h"
#include "IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the PBKDF2 implementation using vector comparisons.
	/// <para>Vectors generated via verified version in .Net CEX.</para>
	/// </summary>
	class PBKDF2Test : public ITest
	{
	private:
		const std::string DESCRIPTION = "PBKDF2 SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All HKDF tests have executed succesfully.";

		TestEventHandler m_progressEvent;
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
		void CompareVector(CEX::Digest::IDigest* Engine, std::vector<byte> &Output);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif
