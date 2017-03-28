#ifndef _CEXTEST_SCRYPTTESTTEST_H
#define _CEXTEST_SCRYPTTESTTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the SCRYPT implementation using vector comparisons.
	/// <para>Using the official Kats from RFC 7914: https://tools.ietf.org/html/rfc7914 .</para>
	/// </summary>
	class SCRYPTTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SCRYPT SHA-2 test vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SCRYPT tests have executed succesfully.";

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
		/// Compares known answer SCRYPT Drbg vectors for equality
		/// </summary>
		SCRYPTTest()
			:
			m_key(2),
			m_output(0),
			m_salt(2)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SCRYPTTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, size_t CpuCost, size_t MemoryCost, size_t Parallelization, size_t OutputSize);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif
