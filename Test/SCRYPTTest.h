#ifndef CEXTEST_SCRYPTTESTTEST_H
#define CEXTEST_SCRYPTTESTTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the SCRYPT implementation using vector comparisons.
	/// <para>Using the official Kats from RFC 7914: https://tools.ietf.org/html/rfc7914 .</para>
	/// </summary>
	class SCRYPTTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_output;
		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_salt;

	public:

		/// <summary>
		/// Compares known answer SCRYPT Drbg vectors for equality
		/// </summary>
		SCRYPTTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SCRYPTTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, size_t CpuCost, size_t Parallelization, size_t OutputSize);
		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif
