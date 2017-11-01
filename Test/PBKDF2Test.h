#ifndef CEXTEST_PBKDF2DRBGTEST_H
#define CEXTEST_PBKDF2DRBGTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the PBKDF2 implementation using vector comparisons.
	/// <para>Using the official Kats from RFC 6070: https://tools.ietf.org/html/rfc6070 .</para>
	/// </summary>
	class PBKDF2Test final : public ITest
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
		/// Compares known answer PBKDF2 Drbg vectors for equality
		/// </summary>
		PBKDF2Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~PBKDF2Test();

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

		void CompareVector(size_t Size, size_t Iterations, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TestInit();
	};
}

#endif
