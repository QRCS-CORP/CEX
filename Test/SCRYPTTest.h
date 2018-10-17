#ifndef CEXTEST_SCRYPTTESTTEST_H
#define CEXTEST_SCRYPTTESTTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"
#include "../CEX/IKdf.h"

namespace Test
{
	using Kdf::IKdf;

	/// <summary>
	/// Tests the SCRYPT implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para>Using the official Kats from RFC 7914: https://tools.ietf.org/html/rfc7914 .</para>
	/// </summary>
	class SCRYPTTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 32 * 255;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 4;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
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

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to kdf output
		/// </summary>
		/// 
		/// <param name="Generator">The kdf generator instance</param>
		/// <param name="Key">The input key</param>
		/// <param name="Salt">The salt array</param>
		/// <param name="Expected">The expected output</param>
		/// <param name="CpuCost">The cpu cost</param>
		/// <param name="Parallelization">The parallelization factor</param>
		void Kat(IKdf* Generator, std::vector<byte> &Key, std::vector<byte> &Salt, std::vector<byte> &Expected, size_t CpuCost, size_t Parallelization);

		/// <summary>
		/// Test the different constructor initialization options
		/// </summary>
		///
		/// <param name="Generator">The kdf generator instance</param>
		void Params(IKdf* Generator);

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		///
		/// <param name="Generator">The kdf generator instance</param>
		void Stress(IKdf* Generator);

	private:

		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif
