#ifndef CEXTEST_HKDSTEST_H
#define CEXTEST_HKDSTEST_H

#include "ITest.h"
#include "../CEX/ShakeModes.h"

namespace Test
{
	using Enumeration::ShakeModes;

	/// <summary>
	/// Tests the HKDS implementation using exception handling, parameter checks, stress and KAT tests.
	/// <para>Uses vectors from: A Hierarchal Key Distribution System (HKDS) 
	/// <see href=""/></para>
	/// </summary>
	class HKDSTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 10240;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 1000;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_montecarlo;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer HKDS vectors for equality
		/// </summary>
		HKDSTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HKDSTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler& Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Test the HKDS authentication methods
		/// </summary>
		///
		/// <param name="ShakeMode">The Prf mode</param>
		void Authentication(ShakeModes ShakeMode);

		/// <summary>
		/// Compares decryption performance between HKDS and DUKPT
		/// </summary>
		void BenchmarkDecrypt();

		/// <summary>
		/// Compares authenticated decryption performance between HKDS and DUKPT
		/// </summary>
		void BenchmarkDecryptVerify();

		/// <summary>
		/// Compares encryption performance between HKDS and DUKPT
		/// </summary>
		void BenchmarkEncrypt();

		/// <summary>
		/// Compares authenticated encryption performance between HKDS and DUKPT
		/// </summary>
		void BenchmarkEncryptAuthenticate();

		/// <summary>
		/// Test a complete key distribution cycle
		/// </summary>
		///
		/// <param name="ShakeMode">The Prf mode</param>
		void Cycle(ShakeModes ShakeMode);

		/// <summary>
		/// Test standard encryption mode for a known answer
		/// </summary>
		///
		/// <param name="ShakeMode">The Prf mode</param>
		/// <param name="Key">The device key</param>
		/// <param name="Expected">The expected message cipher-text</param>
		void Kat(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected);

		/// <summary>
		/// Test authenticated encryption mode for a known answer
		/// </summary>
		///
		/// <param name="ShakeMode">The Prf mode</param>
		/// <param name="Key">The device key</param>
		/// <param name="Expected">The expected message cipher-text</param>
		void KatAE(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// A monte carlo KAT test
		/// </summary>
		///
		/// <param name="ShakeMode">The Prf mode</param>
		/// <param name="Key">The device key</param>
		/// <param name="Expected">The expected message cipher-text</param>
		void MonteCarlo(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected);

		/// <summary>
		/// Test behavior parallel and sequential processing in a looping [TEST_CYCLES] stress-test using randomly sized input and data
		/// </summary>
		/// 
		/// <param name="Generator">The kdf generator instance</param>
		void Stress();

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
