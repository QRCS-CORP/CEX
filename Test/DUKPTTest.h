#ifndef CEXTEST_DUKPTTEST_H
#define CEXTEST_DUKPTTEST_H

#include "ITest.h"
#include "../CEX/DukptKeyType.h"

namespace Test
{
	using Enumeration::DukptKeyType;

	/// <summary>
	/// Tests the DUKPT implementation using exception handling, parameter checks, exception and KAT tests.
	/// <para>Uses vectors from the official ANSI X9.24-3 2017 specification.
	/// <see href="https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf"/></para>
	/// </summary>
	class DUKPTTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 10240;
		static const size_t MINM_ALLOC = 1024;
		static const size_t TEST_CYCLES = 1000;

		std::vector<std::vector<byte>> m_bdk;
		std::vector <std::vector<byte>> m_derivationdata;
		std::vector<std::vector<byte>> m_derivationkey;
		std::vector<std::vector<byte>> m_workingKey;
		std::vector<std::vector<byte>> m_initialkey;
		std::vector<byte> m_initialkeyid;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Compares known answer DUKPT vectors for equality
		/// </summary>
		DUKPTTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~DUKPTTest();

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
		/// <param name="KeyType">The cipher key-type</param>
		void Authentication(DukptKeyType KeyType);

		/// <summary>
		/// Test a complete key distribution cycle
		/// </summary>
		///
		/// <param name="KeyType">The cipher key-type</param>
		void Cycle(DukptKeyType KeyType);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Test standard encryption mode for a known answer
		/// </summary>
		///
		/// <param name="KeyType">The cipher key-type</param>
		/// <param name="Key">The device key</param>
		/// <param name="Expected">The expected message cipher-text</param>
		void Kat(const std::vector<byte> &Bdk, uint Counter, const std::vector<byte> &Derived, 
			const std::vector<byte> &Data, const std::vector<byte> &Working);

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
