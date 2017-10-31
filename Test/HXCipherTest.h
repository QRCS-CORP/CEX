#ifndef CEXTEST_HXCIPHERTEST_H
#define CEXTEST_HXCIPHERTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// HX Cipher Known Answer Monte Carlo Tests.
	/// <para>Vectors generated from the CEX .Net version.</para>
	/// </summary>
	class HXCipherTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_key2;
		std::vector<std::vector<byte>> m_rhxExpected;
		std::vector<std::vector<byte>> m_shxExpected;
		std::vector<std::vector<byte>> m_thxExpected;
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
		/// Compares known answer HX Cipher vectors for equality
		/// </summary>
		HXCipherTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~HXCipherTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void Initialize();
		void OnProgress(std::string Data);
#if defined(__AVX__)
		void AHXMonteCarlo();
#endif
		void RHXMonteCarlo();
		void SHXMonteCarlo();
		void THXMonteCarlo();
	};
}

#endif
