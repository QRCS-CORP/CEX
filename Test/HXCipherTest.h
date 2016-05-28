#ifndef _CEXTEST_HXCIPHERTEST_H
#define _CEXTEST_HXCIPHERTEST_H

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
		const std::string DESCRIPTION = "HX Cipher Known Answer Monte Carlo Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! HX tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_rhxExpected;
		std::vector<std::vector<byte>> m_shxExpected;
		std::vector<std::vector<byte>> m_thxExpected;
		std::vector<byte> m_key;
		std::vector<byte> m_key2;
		std::vector<byte> m_iv;

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
		HXCipherTest()
			:
			m_key(128, 0),
			m_key2(64, 0),
			m_iv(16, 0)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~HXCipherTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void Initialize();
		void OnProgress(char* Data);
		void AHXMonteCarlo();
		void RHXMonteCarlo();
		void SHXMonteCarlo();
		void THXMonteCarlo();
	};
}

#endif
