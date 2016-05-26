#ifndef _CEXTEST_DRBGTEST_H
#define _CEXTEST_DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// DRBG implementations vector comparison tests.
	/// <para>Uses vectors derived from the .NET CEX implementation.</para>
	/// </summary>
	class CTRDrbgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CTRDRBG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All CTRDRBG tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_output;

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
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		CTRDrbgTest()
			:
			m_iv(16, 0),
			m_key(16, 0)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~CTRDrbgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(std::vector<byte> Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif
