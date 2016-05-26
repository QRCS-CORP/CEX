#ifndef _CEXTEST_SP20DRBGTEST_H
#define _CEXTEST_SP20DRBGTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// Tests the SP20DRBG implementation using vector comparisons.
	/// <para>Uses vectors derived from the .NET CEX implementation.</para>
	/// </summary>
	class SP20DrbgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SP20DRBG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SP20DRBG tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<byte> m_iv;
		std::vector<byte> m_key;
		std::vector<byte> m_output128;
		std::vector<byte> m_output256;

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
		/// Compares known answer SP20DRBG Drbg vectors for equality
		/// </summary>
		SP20DrbgTest()
			:
			m_key(16, 0),
			m_iv(16, 0),
			m_output128(0),
			m_output256(0)
		{
		}


		/// <summary>
		/// Destructor
		/// </summary>
		~SP20DrbgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareVector(unsigned int KeySize, std::vector<byte> Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif
