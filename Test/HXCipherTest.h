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

		TestEventHandler _progressEvent;
		std::vector<std::vector<byte>> _rhxExpected;
		std::vector<std::vector<byte>> _shxExpected;
		std::vector<std::vector<byte>> _thxExpected;
		std::vector<byte> _key;
		std::vector<byte> _iv;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compares known answer HX Cipher vectors for equality
		/// </summary>
		HXCipherTest()
			:
			_key(192, 0),
			_iv(16, 0)
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
		void RHXMonteCarlo();
		void SHXMonteCarlo();
		void THXMonteCarlo();
	};
}

#endif
