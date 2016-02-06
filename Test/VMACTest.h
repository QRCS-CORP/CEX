#ifndef _CEXTEST_VMACTEST_H
#define _CEXTEST_VMACTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// VMAC implementation vector comparison tests.
	/// <para>Vector test used by the official documentation:
	/// <see href="http://vmpcfunction.com/vmpc_mac.pdf"/></para>
	/// </summary>
	class VMACTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "VMAC Known Answer Test Vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All VMAC tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<byte> _expected;
		std::vector<byte> _input;
		std::vector<byte> _iv;
		std::vector<byte> _key;

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
		/// Compares known answer VMAC vectors for equality
		/// </summary>
		VMACTest()
			:
			_input(256)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~VMACTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareAccess(std::vector<byte> &Key, std::vector<byte> &Iv);
		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Iv, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif