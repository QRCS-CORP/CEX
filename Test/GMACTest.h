#ifndef _CEXTEST_GMACTEST_H
#define _CEXTEST_GMACTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// 
	/// </summary>
	class GMACTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "GMAC MAC Generator Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! GMAC tests have executed succesfully.";

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_expectedCode;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_nonce;
		std::vector<std::vector<byte>> m_plainText;

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
		/// 
		/// </summary>
		GMACTest()
			:
			m_expectedCode(0),
			m_key(0),
			m_nonce(0),
			m_plainText(0)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~GMACTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void GMACCompare(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &PlainText, std::vector<byte> &MacCode);
		void Initialize();
		void OnProgress(char* Data);
	};
}

#endif