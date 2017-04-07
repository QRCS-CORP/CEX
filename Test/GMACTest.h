#ifndef _CEXTEST_GMACTEST_H
#define _CEXTEST_GMACTEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// Test the GMAC implementation with vectores from:
	/// NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The GMAC Mode for Authentication.
	/// </summary>
	class GMACTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_expectedCode;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_nonce;
		std::vector<std::vector<byte>> m_plainText;
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
		/// Initialize the GMAC tests
		/// </summary>
		GMACTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~GMACTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void GMACCompare(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &PlainText, std::vector<byte> &MacCode);
		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif