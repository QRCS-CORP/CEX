#ifndef CEXTEST_POLY1305TEST_H
#define CEXTEST_POLY1305TEST_H

#include "ITest.h"
#include "../CEX/IMac.h"

namespace Test
{
	using Mac::IMac;

	/// <summary>
	/// Test the Poly1305 implementation with vectors from:
	/// RFC <a href="https://tools.ietf.org/html/rfc7539">7539</a>: ChaCha20 and Poly1305 for IETF Protocols.
	/// </summary>
	class Poly1305Test final : public ITest
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
		/// Initialize the GMAC tests
		/// </summary>
		Poly1305Test();

		/// <summary>
		/// Destructor
		/// </summary>
		~Poly1305Test();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		void Initialize();
		void OnProgress(std::string Data);
		void Poly1305Compare(std::vector<byte> &Key, std::vector<byte> &PlainText, std::vector<byte> &MacCode);
		void Poly1305AESCompare(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &PlainText, std::vector<byte> &MacCode);
	};
}

#endif
