#ifndef _CEXTEST_AEADTEST_H
#define _CEXTEST_AEADTEST_H

#include "ITest.h"
#include "../CEX/IAeadMode.h"

namespace Test
{
	using Cipher::Symmetric::Block::Mode::IAeadMode;

	/// <summary>
	/// Tests the AEAD cipher modes; EAX, OCB and GCM
	/// </summary>
	class AEADTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Authenticate Encrypt and Associated Data (AEAD) Cipher Mode Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! AEAD tests have executed succesfully.";

		const size_t NONCE_LEN = 8;
		const size_t MAC_LEN = 8;
		const size_t AUTHEN_LEN = 20;
		const size_t MIN_ALLOC = 1024;
		const size_t MAX_ALLOC = 4096;
		const size_t EAX_TESTSIZE = 10;
		const size_t OCB_TESTSIZE = 16;
		const size_t GCM_TESTSIZE = 18;

		TestEventHandler m_progressEvent;
		std::vector<std::vector<byte>> m_associatedText;
		std::vector<std::vector<byte>> m_cipherText;
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
		/// Compares known answer AEAD vectors for equality
		/// </summary>
		AEADTest()
			:
			m_associatedText(0),
			m_cipherText(0),
			m_expectedCode(0),
			m_key(0),
			m_nonce(0),
			m_plainText(0)
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~AEADTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void CompareVector(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, std::vector<byte> &PlainText, std::vector<byte> &CipherText, std::vector<byte> &MacCode);
		void IncrementalCheck(IAeadMode* Cipher);
		void Initialize();
		void OnProgress(char* Data);
		void ParallelTest(IAeadMode* Cipher);
		void StressTest(IAeadMode* Cipher);
	};
}

#endif
