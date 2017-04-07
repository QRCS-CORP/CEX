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
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		static const size_t NONCE_LEN = 8;
		static const size_t MAC_LEN = 8;
		static const size_t AUTHEN_LEN = 20;
		static const size_t MIN_ALLOC = 1024;
		static const size_t MAX_ALLOC = 4096;
		static const size_t EAX_TESTSIZE = 10;
		static const size_t OCB_TESTSIZE = 16;
		static const size_t GCM_TESTSIZE = 18;

		std::vector<std::vector<byte>> m_associatedText;
		std::vector<std::vector<byte>> m_cipherText;
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
		/// Compares known answer AEAD vectors for equality
		/// </summary>
		AEADTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AEADTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void CompareVector(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, std::vector<byte> &PlainText, std::vector<byte> &CipherText, std::vector<byte> &MacCode);
		void IncrementalCheck(IAeadMode* Cipher);
		void Initialize();
		void OnProgress(std::string Data);
		void ParallelTest(IAeadMode* Cipher);
		void StressTest(IAeadMode* Cipher);
	};
}

#endif
