#ifndef CEXTEST_AEADTEST_H
#define CEXTEST_AEADTEST_H

#include "ITest.h"
#include "../CEX/IAeadMode.h"

namespace Test
{
	using Cipher::Block::Mode::IAeadMode;

	/// <summary>
	/// Tests the AEAD cipher modes; EAX, OCB and GCM.
	/// <para>Tests each AEAD mode for correct operation, including KAT, parallel-mode, auto-increment, and stress tests.</para>
	/// </summary>
	class AeadTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		static const size_t AUTHEN_LEN = 20;
		static const size_t MAC_LEN = 8;
		static const size_t MIN_ALLOC = 1024;
		static const size_t MAX_ALLOC = 4096;
		static const size_t NONCE_LEN = 8;

		std::vector<std::vector<byte>> m_associatedText;
		std::vector<std::vector<byte>> m_cipherText;
		std::vector<std::vector<byte>> m_expectedCode;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_nonce;
		std::vector<std::vector<byte>> m_plainText;
		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// Compares known answer AEAD vectors for equality
		/// </summary>
		AeadTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AeadTest();

		//~~~Accessors~~~//

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		//~~~Public Functions~~~//

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Compare output with known answer vectors
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		/// <param name="Key">The cipher input-key</param>
		/// <param name="Nonce">The nonce array</param>
		/// <param name="AssociatedText">The associated text array</param>
		/// <param name="PlainText">The plain-text array</param>
		/// <param name="CipherText">The cipher-text array</param>
		/// <param name="MacCode">The expected cipher authentication code</param>
		void Kat(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, 
			std::vector<byte> &PlainText, std::vector<byte> &CipherText, std::vector<byte> &MacCode);
		
		/// <summary>
		/// Test incremental and auto incrementing updates
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		void Incremental(IAeadMode* Cipher);
		
		/// <summary>
		/// Compare parallel to sequential operation modes for equivalence
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		void Parallel(IAeadMode* Cipher);
		
		/// <summary>
		/// Test operations in a looping stress test
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		void Stress(IAeadMode* Cipher);

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
