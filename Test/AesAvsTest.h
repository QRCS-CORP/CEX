#ifndef CEXTEST_AESAVSTEST_H
#define CEXTEST_AESAVSTEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"

namespace Test
{
	using Cipher::Block::IBlockCipher;

    /// <summary>
    /// Tests the Rijndael implementation using the NIST AESAVS KAT, Monte Carlo, and Multi-block Message tests.
    /// <para>Using vector sets from: AESAVS certification package: <see href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf"/></para>
    /// </summary>
    class AesAvsTest final : public ITest
    {
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const std::string COUNT_TOKEN;
		static const std::string IV_TOKEN;
		static const std::string KEY_TOKEN;
		static const std::string PLAINTEXT_TOKEN;
		static const std::string CIPHERTEXT_TOKEN;
		TestEventHandler m_progressEvent;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// NIST AESAVS known answer vector tests
		/// </summary>
		explicit AesAvsTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AesAvsTest();

		//~~~Accessors~~~//

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

		void CbcKat(IBlockCipher* Cipher, const std::string &FilePath);
		void CbcMct(IBlockCipher* Cipher, const std::string &FilePath);
		void CbcMmt(IBlockCipher* Cipher, const std::string &FilePath);
		void EbcKat(IBlockCipher* Cipher, const std::string &FilePath);
		void EcbMct(IBlockCipher* Cipher, const std::string &FilePath);
		void EcbMmt(IBlockCipher* Cipher, const std::string &FilePath);
		void OnProgress(const std::string &Data);
    };
}

#endif
