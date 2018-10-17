#ifndef CEXTEST_CIPHERMODETEST_H
#define CEXTEST_CIPHERMODETEST_H

#include "ITest.h"
#include "../CEX/ICipherMode.h"

namespace Test
{
	using Cipher::Symmetric::Block::Mode::ICipherMode;

    /// <summary>
	/// Cipher Mode implementations vector comparison test sets.
    /// <para>Using vectors from :NIST Special Publication 800-38A:
    /// <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf"/></para>
    /// </summary>
    class CipherModeTest final : public ITest
    {
    private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

        std::vector<std::vector<std::vector<byte>>> m_expected;
        std::vector<std::vector<byte>> m_keys;
        std::vector<std::vector<std::vector<byte>>> m_message;
        std::vector<std::vector<byte>> m_nonce;
		TestEventHandler m_progressEvent;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// Compares known answer Cipher Mode vectors for equality (NIST 800-38A)
		/// </summary>
		CipherModeTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~CipherModeTest();

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
		/// Test the Cipher Mode KAT vectors
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher mode instance</param>
		/// <param name="Key">The cipher input-key</param>
		/// <param name="Message">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		/// <param name="Encryption">Set the transformation mode to encrypt ot decrypt</param>
		void Kat(ICipherMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<std::vector<byte>> &Message, std::vector<std::vector<byte>> &Expected, bool Encryption);

    private:

		void Initialize();
		void OnProgress(std::string Data);
    };
}

#endif
