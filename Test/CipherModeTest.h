#ifndef CEXTEST_CIPHERMODETEST_H
#define CEXTEST_CIPHERMODETEST_H

#include "ITest.h"
#include "../CEX/ICipherMode.h"

namespace Test
{
	using Cipher::Block::Mode::ICipherMode;

    /// <summary>
	/// Cipher Mode implementations vector comparison test sets.
    /// <para>Using vectors from :NIST Special Publication 800-38A:
    /// <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf"/></para>
    /// </summary>
    class CipherModeTest final : public ITest
    {
    private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 102400;
		static const size_t MINM_ALLOC = 128;
		static const size_t MONTE_CYCLES = 10000;
		static const size_t TEST_CYCLES = 100;

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
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

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

		/// <summary>
		/// Test the CFB mode output with a an 8-bit register
		/// </summary>
		void Register();

		/// <summary>
		/// Test transformation and inverse with random in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher mode instance pointer</param>
		void Stress(ICipherMode* Cipher);

    private:

		void Initialize();
		void OnProgress(const std::string &Data);
    };
}

#endif
