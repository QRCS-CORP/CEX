#ifndef CEXTEST_AESFIPSTEST_H
#define CEXTEST_AESFIPSTEST_H

#include "ITest.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/ICipherMode.h"

namespace Test
{
	using Cipher::Block::IBlockCipher;
	using Cipher::Block::Mode::ICipherMode;

    /// <summary>
	/// Rijndael implementation vector comparison tests.
    /// <para>Test vectors from the NIST standard tests contained in the AES specification document FIPS 197:
    /// <see href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"/> and the 
    /// Monte Carlo AES tests from the Brian Gladman's vector set:
    /// <see href="http://fp.gladman.plus.com/cryptography_technology/rijndael/"/></para>
    /// </summary>
    class RijndaelTest final : public ITest
    {
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t MONTE_CYCLES = 10000;
		static const size_t TEST_CYCLES = 100;

        std::vector<std::vector<byte>> m_cipherText;
        std::vector<std::vector<byte>> m_keys;
        std::vector<std::vector<byte>> m_plainText;
		TestEventHandler m_progressEvent;
		bool m_testAesNi;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// Compares known answer Rijndael vectors for equality (FIPS 197)
		/// </summary>
		explicit RijndaelTest(bool TestNI = false);

		/// <summary>
		/// Destructor
		/// </summary>
		~RijndaelTest();

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
		/// Compare known answer test vectors to authenticated and standard cipher output
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Message">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void Kat(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected);

		/// <summary>
		/// Compare known answer test vectors to a looping monte carlo output
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Message">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void MonteCarlo(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected);

		/// <summary>
		/// Compares synchronous to parallel processed random-sized, pseudo-random array transformations and their inverse in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Parallel(ICipherMode* Cipher);

		/// <summary>
		/// Test transformation and inverse with random in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Stress(ICipherMode* Cipher);

    private:

		void Initialize();
		void OnProgress(const std::string &Data);
    };
}

#endif
