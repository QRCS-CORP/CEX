#ifndef CEXTEST_RCSTEST_H
#define CEXTEST_RCSTEST_H

#include "ITest.h"
#include "../CEX/IStreamCipher.h"

#include <wmmintrin.h>
#if defined(CEX_HAS_AVX512) || defined(CEX_HAS_AVX2)
#	include <zmmintrin.h>
#endif

namespace Test
{
	using Cipher::Stream::IStreamCipher;

	/// <summary>
	/// The RCS implementation KAT, monte carlo, stress, permutation, parallelization, authentication, and exception handling tests
	/// </summary>
	/// 
	/// <remarks>
	/// <description>References:</description>
	/// <list type="number">
	/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
	/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
	/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
	/// </list>
	/// </remarks>
	class RCSTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const bool HAS_AESNI;
		static const size_t MAXM_ALLOC = 262140;
#if defined(_DEBUG_)

#else

#endif
		static const size_t MONTE_CYCLES = 10000;
		static const size_t TEST_CYCLES = 10;

		std::vector<std::vector<uint8_t>> m_code;
		std::vector<std::vector<uint8_t>> m_expected;
		std::vector<std::vector<uint8_t>> m_key;
		std::vector<std::vector<uint8_t>> m_message;
		std::vector<std::vector<uint8_t>> m_monte;
		std::vector<std::vector<uint8_t>> m_nonce;
		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// Original known answer tests for the 256, 512, and 1024 bit versions of RCS
		/// </summary>
		RCSTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~RCSTest();

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

		//~~~Public Functions~~~//

		/// <summary>
		/// Tests the the cipher transformation using each supported authentication mode
		/// </summary>
		/// 
		/// <param name="Cipher">The authenticated cipher instance pointer</param>
		void Authentication(IStreamCipher* Cipher);

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer test vectors to split-message finalization calls
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Message">The input message</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Expected">The expected output vector</param>
		/// <param name="MacCode1">The first expected Mac code array</param>
		/// <param name="MacCode2">The second expected Mac code array</param>
		void Finalization(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &MacCode1, std::vector<uint8_t> &MacCode2);

		/// <summary>
		/// Compare known answer test vectors to cipher output
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Message">The input message</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Expected">The expected output vector</param>
		void Kat(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected);

		/// <summary>
		/// Compare known answer test vectors to a looping monte carlo output
		/// </summary>
		/// 
		/// <param name="Cipher">The stream cipher instance pointer</param>
		/// <param name="Message">The input test message</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Expected">The expected output vector</param>
		void MonteCarlo(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected);

		/// <summary>
		/// Compares synchronous to parallel processed random-sized, pseudo-random array transformations and their inverse in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Parallel(IStreamCipher* Cipher);

		/// <summary>
		/// Tests the the ciphers state serialization function
		/// </summary>
		void Serialization();

		/// <summary>
		/// Test a single initialization and sequential successive calls to the transform
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		/// <param name="Message">The plain-text array</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Output1">The first expected output</param>
		/// <param name="Output2">The second expected output</param>
		/// <param name="Output3">The third expected output</param>
		void Sequential(IStreamCipher* Cipher, const std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce,
			const std::vector<uint8_t> &Output1, const std::vector<uint8_t> &Output2, const std::vector<uint8_t> &Output3);

		/// <summary>
		/// Test transformation and inverse with random in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Stress(IStreamCipher* Cipher);

		/// <summary>
		/// Compare known answer test vectors to mac output
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Message">The input message</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Expected">The expected ciphertext</param>
		/// <param name="Mac">The expected mac code</param>
		void Verification(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &Mac);

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
