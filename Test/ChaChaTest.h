#ifndef CEXTEST_CHACHATEST_H
#define CEXTEST_CHACHATEST_H

#include "ITest.h"
#include "../CEX/IStreamCipher.h"

namespace Test
{
	using Cipher::Symmetric::Stream::IStreamCipher;

	/// <summary>
	/// The ChaCha implementation KAT, stress, and exception handling tests
	/// </summary>
	/// 
	/// <remarks>
	/// <description>References:</description>
	/// <list type="number">
	/// <item><description>The <a href="http://cr.yp.to/chacha/chacha-20080128.pdf">ChaCha</a> cipher specification.</description></item>
	/// <item><description>ChaCha20 and Poly1305 for IETF protocols: <a href="https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-10">draft-irtf-cfrg-chacha20-poly1305-10</a>.</description></item>
	/// <item><description>The cryptographic library: <a href="https://github.com/jedisct1/libsodium">LibSodium</a>.</description></item>
	/// <item><description>ChaCha20 and Poly1305 based Cipher Suites for TLS: <a href="https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04">draft-agl-tls-chacha20poly1305-04</a>.</description></item>
	/// </list>
	/// </remarks>
	class ChaChaTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t TEST_CYCLES = 100;

		std::vector<std::vector<byte>> m_expected;
		std::vector<std::vector<byte>> m_key;
		std::vector<std::vector<byte>> m_nonce;
		TestEventHandler m_progressEvent;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// Original known answer tests for the 256, and 512 bit [original] versions of ChaCha
		/// </summary>
		ChaChaTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ChaChaTest();

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
		/// <param name="Cipher">The cipher instance pointer</param>
		void Authentication(IStreamCipher* Cipher);

		/// <summary>
		/// Compare ChaCha-256 vectorized, compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void CompareP256();

		/// <summary>
		/// Compare ChaCha-512 vectorized, compact, and unrolled, permutation functions for equivalence
		/// </summary>
		void CompareP512();

		/// <summary>
		/// Test exception handlers for correct execution
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Exception(IStreamCipher* Cipher);

		/// <summary>
		/// Compare known answer test vectors to cipher output
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Key">The input cipher key</param>
		/// <param name="Nonce">The cipher initialization vector</param>
		/// <param name="Input">The input test message</param>
		/// <param name="Expected">The expected output vector</param>
		void Kat(IStreamCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected);

		/// <summary>
		/// Compares synchronous to parallel processed random-sized, pseudo-random array transformations and their inverse in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Parallel(IStreamCipher* Cipher);

		/// <summary>
		/// Test transformation and inverse with random in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		void Stress(IStreamCipher* Cipher);

	private:

		void Initialize();
		void OnProgress(std::string Data);
	};
}

#endif
