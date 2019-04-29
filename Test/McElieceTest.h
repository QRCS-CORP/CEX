#ifndef CEXTEST_MCELIECETEST_H
#define CEXTEST_MCELIECETEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// The McEliece asymmetric cipher test suite.
	///  <para>Tests public-key and cipher-text integrity, exception handling, cipher authentication, and a looping stress-test</para>
	/// </summary>
	class McElieceTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
#if defined (_DEBUG)
		static const size_t TEST_CYCLES = 1;
#else
		static const size_t TEST_CYCLES = 2;
#endif

		std::vector<byte> m_cprseed;
		std::vector<std::vector<byte>> m_cptexp;
		std::vector<std::vector<byte>> m_rngexp;
		std::vector<byte> m_rngkey;
		std::vector<std::vector<byte>> m_sskexp;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Constructor
		/// </summary>
		McElieceTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~McElieceTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Tests the ciphers authentication mechanism in a looping stress test
		/// </summary>
		void Authentication();

		/// <summary>
		/// Tests the ciphers decryption function for invalid cipher-text in a looping stress test
		/// </summary>
		void CipherText();

		/// <summary>
		/// Tests the ciphers exception handling functions
		/// </summary>
		void Exception();

		/// <summary>
		/// Compare known answer shared-secret and cipher-text vectors to cipher output
		/// </summary>
		void Kat();

		/// <summary>
		/// Verifies the Nist RNG implementation
		/// </summary>
		void NistRngKat();

		/// <summary>
		/// Tests the cipher for invalid public keys in a looping stress test
		/// </summary>
		void PublicKey();

		/// <summary>
		/// Tests the ciphers key serialization function using a looping stress test
		/// </summary>
		void Serialization();

		/// <summary>
		/// Tests the the cipher operations using a looping stress test
		/// </summary>
		void Stress();

	private:

		void Initialize();
		void OnProgress(const std::string &Data);
	};
}

#endif
