#ifndef CEXTEST_AEADTEST_H
#define CEXTEST_AEADTEST_H

#include "ITest.h"
#include "../CEX/IAeadMode.h"

namespace Test
{
	using Cipher::Block::Mode::IAeadMode;

	/// <summary>
	/// Tests the AEAD cipher modes.
	/// <para>Tests each AEAD mode for correct operation, including KAT, parallel-mode, auto-increment, exception handling, and stress tests.
	/// HBA KAT tests are original vectors, generated with this library.
	/// GCM KAT vectors are talken from: The Galois/Counter Mode of Operation (GCM), "https://eprint.iacr.org/2004/193.pdf"</para>
	/// </summary>
	class AeadTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		static const size_t MIN_ALLOC = 1024;
		static const size_t MAX_ALLOC = 4096;
		static const size_t MONTE_CYCLES = 10000;
		static const size_t TEST_CYCLES = 10;

		std::vector<std::vector<byte>> m_associatedText;
		std::vector<std::vector<byte>> m_cipherText;
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
		/// Test exception handlers for correct execution
		/// </summary>
		void Exception();

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
		void Kat(IAeadMode* Cipher, const std::vector<byte> &Key, const std::vector<byte> &Nonce, 
			const std::vector<byte> &AssociatedText, const std::vector<byte> &PlainText, const std::vector<byte> &CipherText);

		/// <summary>
		/// Compare parallel to sequential operation modes for equivalence
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		void Parallel(IAeadMode* Cipher);

		/// <summary>
		/// Test a single initialization and sequential successive calls to the transform
		/// </summary>
		///
		/// <param name="Cipher">The cipher instance</param>
		/// <param name="PlainText">The plain-text array</param>
		/// <param name="Output1">The first expected output</param>
		/// <param name="Output2">The second expected output</param>
		/// <param name="Output3">The third expected output</param>
		void Sequential(IAeadMode* Cipher, const std::vector<byte> &PlainText, const std::vector<byte> &Output1, 
			const std::vector<byte> &Output2, const std::vector<byte> &Output3);

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
