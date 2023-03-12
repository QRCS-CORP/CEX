#ifndef CEXTEST_SERPENTTEST_H
#define CEXTEST_SERPENTTEST_H

#include "ITest.h"
#include "../CEX/ICipherMode.h"
#include "../CEX/IBlockCipher.h"

namespace Test
{
	using Cipher::Block::IBlockCipher;
	using Cipher::Block::Mode::ICipherMode;

    /// <summary>
    /// Serpent implementation vector comparison tests.
    /// <para>Using official vector sets from Nessie: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/"/>
    /// The full Nessie verified vector tests, including 100 and 1000 round Monte Carlo Tests:
    /// 128 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors"/>
    /// 192 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors"/>
    /// 256 bit key: <see href="http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors"/></para>
    /// </summary>
    class SerpentTest final : public ITest
    {
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t MONTE_CYCLES = 10000;
		static const size_t TEST_CYCLES = 100;

		std::vector<std::vector<uint8_t>> m_expected;
		std::vector<std::vector<uint8_t>> m_keys;
		std::vector<std::vector<uint8_t>> m_message;
		TestEventHandler m_progressEvent;

    public:

		//~~~Constructor~~~//

		/// <summary>
		/// Compares known answer Serpent vectors for equality (NESSIE)
		/// </summary>
		SerpentTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SerpentTest();

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
		/// The Serpent-128 known answer tests
		/// </summary>
		void Kat128();

		/// <summary>
		/// The Serpent-192 known answer tests
		/// </summary>
		void Kat192();

		/// <summary>
		/// The Serpent-256 known answer tests
		/// </summary>
		void Kat256();

		/// <summary>
		/// The SHX extended cipher known answer tests
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Key">The cipher key array</param>
		/// <param name="Message">The input message array</param>
		/// <param name="Expected">The expected output answer</param>
		void KatEx(IBlockCipher* Cipher, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected);

		/// <summary>
		/// The SHX extended monte carlo tests
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Key">The cipher key array</param>
		/// <param name="Message">The input message array</param>
		/// <param name="Expected">The expected output answer</param>
		void MonteCarloEx(IBlockCipher* Cipher, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected);

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

		void Kat(std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected);
		void Initialize();
		void MonteCarlo(std::vector<uint8_t> &Key, std::vector<uint8_t> &Input, std::vector<uint8_t> &Output, size_t Count = 100);
		void OnProgress(const std::string &Data);
    };
}

#endif

