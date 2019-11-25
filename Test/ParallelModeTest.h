#ifndef CEXTEST_PARALLELMODETEST_H
#define CEXTEST_PARALLELMODETEST_H

#include "ITest.h"
#include "../CEX/IAeadMode.h"
#include "../CEX/ICipherMode.h"

namespace Test
{
	using namespace Cipher::Block::Mode;

    /// <remarks>
    /// Parallel integrity and output comparisons, targeting multi-threaded and SIMD cipher mode operations
    /// </remarks>
    class ParallelModeTest final : public ITest
    {
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;
		static const size_t MAXM_ALLOC = 262140;
		static const size_t TEST_CYCLES = 100;

		TestEventHandler m_progressEvent;

    public:

		//~~~Constructor~~~//

		/// <remarks>
		/// Compares output between sequential and parallel cipher modes for equivalence
		/// </remarks>
		ParallelModeTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~ParallelModeTest();

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
		/// Compares synchronous to parallel processed random-sized, pseudo-random array transformations and their inverse in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Encryption">Test encryption or decryption output</param>
		void Stress(IAeadMode* Cipher, bool Encryption);

		/// <summary>
		/// Compares synchronous to parallel processed random-sized, pseudo-random array transformations and their inverse in a looping [TEST_CYCLES] stress-test
		/// </summary>
		/// 
		/// <param name="Cipher">The cipher instance pointer</param>
		/// <param name="Encryption">Test encryption or decryption output</param>
		void Stress(ICipherMode* Cipher, bool Encryption);

	private:

		void OnProgress(const std::string &Data);
    };
}

#endif

