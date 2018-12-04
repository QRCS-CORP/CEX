#ifndef CEXTEST_ASYMMETRICSPEEDTEST_H
#define CEXTEST_ASYMMETRICSPEEDTEST_H

#include "ITest.h"
#include "../CEX/AsymmetricEngines.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/MLWEParameters.h"
#include "../CEX/MPKCParameters.h"
#include "../CEX/NTRUParameters.h"
#include "../CEX/IPrng.h"
#include "../CEX/RLWEParameters.h"

namespace Test
{
	using Cipher::Symmetric::Block::IBlockCipher;
	using Enumeration::MLWEParameters;
	using Enumeration::MPKCParameters;
	using Enumeration::NTRUParameters;
	using Prng::IPrng;
	using Enumeration::BlockCiphers;
	using Enumeration::RLWEParameters;


	/// <summary>
	/// Asymmetric Cipher and Signature Scheme Speed Tests
	/// </summary>
	class AsymmetricSpeedTest final : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string MESSAGE;
		static const uint64_t KB1 = 1000;
		static const uint64_t MB1 = KB1 * 1000;
		static const uint64_t MB10 = MB1 * 10;
		static const uint64_t MB100 = MB1 * 100;
		static const uint64_t GB1 = MB1 * 1000;
		static const uint64_t DEF_DATA_SIZE = MB100;
#if defined (_DEBUG)
		static const uint64_t DEF_TEST_ITER = 10;
#else
		static const uint64_t DEF_TEST_ITER = 100;
#endif

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initailize this class
		/// </summary>
		AsymmetricSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AsymmetricSpeedTest();

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

		void MpkcDecryptLoop(MPKCParameters Params, size_t Loops, IPrng* Rng);
		void MpkcEncryptLoop(MPKCParameters Params, size_t Loops, IPrng* Rng);
		void MpkcGenerateLoop(MPKCParameters Params, size_t Loops, IPrng* Rng);
		void MlweDecryptLoop(MLWEParameters Params, size_t Loops, IPrng* Rng);
		void MlweEncryptLoop(MLWEParameters Params, size_t Loops, IPrng* Rng);
		void MlweGenerateLoop(MLWEParameters Params, size_t Loops, IPrng* Rng);
		void NtruDecryptLoop(NTRUParameters Params, size_t Loops, IPrng* Rng);
		void NtruEncryptLoop(NTRUParameters Params, size_t Loops, IPrng* Rng);
		void NtruGenerateLoop(NTRUParameters Params, size_t Loops, IPrng* Rng);
		void RlweDecryptLoop(RLWEParameters Params, size_t Loops, IPrng* Rng);
		void RlweEncryptLoop(RLWEParameters Params, size_t Loops, IPrng* Rng);
		void RlweGenerateLoop(RLWEParameters Params, size_t Loops, IPrng* Rng);
		uint64_t GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count);
		void OnProgress(std::string Data);
	};
}

#endif
