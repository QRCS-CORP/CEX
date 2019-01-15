#ifndef CEXTEST_ASYMMETRICSPEEDTEST_H
#define CEXTEST_ASYMMETRICSPEEDTEST_H

#include "ITest.h"
#include "../CEX/AsymmetricEngines.h"
#include "../CEX/DilithiumParameters.h"
#include "../CEX/IBlockCipher.h"
#include "../CEX/MLWEParameters.h"
#include "../CEX/MPKCParameters.h"
#include "../CEX/NTRUParameters.h"
#include "../CEX/Prngs.h"
#include "../CEX/RLWEParameters.h"
#include "../CEX/SphincsParameters.h"

namespace Test
{
	using Enumeration::BlockCiphers;
	using Enumeration::DilithiumParameters;
	using Cipher::Block::IBlockCipher;
	using Enumeration::MLWEParameters;
	using Enumeration::MPKCParameters;
	using Enumeration::NTRUParameters;
	using Enumeration::Prngs;
	using Enumeration::RLWEParameters;
	using Enumeration::SphincsParameters;

	/// <summary>
	/// Asymmetric Cipher and Signature Scheme Speed Tests
	/// </summary>
	class AsymmetricSpeedTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
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

		void DlmGenerateLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType);
		void DlmSignLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType);
		void DlmVerifyLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType);
		void MpkcDecryptLoop(MPKCParameters Params, size_t Loops, Prngs PrngType);
		void MpkcEncryptLoop(MPKCParameters Params, size_t Loops, Prngs PrngType);
		void MpkcGenerateLoop(MPKCParameters Params, size_t Loops, Prngs PrngType);
		void MlweDecryptLoop(MLWEParameters Params, size_t Loops, Prngs PrngType);
		void MlweEncryptLoop(MLWEParameters Params, size_t Loops, Prngs PrngType);
		void MlweGenerateLoop(MLWEParameters Params, size_t Loops, Prngs PrngType);
		void NtruDecryptLoop(NTRUParameters Params, size_t Loops, Prngs PrngType);
		void NtruEncryptLoop(NTRUParameters Params, size_t Loops, Prngs PrngType);
		void NtruGenerateLoop(NTRUParameters Params, size_t Loops, Prngs PrngType);
		void RlweDecryptLoop(RLWEParameters Params, size_t Loops, Prngs PrngType);
		void RlweEncryptLoop(RLWEParameters Params, size_t Loops, Prngs PrngType);
		void RlweGenerateLoop(RLWEParameters Params, size_t Loops, Prngs PrngType);
		void SpxGenerateLoop(SphincsParameters Params, size_t Loops, Prngs PrngType);
		void SpxSignLoop(SphincsParameters Params, size_t Loops, Prngs PrngType);
		void SpxVerifyLoop(SphincsParameters Params, size_t Loops, Prngs PrngType);
		uint64_t GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count);
		void OnProgress(const std::string &Data);
	};
}

#endif
