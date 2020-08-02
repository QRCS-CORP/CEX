#ifndef CEXTEST_ASYMMETRICSPEEDTEST_H
#define CEXTEST_ASYMMETRICSPEEDTEST_H

#include "ITest.h"
#include "../CEX/AsymmetricCiphers.h"
#include "../CEX/AsymmetricParameters.h"
#include "../CEX/AsymmetricSigners.h"

namespace Test
{
	using Enumeration::AsymmetricCiphers;
	using Enumeration::AsymmetricParameters;
	using Enumeration::AsymmetricSigners;

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
		static const uint64_t TEST_ITERATIONSF = 1;
		static const uint64_t TEST_ITERATIONSL = 1;
#else
		static const uint64_t TEST_ITERATIONSF = 100;
		static const uint64_t TEST_ITERATIONSL = 10;
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

		void CipherDecryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations);
		void CipherEncryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations);
		void CipherGenerateLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations);
		void SignerGenerateLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations);
		void SignerSignLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations);
		void SignerVerifyLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations);
		uint64_t GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count);
		void OnProgress(const std::string &Data);
	};
}

#endif
