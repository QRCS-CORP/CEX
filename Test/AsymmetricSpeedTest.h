#ifndef _CEXTEST_ASYMMETRICSPEEDTEST_H
#define _CEXTEST_ASYMMETRICSPEEDTEST_H

#include "ITest.h"
#include "../CEX/AsymmetricEngines.h"
#include "../CEX/RLWEParams.h"
namespace Test
{
	using Enumeration::RLWEParams;

	/// <summary>
	/// Asymmetric Cipher and Signature Scheme Speed Tests
	/// </summary>
	class AsymmetricSpeedTest : public ITest
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
		static const uint64_t DEF_TEST_ITER = 1000;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Initailize this class
		/// </summary>
		AsymmetricSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~AsymmetricSpeedTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void RlweDecryptLoop(RLWEParams Params, size_t Loops, bool Parallel);
		void RlweEncryptLoop(RLWEParams Params, size_t Loops, bool Parallel);
		void RlweGenerateLoop(RLWEParams Params, size_t Loops, bool Parallel);
		uint64_t GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count);
		void OnProgress(std::string Data);
	};
}

#endif