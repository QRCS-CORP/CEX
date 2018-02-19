#ifndef CEXTEST_SIMDSPEEDTEST_H
#define CEXTEST_SIMDSPEEDTEST_H

#include "ITest.h"

namespace Test
{
	/// <summary>
	/// SIMD Speed Tests
	/// </summary>
	class SimdSpeedTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string MESSAGE;
		static const std::string TESTSIZE;
		static const uint64_t B512 = 512;
		static const uint64_t KB1 = 1024;
		static const uint64_t KB8 = KB1 * 8;
		static const uint64_t KB16 = KB1 * 16;
		static const uint64_t MB1 = 1000 * KB1;
		static const uint64_t MB10 = 10 * MB1;
		static const uint64_t MB100 = 10 * MB10;
		static const uint64_t GB1 = 10 * MB100;

		bool m_hasAVX;
		bool m_hasAVX2;
		bool m_hasAVX512;
		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		SimdSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SimdSpeedTest();

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

		void ClearBlockSpeed(uint64_t Length, size_t Loops);
		void ClearVectorSpeed(uint64_t Length, size_t Loops);
		void CopyBlockSpeed(uint64_t Length, size_t Loops);
		void CopyVectorSpeed(uint64_t Length, size_t Loops);
		static uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void Initialize();
		void OnProgress(std::string Data);
		void PostPerfResult(uint64_t Duration, uint64_t Length, const std::string &Message);
		void SetBlockSpeed(uint64_t Length, size_t Loops);
		void SetVectorSpeed(uint64_t Length, size_t Loops);
		void XorBlockSpeed(uint64_t Length, size_t Loops);
		void XorVectorSpeed(uint64_t Length, size_t Loops);
	};
}

#endif
