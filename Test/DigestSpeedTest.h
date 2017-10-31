#ifndef CEXTEST_DIGESTSPEEDTEST_H
#define CEXTEST_DIGESTSPEEDTEST_H

#include "ITest.h"
#include "../CEX/Digests.h"

namespace Test
{
	/// <summary>
	/// Digest Speed Tests
	/// </summary>
	class DigestSpeedTest : public ITest
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
		static const uint64_t DATA_SIZE = MB100;
		static const uint64_t DEFITER = 10;

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
		DigestSpeedTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~DigestSpeedTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:

		void DigestBlockLoop(Enumeration::Digests DigestType, size_t SampleSize, size_t Loops = DEFITER, bool Parallel = false);
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void OnProgress(std::string Data);
	};
}

#endif