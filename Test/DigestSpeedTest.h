#ifndef _CEXTEST_DIGESTSPEEDTEST_H
#define _CEXTEST_DIGESTSPEEDTEST_H

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
		const std::string DESCRIPTION = "Digest Speed Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string MESSAGE = "COMPLETE! Speed tests have executed succesfully.";
		static constexpr uint64_t KB1 = 1000;
		static constexpr uint64_t MB1 = KB1 * 1000;
		static constexpr uint64_t MB10 = MB1 * 10;
		static constexpr uint64_t MB100 = MB1 * 100;
		static constexpr uint64_t GB1 = MB1 * 1000;
		static constexpr uint64_t DATA_SIZE = MB100;
		static constexpr uint64_t DEFITER = 10;

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

		DigestSpeedTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			using namespace Enumeration;

			try
			{
				using Enumeration::Digests;

				OnProgress(std::string("### Message Digest Speed Tests: 10 loops * 100MB ###"));

				OnProgress(std::string("***The sequential Blake 256 digest***"));
				DigestBlockLoop(Digests::Blake256, MB100);
				OnProgress(std::string("***The sequential parallel Blake 256 digest***"));
				DigestBlockLoop(Digests::Blake256, MB100, 10, true);

				OnProgress(std::string("***The sequential Blake 512 digest***"));
				DigestBlockLoop(Digests::Blake512, MB100);
				OnProgress(std::string("***The parallel Blake 512 digest***"));
				DigestBlockLoop(Digests::Blake512, MB100, 10, true);

				OnProgress(std::string("***The sequential Keccak 256 digest***"));
				DigestBlockLoop(Digests::Keccak256, MB100);
				OnProgress(std::string("***The parallel Keccak 256 digest***"));
				DigestBlockLoop(Digests::Keccak256, MB100, 10, true);

				OnProgress(std::string("***The sequential Keccak 512 digest***"));
				DigestBlockLoop(Digests::Keccak512, MB100);
				OnProgress(std::string("***The parallel Keccak 512 digest***"));
				DigestBlockLoop(Digests::Keccak512, MB100, 10, true);

				OnProgress(std::string("***The sequential SHA2 256 digest***"));
				DigestBlockLoop(Digests::SHA256, MB100);
				OnProgress(std::string("***The parallel SHA2 256 digest***"));
				DigestBlockLoop(Digests::SHA256, MB100, 10, true);

				OnProgress(std::string("***The sequential SHA2 512 digest***"));
				DigestBlockLoop(Digests::SHA512, MB100);
				OnProgress(std::string("***The parallel SHA2 512 digest***"));
				DigestBlockLoop(Digests::SHA512, MB100, 10, true);

				OnProgress(std::string("***The sequential Skein 256 digest***"));
				DigestBlockLoop(Digests::Skein256, MB100);
				OnProgress(std::string("***The parallel Skein 256 digest***"));
				DigestBlockLoop(Digests::Skein256, MB100, 10, true);

				OnProgress(std::string("***The sequential Skein 512 digest***"));
				DigestBlockLoop(Digests::Skein512, MB100);
				OnProgress(std::string("***The parallel Skein 512 digest***"));
				DigestBlockLoop(Digests::Skein512, MB100, 10, true);

				OnProgress(std::string("***The sequential Skein 1024 digest***"));
				DigestBlockLoop(Digests::Skein1024, MB100);
				OnProgress(std::string("***The parallel Skein 1024 digest***"));
				DigestBlockLoop(Digests::Skein1024, MB100, 10, true);

				return MESSAGE;
			}
			catch (std::exception const &ex)
			{
				return FAILURE + " : " + ex.what();
			}
			catch (...)
			{
				return FAILURE + " : Internal Error";
			}
		}

	private:
		void DigestBlockLoop(Enumeration::Digests DigestType, size_t SampleSize, size_t Loops = DEFITER, bool Parallel = false);
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void OnProgress(std::string Data);
	};
}

#endif