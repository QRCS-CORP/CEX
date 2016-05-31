#ifndef _CEXTEST_DIGESTSPEEDTEST_H
#define _CEXTEST_DIGESTSPEEDTEST_H

#include "ITest.h"
#include "Digests.h"
#include "IDigest.h"
#include "DigestFromName.h"

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
			using namespace CEX::Digest;

			try
			{
				using CEX::Enumeration::Digests;

				OnProgress("### Message Digest Speed Tests: 10 loops * 100MB ###");
				OnProgress("***The Blake 256 digest***");
				DigestBlockLoop(Digests::Blake256, MB100);	//53
				OnProgress("***The Blake 512 digest***");
				DigestBlockLoop(Digests::Blake512, MB100);	//96
				OnProgress("***The Keccak 256 digest***");
				DigestBlockLoop(Digests::Keccak256, MB100); //209
				OnProgress("***The Keccak 512 digest***");
				DigestBlockLoop(Digests::Keccak512, MB100); //114
				OnProgress("***The SHA2 256 digest***");
				DigestBlockLoop(Digests::SHA256, MB100);	//177
				OnProgress("***The SHA2 512 digest***");
				DigestBlockLoop(Digests::SHA512, MB100);	//287
				OnProgress("***The Skein 256 digest***");
				DigestBlockLoop(Digests::Skein256, MB100);	//153
				OnProgress("***The Skein 512 digest***");
				DigestBlockLoop(Digests::Skein512, MB100);	//175
				OnProgress("***The Skein 1024 digest***");
				DigestBlockLoop(Digests::Skein1024, MB100); //199

				return MESSAGE;
			}
			catch (std::string &ex)
			{
				return FAILURE + " : " + ex;
			}
			catch (...)
			{
				return FAILURE + " : Internal Error";
			}
		}

	private:
		void DigestBlockLoop(CEX::Enumeration::Digests DigestType, size_t SampleSize, size_t Loops = DEFITER)
		{
			CEX::Digest::IDigest* dgt = CEX::Helper::DigestFromName::GetInstance(DigestType);
			std::vector<byte> hash(dgt->DigestSize(), 0);
			std::vector<byte> buffer(dgt->BlockSize(), 0);
			const char* name = dgt->Name();
			uint64_t start = TestUtils::GetTimeMs64();

			for (size_t i = 0; i < Loops; ++i)
			{
				size_t counter = 0;
				uint64_t lstart = TestUtils::GetTimeMs64();

				while (counter < SampleSize)
				{
					dgt->BlockUpdate(buffer, 0, buffer.size());
					counter += buffer.size();
				}
				std::string calc = CEX::Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
				OnProgress(const_cast<char*>(calc.c_str()));
			}
			dgt->DoFinal(hash, 0);
			delete dgt;

			uint64_t dur = TestUtils::GetTimeMs64() - start;
			uint64_t len = Loops * SampleSize;
			uint64_t rate = GetBytesPerSecond(dur, len);
			std::string glen = CEX::Utility::IntUtils::ToString(len / GB1);
			std::string mbps = CEX::Utility::IntUtils::ToString((rate / MB1));
			std::string secs = CEX::Utility::IntUtils::ToString((double)dur / 1000.0);
			std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");

			OnProgress(const_cast<char*>(resp.c_str()));
			OnProgress("");
		}

		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
		{
			double sec = (double)DurationTicks / 1000.0;
			double sze = (double)DataSize;

			return (uint64_t)(sze / sec);
		}

		void OnProgress(char* Data)
		{
			m_progressEvent(Data);
		}
	};
}

#endif