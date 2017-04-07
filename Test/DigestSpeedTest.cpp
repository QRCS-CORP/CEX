#include "DigestSpeedTest.h"
#include "../CEX/IDigest.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	const std::string DigestSpeedTest::DESCRIPTION = "Digest Speed Tests.";
	const std::string DigestSpeedTest::FAILURE = "FAILURE! ";
	const std::string DigestSpeedTest::MESSAGE = "COMPLETE! Speed tests have executed succesfully.";

	DigestSpeedTest::DigestSpeedTest()
		:
		m_progressEvent()
	{
	}

	DigestSpeedTest::~DigestSpeedTest()
	{
	}

	void DigestSpeedTest::DigestBlockLoop(Enumeration::Digests DigestType, size_t SampleSize, size_t Loops, bool Parallel)
	{
		Digest::IDigest* dgt = Helper::DigestFromName::GetInstance(DigestType, Parallel);
		size_t bufSze = dgt->BlockSize();
		if (Parallel)
			bufSze = dgt->ParallelBlockSize();
		
		std::vector<byte> hash(dgt->DigestSize(), 0);
		std::vector<byte> buffer(bufSze, 0);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				dgt->Update(buffer, 0, buffer.size());
				counter += buffer.size();
			}
			std::string calc = Utility::IntUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(calc);
		}
		dgt->Finalize(hash, 0);
		delete dgt;

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string glen = Utility::IntUtils::ToString(len / GB1);
		std::string mbps = Utility::IntUtils::ToString((rate / MB1));
		std::string secs = Utility::IntUtils::ToString((double)dur / 1000.0);
		std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	uint64_t DigestSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void DigestSpeedTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}