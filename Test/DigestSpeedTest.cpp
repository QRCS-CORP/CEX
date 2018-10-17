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

	const std::string DigestSpeedTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &DigestSpeedTest::Progress()
	{
		return m_progressEvent;
	}

	std::string DigestSpeedTest::Run()
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

			OnProgress(std::string("***The sequential Keccak 1024 digest***"));
			DigestBlockLoop(Digests::Keccak1024, MB100);
			OnProgress(std::string("***The parallel Keccak 1024 digest***"));
			DigestBlockLoop(Digests::Keccak1024, MB100, 10, true);

			OnProgress(std::string("***The sequential SHA2 256 digest***"));
			DigestBlockLoop(Digests::SHA256, MB100);
			OnProgress(std::string("***The parallel SHA2 256 digest***"));
			DigestBlockLoop(Digests::SHA256, MB100, 10, true);

			OnProgress(std::string("***The sequential SHA2 512 digest***"));
			DigestBlockLoop(Digests::SHA512, MB100);
			OnProgress(std::string("***The parallel SHA2 512 digest***"));
			DigestBlockLoop(Digests::SHA512, MB100, 10, true);

			for (size_t i = 0; i < 5; ++i)
			{
				OnProgress(std::string("***The sequential Skein 256 digest***"));
				DigestBlockLoop(Digests::Skein256, MB100);
				OnProgress(std::string("***The parallel Skein 256 digest***"));
				DigestBlockLoop(Digests::Skein256, MB100, 10, true);
			}
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
			return FAILURE + " : Unknown Error";
		}
	}

	void DigestSpeedTest::DigestBlockLoop(Enumeration::Digests DigestType, size_t SampleSize, size_t Loops, bool Parallel)
	{
		Digest::IDigest* dgt = Helper::DigestFromName::GetInstance(DigestType, Parallel);
		size_t bufSze = dgt->BlockSize();
		if (Parallel)
		{
			bufSze = dgt->ParallelBlockSize();
		}

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
			std::string calc = TestUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(calc);
		}
		dgt->Finalize(hash, 0);
		delete dgt;

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string glen = TestUtils::ToString(len / GB1);
		std::string mbps = TestUtils::ToString((rate / MB1));
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
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
