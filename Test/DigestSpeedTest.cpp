#include "DigestSpeedTest.h"
#include "../CEX/IDigest.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/IntegerTools.h"

namespace Test
{
	const std::string DigestSpeedTest::CLASSNAME = "DigestSpeedTest";
	const std::string DigestSpeedTest::DESCRIPTION = "Digest Speed Tests.";
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
			DigestBlockLoop(Digests::SHA3256, MB100);
			OnProgress(std::string("***The parallel Keccak 256 digest***"));
			DigestBlockLoop(Digests::SHA3256, MB100, 10, true);

			OnProgress(std::string("***The sequential Keccak 512 digest***"));
			DigestBlockLoop(Digests::SHA3512, MB100);
			OnProgress(std::string("***The parallel Keccak 512 digest***"));
			DigestBlockLoop(Digests::SHA3512, MB100, 10, true);

			OnProgress(std::string("***The sequential SHA2 256 digest***"));
			DigestBlockLoop(Digests::SHA2256, MB100);
			OnProgress(std::string("***The parallel SHA2 256 digest***"));
			DigestBlockLoop(Digests::SHA2256, MB100, 10, true);

			OnProgress(std::string("***The sequential SHA2 512 digest***"));
			DigestBlockLoop(Digests::SHA2512, MB100);
			OnProgress(std::string("***The parallel SHA2 512 digest***"));
			DigestBlockLoop(Digests::SHA2512, MB100, 10, true);

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
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void DigestSpeedTest::DigestBlockLoop(Enumeration::Digests DigestType, size_t SampleSize, size_t Loops, bool Parallel)
	{
		Digest::IDigest* dgt;
		std::vector<uint8_t> hash(0);
		std::vector<uint8_t> buffer(0);
		std::string calc;
		std::string glen;
		std::string mbps;
		std::string secs;
		std::string resp;
		uint64_t dur;
		uint64_t len;
		uint64_t rate;
		uint64_t lstart;
		uint64_t start;
		size_t buflen;
		size_t counter;
		size_t i;

		dgt = Helper::DigestFromName::GetInstance(DigestType, Parallel);
		buflen = dgt->BlockSize();

		if (Parallel)
		{
			buflen = dgt->ParallelBlockSize();
		}

		hash.resize(dgt->DigestSize(), 0);
		buffer.resize(buflen, 0);
		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Loops; ++i)
		{
			counter = 0;
			lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				dgt->Update(buffer, 0, buffer.size());
				counter += buffer.size();
			}

			calc = TestUtils::ToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(calc);
		}

		dgt->Finalize(hash, 0);
		delete dgt;

		dur = TestUtils::GetTimeMs64() - start;
		len = static_cast<uint64_t>(Loops) * SampleSize;
		rate = GetBytesPerSecond(dur, len);
		glen = TestUtils::ToString(len / GB1);
		mbps = TestUtils::ToString((rate / MB1));
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	uint64_t DigestSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec;
		double sze;

		sec = static_cast<double>(DurationTicks) / 1000.0;
		sze = static_cast<double>(DataSize);

		return static_cast<uint64_t>(sze / sec);
	}

	void DigestSpeedTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
