#include "DigestStreamTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/DigestStream.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/IByteStream.h"

namespace Test
{

	const std::string DigestStreamTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &DigestStreamTest::Progress()
	{
		return m_progressEvent;
	}

	std::string DigestStreamTest::Run()
	{
		try
		{
			CompareOutput(Enumeration::Digests::SHA256);
			OnProgress(std::string("Passed DigestStream SHA256 comparison tests.."));

			CompareOutput(Enumeration::Digests::SHA512);
			OnProgress(std::string("Passed DigestStream SHA512 comparison tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void DigestStreamTest::CompareOutput(Enumeration::Digests Engine)
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);

		// digest instance for baseline
		Digest::IDigest* eng = Helper::DigestFromName::GetInstance(Engine);
		size_t dgtSze = eng->DigestSize();
		std::vector<byte> hash1(dgtSze);
		eng->Compute(data, hash1);
		delete eng;

		// test stream method
		std::vector<byte> hash2(dgtSze);
		Processing::DigestStream ds(Engine);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException("DigestStreamTest: Expected hash is not equal!");
		}

		// test byte access method
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
		{
			throw TestException("DigestStreamTest: Expected hash is not equal!");
		}
	}

	void DigestStreamTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
