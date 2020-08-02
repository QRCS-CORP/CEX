#include "DigestStreamTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/DigestStream.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/IByteStream.h"

namespace Test
{
	const std::string DigestStreamTest::CLASSNAME = "DigestStreamTest";
	const std::string DigestStreamTest::DESCRIPTION = "DigestStream output test; compares output from SHA 256/512 digests and DigestStream.";
	const std::string DigestStreamTest::SUCCESS = "SUCCESS! All DigestStream tests have executed succesfully.";

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
			Evaluate(Enumeration::Digests::SHA2256);
			OnProgress(std::string("Passed DigestStream SHA2256 comparison tests.."));

			Evaluate(Enumeration::Digests::SHA2512);
			OnProgress(std::string("Passed DigestStream SHA2512 comparison tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
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

	void DigestStreamTest::Evaluate(Enumeration::Digests Engine)
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);

		// digest instance for baseline
		Digest::IDigest* gen = Helper::DigestFromName::GetInstance(Engine);
		const std::string GENNME = gen->Name();
		size_t dgtSze = gen->DigestSize();
		std::vector<byte> hash1(dgtSze);
		gen->Compute(data, hash1);
		delete gen;

		// test stream method
		std::vector<byte> hash2(dgtSze);
		Processing::DigestStream ds(Engine);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException(std::string("Evaluate"), GENNME, std::string("DigestStreamTest: Expected hash is not equal! -DE1"));
		}

		// test byte access method
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
		{
			throw TestException(std::string("Evaluate"), GENNME, std::string("DigestStreamTest: Expected hash is not equal! -DE2"));
		}
	}

	void DigestStreamTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
