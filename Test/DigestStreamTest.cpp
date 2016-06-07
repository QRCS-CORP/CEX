#include "DigestStreamTest.h"
#include "../CEX/CSPPrng.h"
#include "../CEX/DigestStream.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/IByteStream.h"

namespace Test
{
	std::string DigestStreamTest::Run()
	{
		try
		{
			CompareOutput(CEX::Enumeration::Digests::SHA256);
			OnProgress("Passed DigestStream SHA256 comparison tests..");

			CompareOutput(CEX::Enumeration::Digests::SHA512);
			OnProgress("Passed DigestStream SHA512 comparison tests..");

			return SUCCESS;
		}
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void DigestStreamTest::CompareOutput(CEX::Enumeration::Digests Engine)
	{
		CEX::Prng::CSPPrng rnd;
		std::vector<byte> data(rnd.Next(1000, 10000));
		rnd.GetBytes(data);

		// digest instance for baseline
		CEX::Digest::IDigest* eng = CEX::Helper::DigestFromName::GetInstance(Engine);
		size_t dgtSze = eng->DigestSize();
		std::vector<byte> hash1(dgtSze);
		eng->ComputeHash(data, hash1);
		delete eng;

		// test stream method
		std::vector<byte> hash2(dgtSze);
		CEX::Processing::DigestStream ds(Engine);
		CEX::IO::IByteStream* ms = new CEX::IO::MemoryStream(data);
		hash2 = ds.ComputeHash(ms);

		if (hash1 != hash2)
			throw std::string("DigestStreamTest: Expected hash is not equal!");

		// test byte access method
		hash2 = ds.ComputeHash(data, 0, data.size());

		if (hash1 != hash2)
			throw std::string("DigestStreamTest: Expected hash is not equal!");
	}

	void DigestStreamTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}