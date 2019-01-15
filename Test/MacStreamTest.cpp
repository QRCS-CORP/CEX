#include "MacStreamTest.h"
#include "../CEX/BlockCiphers.h"
#include "../CEX/CMAC.h"
#include "../CEX/HMAC.h"
#include "../CEX/IByteStream.h"
#include "../CEX/IVSizes.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/MacDescription.h"
#include "../CEX/MacStream.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/RHX.h"
#include "../CEX/SHA256.h"

namespace Test
{
	using Cipher::SymmetricKey;

	const std::string MacStreamTest::CLASSNAME = "MacStreamTest";
	const std::string MacStreamTest::DESCRIPTION = "MacStream output test; compares output from an SHA-2 512 HMAC and MacStream.";
	const std::string MacStreamTest::SUCCESS = "SUCCESS! All MacStream tests have executed succesfully.";

	MacStreamTest::MacStreamTest()
		:
		m_progressEvent()
	{
	}

	MacStreamTest::~MacStreamTest()
	{
	}

	const std::string MacStreamTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &MacStreamTest::Progress()
	{
		return m_progressEvent;
	}

	std::string MacStreamTest::Run()
	{
		using namespace Mac;

		try
		{
			EvaluateHMAC();
			OnProgress(std::string("Passed MacStream HMAC comparison tests.."));
			EvaluateCMAC();
			OnProgress(std::string("Passed MacStream CMAC comparison tests.."));
			DescriptionCMAC();
			OnProgress(std::string("Passed CMAC description initialization test.."));
			DescriptionHMAC();
			OnProgress(std::string("Passed HMAC description initialization test.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void MacStreamTest::EvaluateCMAC()
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);
		std::vector<byte> key = rnd.Generate(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::CMAC* gen = new Mac::CMAC(Enumeration::BlockCiphers::Rijndael);
		size_t macSze = gen->TagSize();
		std::vector<byte> hash1(macSze);
		gen->Initialize(kp);
		gen->Compute(data, hash1);
		gen->Reset();

		// test stream method
		std::vector<byte> hash2(macSze);
		Processing::MacStream ds(gen);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateCMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}

		// test byte access method
		ds.Initialize(kp);
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateCMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}
	}

	void MacStreamTest::EvaluateHMAC()
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);
		std::vector<byte> key = rnd.Generate(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::HMAC* gen = new Mac::HMAC(Enumeration::SHA2Digests::SHA256);
		size_t macSze = gen->TagSize();
		std::vector<byte> hash1(macSze);
		gen->Initialize(kp);
		gen->Compute(data, hash1);
		gen->Reset();

		// test stream method
		std::vector<byte> hash2(macSze);
		Processing::MacStream ds(gen);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateHMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}

		// test byte access method
		ds.Initialize(kp);
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateHMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}
	}

	void MacStreamTest::DescriptionCMAC()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.Generate(rng.NextUInt32(400, 100));
		std::vector<byte> key = rng.Generate(32);
		Mac::CMAC gen(Enumeration::BlockCiphers::Rijndael);
		SymmetricKey kp(key);
		gen.Initialize(kp);
		std::vector<byte> c1(gen.TagSize());
		gen.Compute(data, c1);

		Processing::MacDescription mds(Enumeration::Macs::CMAC, Enumeration::BlockCiphers::Rijndael);
		Processing::MacStream mst(mds);
		mst.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.Compute(ms);
		delete ms;

		if (c1 != c2)
		{
			throw TestException(std::string("EvaluateCMAC"), gen.Name(), std::string("CMAC code arrays are not equal!"));
		}
	}

	void MacStreamTest::DescriptionHMAC()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.Generate(rng.NextUInt32(400, 100));
		std::vector<byte> key = rng.Generate(64);
		Mac::HMAC gen(Enumeration::SHA2Digests::SHA256);
		SymmetricKey kp(key);
		gen.Initialize(kp);
		std::vector<byte> c1(gen.TagSize());
		gen.Compute(data, c1);

		Cipher::SymmetricKey mp(key);
		Processing::MacDescription mds(Enumeration::Macs::HMACSHA256, Enumeration::Digests::SHA256);
		Processing::MacStream mst(mds);
		mst.Initialize(mp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.Compute(ms);
		delete ms;

		if (c1 != c2)
		{
			throw TestException(std::string("EvaluateHMAC"), gen.Name(), std::string("HMAC code arrays are not equal!"));
		}
	}

	void MacStreamTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
