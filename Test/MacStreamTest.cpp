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
	using Key::Symmetric::SymmetricKey;

	const std::string MacStreamTest::DESCRIPTION = "MacStream output test; compares output from an SHA-2 512 HMAC and MacStream.";
	const std::string MacStreamTest::FAILURE = "FAILURE! ";
	const std::string MacStreamTest::SUCCESS = "SUCCESS! All MacStream tests have executed succesfully.";

	MacStreamTest::MacStreamTest()
		:
		m_progressEvent()
	{
	}

	MacStreamTest::~MacStreamTest()
	{
	}

	std::string MacStreamTest::Run()
	{
		using namespace Mac;

		try
		{
			CompareHmac();
			OnProgress(std::string("Passed MacStream HMAC comparison tests.."));
			CompareCmac();
			OnProgress(std::string("Passed MacStream CMAC comparison tests.."));
			CmacDescriptionTest();
			OnProgress(std::string("Passed CMAC description initialization test.."));
			HmacDescriptionTest();
			OnProgress(std::string("Passed HMAC description initialization test.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void MacStreamTest::CompareCmac()
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextInt32(1000, 100));
		rnd.GetBytes(data);
		std::vector<byte> key = rnd.GetBytes(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::CMAC* eng = new Mac::CMAC(Enumeration::BlockCiphers::Rijndael);
		size_t macSze = eng->MacSize();
		std::vector<byte> hash1(macSze);
		eng->Initialize(kp);
		eng->Compute(data, hash1);
		eng->Reset();

		// test stream method
		std::vector<byte> hash2(macSze);
		Processing::MacStream ds(eng);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
			throw TestException("DigestStreamTest: Expected hash is not equal!");

		// test byte access method
		ds.Initialize(kp);
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
			throw TestException("DigestStreamTest: Expected hash is not equal!");
	}

	void MacStreamTest::CompareHmac()
	{
		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextInt32(1000, 100));
		rnd.GetBytes(data);
		std::vector<byte> key = rnd.GetBytes(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::HMAC* eng = new Mac::HMAC(Enumeration::Digests::SHA256);
		size_t macSze = eng->MacSize();
		std::vector<byte> hash1(macSze);
		eng->Initialize(kp);
		eng->Compute(data, hash1);
		eng->Reset();

		// test stream method
		std::vector<byte> hash2(macSze);
		Processing::MacStream ds(eng);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
			throw TestException("DigestStreamTest: Expected hash is not equal!");

		// test byte access method
		ds.Initialize(kp);
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
			throw TestException("DigestStreamTest: Expected hash is not equal!");
	}

	void MacStreamTest::CmacDescriptionTest()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.GetBytes(rng.NextInt32(400, 100));
		std::vector<byte> key = rng.GetBytes(32);
		Mac::CMAC mac(Enumeration::BlockCiphers::Rijndael);
		SymmetricKey kp(key);
		mac.Initialize(kp);
		std::vector<byte> c1(mac.MacSize());
		mac.Compute(data, c1);
		Key::Symmetric::SymmetricKey mp(kp);

		Processing::MacDescription mds(32, Enumeration::BlockCiphers::Rijndael, Enumeration::IVSizes::V128);
		Processing::MacStream mst(mds);
		mst.Initialize(mp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.Compute(ms);
		delete ms;

		if (c1 != c2)
			throw TestException("MacStreamTest: CMAC code arrays are not equal!");
	}

	void MacStreamTest::HmacDescriptionTest()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.GetBytes(rng.NextInt32(400, 100));
		std::vector<byte> key = rng.GetBytes(64);
		Mac::HMAC mac(Enumeration::Digests::SHA256);
		SymmetricKey kp(key);
		mac.Initialize(kp);
		std::vector<byte> c1(mac.MacSize());
		mac.Compute(data, c1);

		Key::Symmetric::SymmetricKey mp(key);
		Processing::MacDescription mds(64, Enumeration::Digests::SHA256);
		Processing::MacStream mst(mds);
		mst.Initialize(mp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.Compute(ms);
		delete ms;

		if (c1 != c2)
			throw TestException("MacStreamTest: HMAC code arrays are not equal!");
	}

	void MacStreamTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}