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
	std::string MacStreamTest::Run()
	{
		using namespace Mac;

		try
		{
			std::vector<byte> key(64);
			std::vector<byte> iv(32);
			Prng::SecureRandom rnd;

			rnd.GetBytes(key);
			rnd.GetBytes(iv);

			Digest::SHA256* sha = new Digest::SHA256();
			HMAC* hmac1 = new HMAC(sha);
			hmac1->Initialize(key, iv);
			// test enum initialization
			HMAC* hmac2 = new HMAC(Enumeration::Digests::SHA256);
			hmac2->Initialize(key, iv);
			CompareOutput(hmac1, hmac2);
			OnProgress("Passed MacStream HMAC comparison tests..");
			delete hmac1;
			delete hmac2;
			delete sha;

			key.resize(32);
			iv.resize(16);
			Cipher::Symmetric::Block::RHX* eng = new Cipher::Symmetric::Block::RHX();
			CMAC* cmac1 = new CMAC(eng);
			cmac1->Initialize(key, iv);
			CMAC* cmac2 = new CMAC(Enumeration::BlockCiphers::RHX);
			cmac2->Initialize(key, iv);
			CompareOutput(cmac1, cmac2);
			OnProgress("Passed MacStream CMAC comparison tests..");
			delete cmac1;
			delete cmac2;
			delete eng;
			OnProgress("Passed CMAC enum initialization test..");

			CmacDescriptionTest();
			OnProgress("Passed CMAC description initialization test..");
			HmacDescriptionTest();
			OnProgress("Passed HMAC description initialization test..");

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void MacStreamTest::CompareOutput(Mac::IMac* Engine1, Mac::IMac* Engine2)
	{
		using IO::IByteStream;
		using IO::MemoryStream;

		Prng::SecureRandom rnd;
		std::vector<byte> data(rnd.NextInt32(1000, 10000));
		rnd.GetBytes(data);

		// mac instance for baseline
		size_t macSze = Engine1->MacSize();
		std::vector<byte> code1(macSze);
		Engine1->ComputeMac(data, code1);

		// test stream method
		std::vector<byte> code2(macSze);
		Processing::MacStream ds(Engine2);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		code2 = ds.ComputeMac(ms);

		if (code1 != code2)
			throw std::exception("MacStreamTest: Expected hash is not equal!");

		delete ms;
	}

	void MacStreamTest::CmacDescriptionTest()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.GetBytes(rng.NextInt32(100, 400));
		std::vector<byte> key = rng.GetBytes(32);
		std::vector<byte> iv = rng.GetBytes(16);
		Mac::CMAC mac(Enumeration::BlockCiphers::Rijndael);
		mac.Initialize(key, iv);
		std::vector<byte> c1(mac.MacSize());
		mac.ComputeMac(data, c1);
		Key::Symmetric::SymmetricKey mp(key, iv);

		Processing::MacDescription mds(32, Enumeration::BlockCiphers::Rijndael, Enumeration::IVSizes::V128);
		Processing::MacStream mst(mds, mp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.ComputeMac(ms);
		delete ms;

		if (c1 != c2)
			throw std::exception("MacStreamTest: CMAC code arrays are not equal!");
	}

	void MacStreamTest::HmacDescriptionTest()
	{
		Prng::SecureRandom rng;
		std::vector<byte> data = rng.GetBytes(rng.NextInt32(100, 400));
		std::vector<byte> key = rng.GetBytes(64);
		Mac::HMAC mac(Enumeration::Digests::SHA256);
		mac.Initialize(key);
		std::vector<byte> c1(mac.MacSize());
		mac.ComputeMac(data, c1);
		Key::Symmetric::SymmetricKey mp(key);

		Processing::MacDescription mds(64, Enumeration::Digests::SHA256);
		Processing::MacStream mst(mds, mp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		std::vector<byte> c2 = mst.ComputeMac(ms);
		delete ms;

		if (c1 != c2)
			throw std::exception("MacStreamTest: HMAC code arrays are not equal!");
	}

	void MacStreamTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}