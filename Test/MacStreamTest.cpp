#include "MacStreamTest.h"
#include "CSPPrng.h"
#include "CMAC.h"
#include "HMAC.h"
#include "VMAC.h"
#include "BlockCiphers.h"
#include "MacDescription.h"
#include "IVSizes.h"
#include "KeyParams.h"

namespace Test
{
	std::string MacStreamTest::Run()
	{
		using namespace CEX::Mac;

		try
		{
			std::vector<byte> key(64);
			std::vector<byte> iv(32);
			CEX::Prng::CSPPrng rnd;

			rnd.GetBytes(key);
			rnd.GetBytes(iv);

			CEX::Digest::SHA256* sha = new CEX::Digest::SHA256();
			HMAC* hmac = new HMAC(sha);
			hmac->Initialize(key, iv);
			CompareOutput(hmac);
			OnProgress("Passed MacStream HMAC comparison tests..");
			// test enum initialization
			HMAC* hmac2 = new HMAC(CEX::Enumeration::Digests::SHA256);
			hmac2->Initialize(key, iv);
			CompareOutput(hmac2);
			delete hmac;
			delete hmac2;
			delete sha;
			OnProgress("Passed HMAC enum initialization test..");

			key.resize(32);
			iv.resize(16);
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CMAC* cmac = new CMAC(eng);
			cmac->Initialize(key, iv);
			CompareOutput(cmac);
			OnProgress("Passed MacStream CMAC comparison tests..");
			// test enum initialization
			CMAC* cmac2 = new CMAC(CEX::Enumeration::BlockCiphers::RHX);
			cmac2->Initialize(key, iv);
			CompareOutput(cmac2);
			delete cmac;
			delete cmac2;
			delete eng;
			OnProgress("Passed CMAC enum initialization test..");

			iv.resize(32);
			rnd.GetBytes(iv);
			VMAC* vmac = new VMAC();
			vmac->Initialize(key, iv);
			CompareOutput(vmac);
			delete vmac;
			OnProgress("Passed MacStream VMAC comparison tests..");

			CmacDescriptionTest();
			OnProgress("Passed MacStream CMAC test..");
			HmacDescriptionTest();
			OnProgress("Passed MacStream HMAC tests..");
			VmacDescriptionTest();
			OnProgress("Passed MacStream VMAC tests..");

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

	void MacStreamTest::CompareOutput(CEX::Mac::IMac* Engine)
	{
		using CEX::IO::IByteStream;
		using CEX::IO::MemoryStream;

		CEX::Prng::CSPPrng rnd;
		std::vector<byte> data(rnd.Next(1000, 10000));
		rnd.GetBytes(data);

		// mac instance for baseline
		unsigned int macSze = Engine->MacSize();
		std::vector<byte> code1(macSze);
		Engine->ComputeMac(data, code1);

		// test stream method
		std::vector<byte> code2(macSze);
		CEX::Processing::MacStream ds(Engine);
		CEX::IO::IByteStream* ms = new CEX::IO::MemoryStream(data);
		code2 = ds.ComputeMac(ms);

		if (code1 != code2)
			throw std::string("MacStreamTest: Expected hash is not equal!");

		// test byte access method
		code2 = ds.ComputeMac(data, 0, data.size());

		if (code1 != code2)
			throw std::string("MacStreamTest: Expected hash is not equal!");

		delete ms;
	}

	void MacStreamTest::CmacDescriptionTest()
	{
		CEX::Prng::CSPPrng rng;
		std::vector<byte> data = rng.GetBytes(rng.Next(100, 400));
		std::vector<byte> key = rng.GetBytes(32);
		std::vector<byte> iv = rng.GetBytes(16);
		CEX::Mac::CMAC mac(CEX::Enumeration::BlockCiphers::RHX);
		mac.Initialize(key, iv);
		std::vector<byte> c1(mac.MacSize());
		mac.ComputeMac(data, c1);

		CEX::Common::MacDescription mds(32, CEX::Enumeration::BlockCiphers::RHX, CEX::Enumeration::IVSizes::V128);
		CEX::Processing::MacStream mst(mds, CEX::Common::KeyParams(key, iv));
		CEX::IO::IByteStream* ms = new CEX::IO::MemoryStream(data);
		std::vector<byte> c2 = mst.ComputeMac(ms);
		delete ms;

		if (c1 != c2)
			throw std::string("MacStreamTest: CMAC code arrays are not equal!");
	}

	void MacStreamTest::HmacDescriptionTest()
	{
		CEX::Prng::CSPPrng rng;
		std::vector<byte> data = rng.GetBytes(rng.Next(100, 400));
		std::vector<byte> key = rng.GetBytes(64);
		CEX::Mac::HMAC mac(CEX::Enumeration::Digests::SHA256);
		mac.Initialize(key);
		std::vector<byte> c1(mac.MacSize());
		mac.ComputeMac(data, c1);

		CEX::Common::MacDescription mds(64, CEX::Enumeration::Digests::SHA256);
		CEX::Processing::MacStream mst(mds, CEX::Common::KeyParams(key));
		CEX::IO::IByteStream* ms = new CEX::IO::MemoryStream(data);
		std::vector<byte> c2 = mst.ComputeMac(ms);
		delete ms;

		if (c1 != c2)
			throw std::string("MacStreamTest: HMAC code arrays are not equal!");
	}

	void MacStreamTest::VmacDescriptionTest()
	{
		CEX::Prng::CSPPrng rng;
		std::vector<byte> data = rng.GetBytes(rng.Next(100, 400));
		std::vector<byte> key = rng.GetBytes(64);
		std::vector<byte> iv = rng.GetBytes(16);
		CEX::Mac::VMAC mac;
		mac.Initialize(key, iv);
		std::vector<byte> c1(mac.MacSize());
		mac.ComputeMac(data, c1);

		CEX::Common::MacDescription mds(64, 16);
		CEX::Processing::MacStream mst(mds, CEX::Common::KeyParams(key, iv));
		CEX::IO::IByteStream* ms = new CEX::IO::MemoryStream(data);
		std::vector<byte> c2 = mst.ComputeMac(ms);

		if (c1 != c2)
			throw std::string("MacStreamTest: VMAC code arrays are not equal!");
	}

	void MacStreamTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}