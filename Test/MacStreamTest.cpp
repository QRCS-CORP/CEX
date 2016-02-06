#include "MacStreamTest.h"

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
			delete sha;
			delete hmac;
			OnProgress("Passed MacStream HMAC comparison tests..");

			key.resize(32);
			iv.resize(16);
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CMAC* cmac = new CMAC(eng, 128);
			cmac->Initialize(key, iv);
			CompareOutput(cmac);
			delete eng;
			delete cmac;
			OnProgress("Passed MacStream CMAC comparison tests..");

			iv.resize(32);
			rnd.GetBytes(iv);
			VMAC* vmac = new VMAC();
			vmac->Initialize(key, iv);
			CompareOutput(vmac);
			delete vmac;
			OnProgress("Passed MacStream VMAC comparison tests..");

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
	}

	void MacStreamTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}