#include "MacStreamTest.h"
#include "../CEX/BlockCiphers.h"
#include "../CEX/CMAC.h"
#include "../CEX/HMAC.h"
#include "../CEX/IByteStream.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/MacStream.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/RHX.h"
#include "../CEX/SHA2256.h"

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

	void MacStreamTest::EvaluateCMAC()
	{
		Prng::SecureRandom rnd;
		std::vector<uint8_t> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);
		std::vector<uint8_t> key = rnd.Generate(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::CMAC* gen = new Mac::CMAC(Enumeration::BlockCiphers::AES);
		size_t macSze = gen->TagSize();
		std::vector<uint8_t> hash1(macSze);
		gen->Initialize(kp);
		gen->Compute(data, hash1);
		gen->Reset();

		// test stream method
		std::vector<uint8_t> hash2(macSze);
		Processing::MacStream ds(gen);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateCMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}

		// test uint8_t access method
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
		std::vector<uint8_t> data(rnd.NextUInt32(1000, 100));
		rnd.Generate(data);
		std::vector<uint8_t> key = rnd.Generate(32);
		SymmetricKey kp(key);

		// digest instance for baseline
		Mac::HMAC* gen = new Mac::HMAC(Enumeration::SHA2Digests::SHA2256);
		size_t macSze = gen->TagSize();
		std::vector<uint8_t> hash1(macSze);
		gen->Initialize(kp);
		gen->Compute(data, hash1);
		gen->Reset();

		// test stream method
		std::vector<uint8_t> hash2(macSze);
		Processing::MacStream ds(gen);
		ds.Initialize(kp);
		IO::IByteStream* ms = new IO::MemoryStream(data);
		hash2 = ds.Compute(ms);

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateHMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}

		// test uint8_t access method
		ds.Initialize(kp);
		hash2 = ds.Compute(data, 0, data.size());

		if (hash1 != hash2)
		{
			throw TestException(std::string("EvaluateHMAC"), gen->Name(), std::string("Expected hash is not equal!"));
		}
	}

	void MacStreamTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
