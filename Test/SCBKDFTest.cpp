#include "SCBKDFTest.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SCBKDF.h"
#include "../CEX/SymmetricKeySize.h"

namespace Test
{
	using Exception::CryptoKdfException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;
	using Kdf::SCBKDF;
	using Cipher::SymmetricKeySize;

	const std::string SCBKDFTest::CLASSNAME = "SCBKDFTest";
	const std::string SCBKDFTest::DESCRIPTION = "SCBKDF Known Answer Tests";
	const std::string SCBKDFTest::SUCCESS = "SUCCESS! All SCBKDF tests have executed succesfully.";

	SCBKDFTest::SCBKDFTest()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent()
	{
		Initialize();
	}

	SCBKDFTest::~SCBKDFTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
	}

	const std::string SCBKDFTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SCBKDFTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SCBKDFTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("SCBKDFTest: Passed SCBKDF exception handling tests.."));

			SCBKDF* gen128 = new SCBKDF(ShakeModes::SHAKE128);
			Kat(gen128, m_key[0], m_expected[0]);
			OnProgress(std::string("SCBKDFTest: Passed SCBKDF128 KAT tests.."));

			SCBKDF* gen256 = new SCBKDF(ShakeModes::SHAKE256);
			Kat(gen256, m_key[1], m_expected[1]);
			OnProgress(std::string("SCBKDFTest: Passed SCBKDF256 KAT tests.."));

			SCBKDF* gen512 = new SCBKDF(ShakeModes::SHAKE512);
			Kat(gen512, m_key[2], m_expected[2]);
			OnProgress(std::string("SCBKDFTest: Passed SCBKDF512 KAT tests.."));

			Params(gen128);
			Params(gen256);
			Params(gen512);
			OnProgress(std::string("SCBKDFTest: Passed initialization tests.."));

			Stress(gen128);
			Stress(gen256);
			Stress(gen512);
			OnProgress(std::string("SCBKDFTest: Passed stress tests.."));

			delete gen128;
			delete gen256;
			delete gen512;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoKdfException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void SCBKDFTest::Exception()
	{
		// test constructor
		try
		{
			// invalid digest choice
			SCBKDF gen(ShakeModes::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test generator state -1
		try
		{
			SCBKDF gen(ShakeModes::SHAKE128);
			std::vector<uint8_t> otp(32);
			// generator was not initialized
			gen.Generate(otp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoKdfException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SCBKDFTest::Kat(IKdf* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Expected)
	{
		std::vector<uint8_t> otp(Expected.size());
		SymmetricKey kp(Key);

		Generator->Initialize(kp);
		Generator->Generate(otp);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Output does not match the known answer! -SK1"));
		}
	}

	void SCBKDFTest::Initialize()
	{
		/*lint -save -e417 */
		/*lint -save -e146 */
		HexConverter::Decode(std::string("456D61696C205369676E6174757265"), m_custom);

		const std::vector<std::string> keys =
		{
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		};
		HexConverter::Decode(keys, 4, m_key);

		// original vectors
		const std::vector<std::string> expected =
		{
			std::string("C4C337D8D0F645D3B471194CCE3C824B"),
			std::string("73B392E157BAAE599384851B7C7188F4C1280EFD5527341951C4A8DA2E5564AA"),
			std::string("4EE8D73A28FC689385CA402A5C5BD2560B4F5463F031822E5812828117BD18D977A22D2D3EBB33374AE6B084BCEB0604B314A0AF21EE0A758853BDA5FFE776A5"),
			std::string("A2FD766FECF3FBABCEE97539864E78B827237A34EACED93A42F5D060F2AD115D6581F62D864D9F45ECE697A20C9928C83E8E1E5BEC4272CB9786D7D518C4FE9F"
				"7224BC8DEB5B014F05558A0CB91A0E49A531EE364029B5128B7522FF1D7DEDFAA12BD6A38B853AAA486A3E2AB3E869EA8E1A2A16E44E3E2F26E0342664242389")
		};
		HexConverter::Decode(expected, 4, m_expected);
		/*lint -restore */
	}

	void SCBKDFTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void SCBKDFTest::Params(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> otp1;
		std::vector<uint8_t> otp2;
		std::vector<uint8_t> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp1.reserve(MAXM_ALLOC);
		otp2.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			otp1.resize(OTPLEN);
			otp2.resize(OTPLEN);
			rnd.Generate(key, 0, key.size());

			// generate with the kdf
			SymmetricKey kp(key);
			Generator->Initialize(kp);
			Generator->Generate(otp1, 0, OTPLEN);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Generate(otp2, 0, OTPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -HR1"));
			}
		}
	}

	void SCBKDFTest::Stress(IKdf* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> otp;
		SecureRandom rnd;
		size_t i;

		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				otp.resize(OTPLEN);
				rnd.Generate(key, 0, key.size());

				// generate with the kdf
				SymmetricKey kp(key);
				Generator->Initialize(kp);
				Generator->Generate(otp, 0, OTPLEN);
				Generator->Reset();
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (const std::exception&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
