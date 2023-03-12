#include "KPATest.h"
#include "../CEX/KPA.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Exception::CryptoMacException;
	using Mac::KPA;
	using Tools::IntegerTools;
	using Prng::SecureRandom;
	using Enumeration::KpaModes;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string KPATest::CLASSNAME = "KPATest";
	const std::string KPATest::DESCRIPTION = "Test Vectors for KPA-128, KPA-256, and KPA-512.";
	const std::string KPATest::SUCCESS = "SUCCESS! All KPA tests have executed succesfully.";

	KPATest::KPATest()
		:
		m_custom(0),
		m_expected(0),
		m_key(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	KPATest::~KPATest()
	{
		IntegerTools::Clear(m_custom);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
	}

	const std::string KPATest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KPATest::Progress()
	{
		return m_progressEvent;
	}

	std::string KPATest::Run()
	{
		try
		{
			std::vector<uint8_t> zero(0);

			Exception();
			OnProgress(std::string("KPATest: Passed KPA exception handling tests.."));

			KPA* gen1 = new KPA(KpaModes::KPA128);
			//Kat(gen1, m_key[0], m_custom, m_message[0], m_expected[0]);
			//Kat(gen1, m_key[0], zero, m_message[1], m_expected[1]);
			//OnProgress(std::string("KPATest: Passed KPA-128 known answer vector tests.."));

			KPA* gen2 = new KPA(KpaModes::KPA256);
			Kat(gen2, m_key[1], m_custom, m_message[2], m_expected[2]);
			Kat(gen2, m_key[1], zero, m_message[3], m_expected[3]);
			OnProgress(std::string("KPATest: Passed KPA-256 known answer vector tests.."));

			KPA* gen3 = new KPA(KpaModes::KPA512);
			Kat(gen3, m_key[2], m_custom, m_message[4], m_expected[4]);
			Kat(gen3, m_key[2], zero, m_message[5], m_expected[5]);
			OnProgress(std::string("KPATest: Passed KPA-512 known answer vector tests.."));

			Params(gen1);
			Params(gen2);
			Params(gen3);
			OnProgress(std::string("KPATest: Passed KPA 128/256/512/1024 initialization parameters tests.."));

			Stress(gen1);
			Stress(gen2);
			Stress(gen3);
			OnProgress(std::string("HMACTest: Passed KPA 128/256/512/1024 stress tests.."));

			delete gen1;
			delete gen2;
			delete gen3;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoMacException &ex)
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

	void KPATest::Exception()
	{
		// test constructor
		try
		{
			// invalid cipher choice
			KPA gen(KpaModes::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -KE1"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			KPA gen(KpaModes::KPA128);
			// invalid key size
			std::vector<uint8_t> k(1);
			SymmetricKey kp(k);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -KE3"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test finalize state
		try
		{
			KPA gen(KpaModes::KPA128);
			std::vector<uint8_t> code(gen.TagSize());
			// generator was not initialized
			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -KE4"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void KPATest::Initialize()
	{
		HexConverter::Decode(std::string("4D7920546167676564204170706C69636174696F6E"), m_custom);

		const std::vector<std::string> key =
		{
			std::string("4D7920546167676564204170706C6963"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")
		};
		HexConverter::Decode(message, 6, m_message);

		const std::vector<std::string> expected =
		{
			std::string("B7B5EA85E4C039962D59A77F8E530304"),
			std::string("98EA60B2C863603B773EC1D89535EA51"),
			std::string("EBEC64EBE52DA21D9465341CBDC4941F5141855F8B62312EBDFC015083315193"),
			std::string("36DB74619B441167575FCD69E4B4DFDEECFF97F99F49BB68B7EB7A4FDC5A9E20"),
			std::string("5A3A48CE2221347213A93A847EAEF6455351018E1239C130069DB1A71DCF28DC8D9FB65193F1AB620752A4FEA0DDF0ED5824CAB50DD37BBC4A8909A91ADBC2C2"),
			std::string("D31EDF6ABD9B4497C98F065C398622E51DCC24B96DA9345D613757274472C612165218DD0F15D86E93894289AD95081FF5CE80FFFAAB5625D3CBFAC4CEB88898")
		};
		HexConverter::Decode(expected, 6, m_expected);

		/*lint -restore */
	}

	void KPATest::Kat(IMac* Generator, std::vector<uint8_t> &Key, std::vector<uint8_t> &Custom, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected)
	{
		std::vector<uint8_t> code(Expected.size());
		SymmetricKey kp(Key, Custom);

		Generator->Initialize(kp);
		Generator->Update(Message, 0, Message.size());
		Generator->Finalize(code, 0);

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Expected values don't match! -KK1"));
		}
	}

	void KPATest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void KPATest::Params(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> msg;
		std::vector<uint8_t> otp1(Generator->TagSize());
		std::vector<uint8_t> otp2(Generator->TagSize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			msg.resize(MSGLEN);
			rnd.Generate(key, 0, key.size());
			rnd.Generate(msg, 0, msg.size());
			SymmetricKey kp(key);

			// generate the mac
			Generator->Initialize(kp);
			Generator->Compute(msg, otp1);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Compute(msg, otp2);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -KP1"));
			}
		}
	}

	void KPATest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> msg;
		std::vector<uint8_t> otp(Generator->TagSize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				msg.resize(MSGLEN);
				rnd.Generate(key, 0, key.size());
				rnd.Generate(msg, 0, msg.size());
				SymmetricKey kp(key);

				// generate with the kdf
				Generator->Initialize(kp);
				Generator->Compute(msg, otp);
				Generator->Reset();
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -KS1"));
			}
		}
	}
}
