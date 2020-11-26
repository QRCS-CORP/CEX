#include "KMACTest.h"
#include "../CEX/Keccak.h"
#include "../CEX/KMAC.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Exception::CryptoMacException;
	using Digest::Keccak;
	using Mac::KMAC;
	using Tools::IntegerTools;
	using Prng::SecureRandom;
	using Enumeration::KmacModes;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string KMACTest::CLASSNAME = "KMACTest";
	const std::string KMACTest::DESCRIPTION = "SP800-185 Test Vectors for KMAC-128 and KMAC-256.";
	const std::string KMACTest::SUCCESS = "SUCCESS! All KMAC tests have executed succesfully.";

	KMACTest::KMACTest()
		:
		m_custom(0),
		m_expected(0),
		m_key(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	KMACTest::~KMACTest()
	{
		IntegerTools::Clear(m_custom);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
	}

	const std::string KMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string KMACTest::Run()
	{
		try
		{
			Ancillary();
			OnProgress(std::string("KMACTest: Passed the KMAC compact functions tests.."));

			Exception();
			OnProgress(std::string("KMACTest: Passed KMAC exception handling tests.."));

			KMAC* gen1 = new KMAC(KmacModes::KMAC128);
			Kat(gen1, m_key[0], m_custom[0], m_message[0], m_expected[0]);
			Kat(gen1, m_key[0], m_custom[1], m_message[0], m_expected[1]);
			Kat(gen1, m_key[0], m_custom[1], m_message[1], m_expected[2]);
			OnProgress(std::string("KMACTest: Passed KMAC-128 known answer vector tests.."));

			KMAC* gen2 = new KMAC(KmacModes::KMAC256);
			Kat(gen2, m_key[0], m_custom[1], m_message[0], m_expected[3]);
			Kat(gen2, m_key[0], m_custom[0], m_message[1], m_expected[4]);
			Kat(gen2, m_key[0], m_custom[1], m_message[1], m_expected[5]);
			OnProgress(std::string("KMACTest: Passed KMAC-256 known answer vector tests.."));

			KMAC* gen3 = new KMAC(KmacModes::KMAC512);
			Kat(gen3, m_key[1], m_custom[1], m_message[2], m_expected[6]);
			Kat(gen3, m_key[2], m_custom[3], m_message[2], m_expected[7]);
			Kat(gen3, m_key[1], m_custom[2], m_message[3], m_expected[8]);
			OnProgress(std::string("KMACTest: Passed KMAC-512 known answer vector tests.."));

			KMAC* gen4 = new KMAC(KmacModes::KMAC1024);
			Kat(gen4, m_key[1], m_custom[3], m_message[2], m_expected[9]);
			Kat(gen4, m_key[2], m_custom[2], m_message[3], m_expected[10]);
			Kat(gen4, m_key[2], m_custom[3], m_message[2], m_expected[11]);
			OnProgress(std::string("KMACTest: Passed KMAC-1024 known answer vector tests.."));

			Params(gen1);
			Params(gen2);
			Params(gen3);
			Params(gen4);
			OnProgress(std::string("KMACTest: Passed KMAC 128/256/512/1024 initialization parameters tests.."));

			Stress(gen1);
			Stress(gen2);
			Stress(gen3);
			Stress(gen4);
			OnProgress(std::string("HMACTest: Passed KMAC 128/256/512/1024 stress tests.."));

			delete gen1;
			delete gen2;
			delete gen3;
			delete gen4;

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

	void KMACTest::Ancillary()
	{
		std::vector<byte> otp(0);

		// KMAC-128

		otp.resize(m_expected[0].size());
		Keccak::MACR24P1600(m_key[0], m_custom[0], m_message[0], 0, m_message[0].size(), otp, Keccak::KECCAK128_RATE_SIZE);

		if (otp != m_expected[0])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA1"));
		}

		otp.resize(m_expected[1].size());
		Keccak::MACR24P1600(m_key[0], m_custom[1], m_message[0], 0, m_message[0].size(), otp, Keccak::KECCAK128_RATE_SIZE);

		if (otp != m_expected[1])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA2"));
		}

		otp.resize(m_expected[2].size());
		Keccak::MACR24P1600(m_key[0], m_custom[1], m_message[1], 0, m_message[1].size(), otp, Keccak::KECCAK128_RATE_SIZE);

		if (otp != m_expected[2])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA3"));
		}

		// KMAC-256

		otp.resize(m_expected[3].size());
		Keccak::MACR24P1600(m_key[0], m_custom[1], m_message[0], 0, m_message[0].size(), otp, Keccak::KECCAK256_RATE_SIZE);

		if (otp != m_expected[3])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA4"));
		}

		otp.resize(m_expected[4].size());
		Keccak::MACR24P1600(m_key[0], m_custom[0], m_message[1], 0, m_message[1].size(), otp, Keccak::KECCAK256_RATE_SIZE);

		if (otp != m_expected[4])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA5"));
		}

		otp.resize(m_expected[5].size());
		Keccak::MACR24P1600(m_key[0], m_custom[1], m_message[1], 0, m_message[1].size(), otp, Keccak::KECCAK256_RATE_SIZE);

		if (otp != m_expected[5])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA6"));
		}

		// KMAC-512

		otp.resize(m_expected[6].size());
		Keccak::MACR24P1600(m_key[1], m_custom[1], m_message[2], 0, m_message[2].size(), otp, Keccak::KECCAK512_RATE_SIZE);

		if (otp != m_expected[6])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA7"));
		}

		otp.resize(m_expected[7].size());
		Keccak::MACR24P1600(m_key[2], m_custom[3], m_message[2], 0, m_message[2].size(), otp, Keccak::KECCAK512_RATE_SIZE);

		if (otp != m_expected[7])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA8"));
		}

		otp.resize(m_expected[8].size());
		Keccak::MACR24P1600(m_key[1], m_custom[2], m_message[3], 0, m_message[3].size(), otp, Keccak::KECCAK512_RATE_SIZE);

		if (otp != m_expected[8])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR24P1600"), std::string("Expected values don't match! -KA9"));
		}

		// KMAC-1024

		otp.resize(m_expected[9].size());
		Keccak::MACR48P1600(m_key[1], m_custom[3], m_message[2], 0, m_message[2].size(), otp, Keccak::KECCAK1024_RATE_SIZE);

		if (otp != m_expected[9])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR48P1600"), std::string("Expected values don't match! -KA10"));
		}

		otp.resize(m_expected[10].size());
		Keccak::MACR48P1600(m_key[2], m_custom[2], m_message[3], 0, m_message[3].size(), otp, Keccak::KECCAK1024_RATE_SIZE);

		if (otp != m_expected[10])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR48P1600"), std::string("Expected values don't match! -KA11"));
		}

		otp.resize(m_expected[11].size());
		Keccak::MACR48P1600(m_key[2], m_custom[3], m_message[2], 0, m_message[2].size(), otp, Keccak::KECCAK1024_RATE_SIZE);

		if (otp != m_expected[11])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR48P1600"), std::string("Expected values don't match! -KA12"));
		}
	}

	void KMACTest::Exception()
	{
		// test constructor
		try
		{
			// invalid cipher choice
			KMAC gen(KmacModes::None);

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
			KMAC gen(KmacModes::KMAC128);
			// invalid key size
			std::vector<byte> k(1);
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
			KMAC gen(KmacModes::KMAC128);
			std::vector<byte> code(gen.TagSize());
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

	void KMACTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */  // k1,c1,m2,e6	k2,c3,m2,e7		k1,c2,m3,e8

		const std::vector<std::string> key =
		{
			std::string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"),
			std::string("4D7920546167676564204170706C69636174696F6E"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> custom =
		{
			std::string(""),
			std::string("4D7920546167676564204170706C69636174696F6E"),
			std::string("4D7920546167676564204170706C69636174696F6E4D7920546167676564204170706C69636174696F6E"),
			std::string("4D7920546167676564204170706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D7920")
		};
		HexConverter::Decode(custom, 4, m_custom);

		const std::vector<std::string> message =
		{
			std::string("00010203"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7"),
			std::string("4D7920546167676564204170706C69636174696F6E4D7920546167676564204170706C69636174696F6E"),
			std::string("4D7920546167676564204170706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D"
				"7920546167676564204170706C69636174696F6E")
		};
		HexConverter::Decode(message, 4, m_message);

		const std::vector<std::string> expected =
		{
			std::string("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"),
			std::string("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"),
			std::string("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"),
			std::string("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
			std::string("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"),
			std::string("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"),
			std::string("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8"),
			std::string("6535FB96EAB4F831D801E6C3C6E71755F4A56E8E711D376DDC564F5C6DACB8B591EEF0503F433872B401FCEF8F05DA42FB950176C10FDB59395273FB9EDA39B8"),
			std::string("7BA4F7EE765960E6DA15D2CB51775DBA3E7B9279E5740469EF9FFD04C52460919A99BEE5BFDA27163E2729A8E3B663BD963EF067C7CCABDE6F6EFFF9093E2A2F"),
			std::string("12D90F6CD4C80C8AD5F57272C9A0D3945EF47BB2215BCE0BA880ACC41E3A676627AFE2F223A7CD6AFA09CA428207E71077B36A4E5A0E49F8973543650F941F17"
				"568F6171A7087C76480CAECB8C5E44F177618BE91A760EDBC5274558C2C94C928A925B662E9137C856764E74B5A2C4A42160BCF88E73D42482A279225C9D29D9"),
			std::string("9D9877C44C1DA8B31587044FE89D294506420FAE7846F398920220491EBDB456BF3AF03E79590C89AD11E1BA8CFDDCD40A7B37425AB0F9A8ADAE64A67A0DB171"
				"29EAF27949BAE84C93A69B1496FDCC4FCF889E2F74BC58A7186B0503F422321036E8E5667BA3000938262B213277831A0002B967F0EA702BFF78FE59A6267820"),
			std::string("539B65F7041A350B875F844E1C2EC97CC8DC1B4198C401EC212BF750D5EF0BE3C0617EACDCDB26A5EECB21AB1D1C23C26018E694840939D49BCC3D0AAF476974"
				"061951A9465C1E6CDA4D7643F20FCC21DCF2E7CB17A4337B39C83405A71FCB2573504248C603E2AD4304F17F543FD24777694DE9B1CD69F3F58DDBD5E57B567D"),
		};
		HexConverter::Decode(expected, 12, m_expected);

		/*lint -restore */
	}

	void KMACTest::Kat(IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Custom, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> code(Expected.size());
		SymmetricKey kp(Key, Custom);

		Generator->Initialize(kp);
		Generator->Update(Message, 0, Message.size());
		Generator->Finalize(code, 0);

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Expected values don't match! -KK1"));
		}
	}

	void KMACTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void KMACTest::Params(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		std::vector<byte> otp1(Generator->TagSize());
		std::vector<byte> otp2(Generator->TagSize());
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

	void KMACTest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		std::vector<byte> otp(Generator->TagSize());
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
