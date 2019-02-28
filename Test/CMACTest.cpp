#include "CMACTest.h"
#include "../CEX/CMAC.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Enumeration::BlockCiphers;
	using Enumeration::BlockCipherExtensions;
	using Exception::CryptoMacException;
	using Mac::CMAC;
	using Utility::IntegerTools;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string CMACTest::CLASSNAME = "CMACTest";
	const std::string CMACTest::DESCRIPTION = "CMAC Known Answer Test Vectors for 128/192/256 bit Keys.";
	const std::string CMACTest::SUCCESS = "SUCCESS! All CMAC tests have executed succesfully.";

	CMACTest::CMACTest()
		:
		m_expected(0),
		m_key(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	CMACTest::~CMACTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
	}

	const std::string CMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CMACTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("CMACTest: Passed CMAC exception handling tests.."));

			// standard AES versions
			CMAC* cmacaes = new CMAC(BlockCiphers::AES);
			// 128-bit key
			Kat(cmacaes, m_key[0], m_message[0], m_expected[0]);
			Kat(cmacaes, m_key[0], m_message[1], m_expected[1]);
			Kat(cmacaes, m_key[0], m_message[2], m_expected[2]);
			Kat(cmacaes, m_key[0], m_message[3], m_expected[3]);
			OnProgress(std::string("CMACTest: Passed CMAC 128 bit key vector tests.."));
			// 192-bit key
			Kat(cmacaes, m_key[1], m_message[0], m_expected[4]);
			Kat(cmacaes, m_key[1], m_message[1], m_expected[5]);
			Kat(cmacaes, m_key[1], m_message[2], m_expected[6]);
			Kat(cmacaes, m_key[1], m_message[3], m_expected[7]);
			OnProgress(std::string("CMACTest: Passed CMAC 192 bit key vector tests.."));
			// 256-bit key
			Kat(cmacaes, m_key[2], m_message[0], m_expected[8]);
			Kat(cmacaes, m_key[2], m_message[1], m_expected[9]);
			Kat(cmacaes, m_key[2], m_message[2], m_expected[10]);
			Kat(cmacaes, m_key[2], m_message[3], m_expected[11]);
			OnProgress(std::string("CMACTest: Passed CMAC 256 bit key vector tests.."));

			Params(cmacaes);
			OnProgress(std::string("CMACTest: Passed CMAC initialization parameters tests.."));

			Stress(cmacaes);
			OnProgress(std::string("CMACTest: Passed CMAC stress tests.."));

			delete cmacaes;

			CMAC* cmacahxh256 = new CMAC(BlockCiphers::RHXH256);
			// ahx extended with HKDF(HMAC(SHA2-256))
			Kat(cmacahxh256, m_key[2], m_message[0], m_expected[12]);
			Kat(cmacahxh256, m_key[2], m_message[1], m_expected[13]);
			Kat(cmacahxh256, m_key[2], m_message[2], m_expected[14]);
			Kat(cmacahxh256, m_key[2], m_message[3], m_expected[15]);
			OnProgress(std::string("CMACTest: Passed CMAC 256 bit key vector tests.."));

			delete cmacahxh256;

			CMAC* cmacahxs256 = new CMAC(BlockCiphers::RHXS256);
			// ahx extended with cSHAKE-256
			Kat(cmacahxs256, m_key[2], m_message[0], m_expected[16]);
			Kat(cmacahxs256, m_key[2], m_message[1], m_expected[17]);
			Kat(cmacahxs256, m_key[2], m_message[2], m_expected[18]);
			Kat(cmacahxs256, m_key[2], m_message[3], m_expected[19]);
			OnProgress(std::string("CMACTest: Passed CMAC 256 bit key vector tests.."));

			delete cmacahxs256;

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

	void CMACTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid cipher choice
			CMAC gen(BlockCiphers::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE1"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
		// test constructor -2
		try
		{
			// invalid cipher choice
			CMAC gen(nullptr);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE2"));
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
			CMAC gen(BlockCiphers::AES);
			// invalid key size
			std::vector<byte> k(1);
			SymmetricKey kp(k);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE3"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test finalize state -1
		try
		{
			CMAC gen(BlockCiphers::AES);
			std::vector<byte> code(16);
			// generator was not initialized
			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE4"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CMACTest::Initialize()
	{
		const std::vector<std::string> keys =
		{
			std::string("2B7E151628AED2A6ABF7158809CF4F3C"),
			std::string("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"),
			std::string("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
		};
		HexConverter::Decode(keys, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string(""),
			std::string("6BC1BEE22E409F96E93D7E117393172A"),
			std::string("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411"),
			std::string("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710")
		};
		HexConverter::Decode(message, 4, m_message);

		const std::vector<std::string> expected =
		{
			// aes-128
			std::string("BB1D6929E95937287FA37D129B756746"),
			std::string("070A16B46B4D4144F79BDD9DD04A287C"),
			std::string("DFA66747DE9AE63030CA32611497C827"),
			std::string("51F0BEBF7E3B9D92FC49741779363CFE"),
			// aes-192
			std::string("D17DDF46ADAACDE531CAC483DE7A9367"),
			std::string("9E99A7BF31E710900662F65E617C5184"),
			std::string("8A1DE5BE2EB31AAD089A82E6EE908B0E"),
			std::string("A1D5DF0EED790F794D77589659F39A11"),
			// aes-256
			std::string("028962F61B7BF89EFC6B551F4667D983"),
			std::string("28A7023F452E8F82BD4BF28D8C37C35C"),
			std::string("AAF3D8F1DE5640C232F5B169B9C911E6"),
			std::string("E1992190549F6ED5696A2C056C315410"),
			// ahx-hkdf-256
			std::string("7EA1E586F7BD1B08BFD9D6CE8D680674"),
			std::string("42669E1F401DF5552AE4EB4671B92461"),
			std::string("68771A43CD5F1260D67DC1997DBEC07D"),
			std::string("02C0D13BC9E328B62D6A7D04306AF494"),
			// ahx-cshake-256
			std::string("ADC40471C8F8EFB1F7880AA52192166C"),
			std::string("4C1CA1BF5505FEFDA00B8EE3FE1A6A33"),
			std::string("6F3C182707DC300E0D75690AFD71EECE"),
			std::string("BC9DE1B74889FB483A29EB941291FD9A")
		};
		HexConverter::Decode(expected, 20, m_expected);
	}

	void CMACTest::Kat(IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> code(16);
		SymmetricKey kp(Key);

		Generator->Initialize(kp);
		Generator->Update(Message, 0, Message.size());
		Generator->Finalize(code, 0);

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Expected values don't match! -CK1"));
		}
	}

	void CMACTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void CMACTest::Params(IMac* Generator)
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
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(msg, 0, msg.size(), rnd);
			SymmetricKey kp(key);

			// generate the mac
			Generator->Initialize(kp);
			Generator->Compute(msg, otp1);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Compute(msg, otp2);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -CP1"));
			}
		}
	}

	void CMACTest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> msg;
		std::vector<byte> otp(Generator->TagSize());
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				msg.resize(MSGLEN);
				IntegerTools::Fill(key, 0, key.size(), rnd);
				IntegerTools::Fill(msg, 0, msg.size(), rnd);
				SymmetricKey kp(key);

				// generate with the kdf
				Generator->Initialize(kp);
				Generator->Compute(msg, otp);
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -CS1"));
			}
		}
	}
}
