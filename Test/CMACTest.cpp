#include "CMACTest.h"
#include "../CEX/CMAC.h"
#include "../CEX/IntUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Enumeration::BlockCiphers;
	using Enumeration::BlockCipherExtensions;
	using Exception::CryptoMacException;
	using Mac::CMAC;
	using Utility::IntUtils;
	using Prng::SecureRandom;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;

	const std::string CMACTest::DESCRIPTION = "CMAC Known Answer Test Vectors for 128/192/256 bit Keys.";
	const std::string CMACTest::FAILURE = "FAILURE! ";
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
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_message);
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
			CMAC* cmacaes = new CMAC(BlockCiphers::Rijndael);
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

			CMAC* cmacahxh256 = new CMAC(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::HKDF256);
			// ahx extended with HKDF(HMAC(SHA2-256))
			Kat(cmacahxh256, m_key[2], m_message[0], m_expected[12]);
			Kat(cmacahxh256, m_key[2], m_message[1], m_expected[13]);
			Kat(cmacahxh256, m_key[2], m_message[2], m_expected[14]);
			Kat(cmacahxh256, m_key[2], m_message[3], m_expected[15]);
			OnProgress(std::string("CMACTest: Passed CMAC 256 bit key vector tests.."));

			delete cmacahxh256;

			CMAC* cmacahxs256 = new CMAC(BlockCiphers::AHX, Enumeration::BlockCipherExtensions::SHAKE256);
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
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void CMACTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid cipher choice
			CMAC mac(BlockCiphers::None);

			throw TestException(std::string("CMAC"), std::string("Exception: Exception handling failure! -CE1"));
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
			CMAC mac(nullptr);

			throw TestException(std::string("CMAC"), std::string("Exception: Exception handling failure! -CE2"));
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
			CMAC mac(BlockCiphers::Rijndael);
			// invalid key size
			std::vector<byte> k(1);
			SymmetricKey kp(k);
			mac.Initialize(kp);

			throw TestException(std::string("CMAC"), std::string("Exception: Exception handling failure! -CE3"));
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
			CMAC mac(BlockCiphers::Rijndael);
			std::vector<byte> code(16);
			// generator was not initialized
			mac.Finalize(code, 0);

			throw TestException(std::string("CMAC"), std::string("Exception: Exception handling failure! -CE4"));
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
			std::string("45A67A8612C3A2D091A32CB60421798C"),
			std::string("9DB96F23B87F70B1D0FF295C8C206021"),
			std::string("C34252CA83F0E314CFE2EF2347E4EDF3"),
			std::string("787E4B3223C623F3FFE9E822C9DF2541"),
			// ahx-cshake-256
			std::string("AF8933A9BB7DB64EF05BEA9907FC6924"),
			std::string("587A521C861B335C56EAD4330191E8B5"),
			std::string("617274BDE54A68037CF9E7A8744FCDEB"),
			std::string("4C453976B339A4EC51A1E70E6816991D")
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
			throw TestException(std::string("CMAC"), std::string("KAT: Expected values don't match! -CK1"));
		}
	}

	void CMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void CMACTest::Params(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		std::vector<byte> otp1(Generator->MacSize());
		std::vector<byte> otp2(Generator->MacSize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			msg.resize(MSGLEN);
			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(msg, 0, msg.size(), rnd);
			SymmetricKey kp(key);

			// generate the mac
			Generator->Initialize(kp);
			Generator->Compute(msg, otp1);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Compute(msg, otp2);

			if (otp1 != otp2)
			{
				throw TestException(std::string("CMAC"), std::string("Reset: Returns a different array after reset! -CP1"));
			}
		}
	}

	void CMACTest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[1];
		std::vector<byte> msg;
		std::vector<byte> otp(Generator->MacSize());
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
				IntUtils::Fill(key, 0, key.size(), rnd);
				IntUtils::Fill(msg, 0, msg.size(), rnd);
				SymmetricKey kp(key);

				// generate with the kdf
				Generator->Initialize(kp);
				Generator->Compute(msg, otp);
				Generator->Reset();
			}
			catch (...)
			{
				throw TestException(std::string("CMAC"), std::string("Stress: The generator has thrown an exception! -CS1"));
			}
		}
	}
}
