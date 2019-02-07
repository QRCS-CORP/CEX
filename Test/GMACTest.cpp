#include "GMACTest.h"
#include "../CEX/GMAC.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Enumeration::BlockCiphers;
	using Exception::CryptoMacException;
	using Mac::GMAC;
	using Utility::IntegerTools;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string GMACTest::CLASSNAME = "GMACTest";
	const std::string GMACTest::DESCRIPTION = "GMAC MAC Generator Tests.";
	const std::string GMACTest::SUCCESS = "SUCCESS! GMAC tests have executed succesfully.";

	GMACTest::GMACTest()
		:
		m_expected(0),
		m_key(0),
		m_message(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	GMACTest::~GMACTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_nonce);
	}

	const std::string GMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &GMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string GMACTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("GMACTest: Passed GMAC exception handling tests.."));

			Kat(m_key[0], m_nonce[0], m_message[0], m_expected[0]);
			Kat(m_key[1], m_nonce[1], m_message[1], m_expected[1]);
			Kat(m_key[2], m_nonce[2], m_message[2], m_expected[2]);
			Kat(m_key[3], m_nonce[3], m_message[3], m_expected[3]);
			Kat(m_key[4], m_nonce[4], m_message[4], m_expected[4]);
			Kat(m_key[5], m_nonce[5], m_message[5], m_expected[5]);
			Kat(m_key[6], m_nonce[6], m_message[6], m_expected[6]);
			Kat(m_key[7], m_nonce[7], m_message[7], m_expected[7]);
			Kat(m_key[8], m_nonce[8], m_message[8], m_expected[8]);
			Kat(m_key[9], m_nonce[9], m_message[9], m_expected[9]);
			Kat(m_key[10], m_nonce[10], m_message[10], m_expected[10]);
			OnProgress(std::string("GMACTest: Passed GMAC known answer vector tests.."));

			GMAC* gen = new GMAC(BlockCiphers::AES);

			Params(gen);
			OnProgress(std::string("GMACTest: Passed GMAC initialization parameters tests.."));

			Stress(gen);
			OnProgress(std::string("GMACTest: Passed GMAC stress tests.."));

			delete gen;

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

	void GMACTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid cipher choice
			GMAC gen(BlockCiphers::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -GE1"));
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
			GMAC gen(nullptr);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -GE2"));
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
			GMAC gen(BlockCiphers::AES);
			// invalid key size
			std::vector<byte> k(1);
			SymmetricKey kp(k);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -GE3"));
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
			GMAC gen(BlockCiphers::AES);
			std::vector<byte> code(16);
			// generator was not initialized
			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -GE4"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void GMACTest::Initialize()
	{
		const std::vector<std::string> keys =
		{
			std::string("11754CD72AEC309BF52F7687212E8957"),
			std::string("272F16EDB81A7ABBEA887357A58C1917"),
			std::string("81B6844AAB6A568C4556A2EB7EAE752F"),
			std::string("CDE2F9A9B1A004165EF9DC981F18651B"),
			std::string("B01E45CC3088AABA9FA43D81D481823F"),
			std::string("77BE63708971C4E240D1CB79E8D77FEB"),
			std::string("BEA48AE4980D27F357611014D4486625"),
			std::string("99E3E8793E686E571D8285C564F75E2B"),
			std::string("C77ACD1B0918E87053CB3E51651E7013"),
			std::string("D0F1F4DEFA1E8C08B4B26D576392027C"),
			std::string("3CCE72D37933394A8CAC8A82DEADA8F0")
		};
		HexConverter::Decode(keys, 11, m_key);

		const std::vector<std::string> nonce =
		{
			std::string("3C819D9A9BED087615030B65"),
			std::string("794EC588176C703D3D2A7A07"),
			std::string("CE600F59618315A6829BEF4D"),
			std::string("29512C29566C7322E1E33E8E"),
			std::string("5A2C4A66468713456A4BD5E1"),
			std::string("E0E00F19FED7BA0136A797F3"),
			std::string("32BDDB5C3AA998A08556454C"),
			std::string("C2DD0AB868DA6AA8AD9C0D23"),
			std::string("39FF857A81745D10F718AC00"),
			std::string("42B4F01EB9F5A1EA5B1EB73B0FB0BAED54F387ECAA0393C7D7DFFC6AF50146ECC021ABF7EB9038D4303D91F8D741A11743166C0860208BCC02C6258FD9511A2FA626F96D60B72FCFF773AF4E88E7A923506E4916ECBD814651E9F445ADEF4AD6A6B6C7290CC13B956130EEF5B837C939FCAC0CBBCC9656CD75B13823EE5ACDAC"),
			std::string("AA2F0D676D705D9733C434E481972D4888129CF7EA55C66511B9C0D25A92A174B1E28AA072F27D4DE82302828955AADCB817C4907361869BD657B45FF4A6F323871987FCF9413B0702D46667380CD493ED24331A28B9CE5BBFA82D3A6E7679FCCE81254BA64ABCAD14FD18B22C560A9D2C1CD1D3C42DAC44C683EDF92ACED894")
		};
		HexConverter::Decode(nonce, 11, m_nonce);

		const std::vector<std::string> message =
		{
			std::string(""),
			std::string(""),
			std::string(""),
			std::string(""),
			std::string(""),
			std::string("7A43EC1D9C0A5A78A0B16533A6213CAB"),
			std::string("8A50B0B8C7654BCED884F7F3AFDA2EAD"),
			std::string("B668E42D4E444CA8B23CFDD95A9FEDD5178AA521144890B093733CF5CF22526C5917EE476541809AC6867A8C399309FC"),
			std::string("407992F82EA23B56875D9A3CB843CEB83FD27CB954F7C5534D58539FE96FB534502A1B38EA4FAC134DB0A42DE4BE1137"),
			std::string(""),
			std::string("5686B458E9C176F4DE8428D9EBD8E12F569D1C7595CF49A4B0654AB194409F86C0DD3FDB8EB18033BB4338C70F0B97D1")
		};
		HexConverter::Decode(message, 11, m_message);

		const std::vector<std::string> expected =
		{
			std::string("250327C674AAF477AEF2675748CF6971"),
			std::string("B6E6F197168F5049AEDA32DAFBDAEB"),
			std::string("89B43E9DBC1B4F597DBBC7655BB5"),
			std::string("2E58CE7DABD107C82759C66A75"),
			std::string("014280F944F53C681164B2FF"),
			std::string("209FCC8D3675ED938E9C7166709DD946"),
			std::string("8E0F6D8BF05FFEBE6F500EB1"),
			std::string("3F4FBA100EAF1F34B0BAADAAE9995D85"),
			std::string("2A5DC173285375DC82835876"),
			std::string("7AB49B57DDF5F62C427950111C5C4F0D"),
			std::string("A3A9444B21F330C3DF64C8B6")
		};
		HexConverter::Decode(expected, 11, m_expected);
	}

	void GMACTest::Kat(std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		GMAC gen(BlockCiphers::AES);
		SymmetricKey kp(Key, Nonce);
		std::vector<byte> code(gen.TagSize());

		gen.Initialize(kp);
		gen.Update(Message, 0, Message.size());
		gen.Finalize(code, 0);
		code.resize(Expected.size());

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), gen.Name(), std::string("Expected values don't match! -KK1"));
		}
	}

	void GMACTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void GMACTest::Params(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		std::vector<byte> nonce(ks.NonceSize());
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
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// generate the mac
			Generator->Initialize(kp);
			Generator->Compute(msg, otp1);
			Generator->Reset();
			// post-reset generation
			Generator->Initialize(kp);
			Generator->Compute(msg, otp2);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -GP1"));
			}
		}
	}

	void GMACTest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> msg;
		std::vector<byte> nonce(ks.NonceSize());
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
				IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
				SymmetricKey kp(key, nonce);

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
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -GS1"));
			}
		}
	}
}
