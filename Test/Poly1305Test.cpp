#include "Poly1305Test.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Poly1305.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Mac::CryptoMacException;
	using Utility::IntegerTools;
	using Mac::Poly1305;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string Poly1305Test::CLASSNAME = "Poly1305Test";
	const std::string Poly1305Test::DESCRIPTION = "Poly1305 MAC Generator Tests.";
	const std::string Poly1305Test::SUCCESS = "SUCCESS! Poly1305 tests have executed succesfully.";

	Poly1305Test::Poly1305Test()
		:
		m_expected(0),
		m_key(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	Poly1305Test::~Poly1305Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
	}

	const std::string Poly1305Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &Poly1305Test::Progress()
	{
		return m_progressEvent;
	}

	std::string Poly1305Test::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("Poly1305Test: Passed Poly1305 exception handling tests.."));

			Poly1305* gen = new Poly1305();
			Kat(gen, m_key[0], m_message[0], m_expected[0]);
			Kat(gen, m_key[1], m_message[1], m_expected[1]);
			Kat(gen, m_key[2], m_message[2], m_expected[2]);
			Kat(gen, m_key[3], m_message[3], m_expected[3]);
			Kat(gen, m_key[4], m_message[4], m_expected[4]);
			Kat(gen, m_key[5], m_message[5], m_expected[5]);
			Kat(gen, m_key[6], m_message[6], m_expected[6]);
			Kat(gen, m_key[7], m_message[7], m_expected[7]);
			Kat(gen, m_key[8], m_message[8], m_expected[8]);
			Kat(gen, m_key[9], m_message[9], m_expected[9]);
			Kat(gen, m_key[10], m_message[10], m_expected[10]);
			Kat(gen, m_key[11], m_message[11], m_expected[11]);
			Kat(gen, m_key[12], m_message[12], m_expected[12]);
			Kat(gen, m_key[13], m_message[13], m_expected[13]);
			Kat(gen, m_key[14], m_message[14], m_expected[14]);
			Kat(gen, m_key[15], m_message[15], m_expected[15]);
			Kat(gen, m_key[16], m_message[16], m_expected[16]);
			Kat(gen, m_key[17], m_message[17], m_expected[17]);
			Kat(gen, m_key[18], m_message[18], m_expected[18]);
			Kat(gen, m_key[19], m_message[19], m_expected[19]);
			OnProgress(std::string("Poly1305Test: Passed Poly1305 known answer vector tests.."));

			Params(gen);
			OnProgress(std::string("Poly1305Test: Passed Poly1305 initialization parameters tests.."));

			Stress(gen);
			OnProgress(std::string("Poly1305Test: Passed Poly1305stress tests.."));

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

	void Poly1305Test::Exception()
	{
		Poly1305 gen;
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[0];

		// test initialization key input-size
		try
		{
			std::vector<byte> key(ks.KeySize() - 1);
			SymmetricKey k(key);

			gen.Initialize(k);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE1"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization check -1
		try
		{
			std::vector<byte> code(16);
			std::vector<byte> msg(1);

			gen.Compute(msg, code);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE2"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization check -2
		try
		{
			std::vector<byte> code(16);
			std::vector<byte> msg(1);

			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE3"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// output size check -1
		try
		{
			std::vector<byte> code(gen.TagSize() - 1);
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> msg(1);
			SymmetricKey kp(key);

			gen.Initialize(kp);
			gen.Compute(msg, code);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE4"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// output size check -2
		try
		{
			std::vector<byte> code(gen.TagSize() - 1);
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> msg(1);
			SymmetricKey kp(key);

			gen.Initialize(kp);
			gen.Update(msg, 0, 1);
			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -PE5"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void Poly1305Test::Initialize()
	{
		/*lint -save -e146 */
		/*lint -save -e417 */

		const std::vector<std::string> expected =
		{
			// self-test from poly1305-donna
			std::string("DDB9DA7DDD5E52792730ED5CDA5F90A4"),
			// onetimeauth test from libsodium
			std::string("F3FFC7703F9400E52A7DFB4B3D3305D9"),
			// draft agl-tls-chacha20poly1305-04
			std::string("A6F745008F81C916A20DCC74EEF2B2F0"),
			// draft-irtf-cfrg-chacha20-poly1305-03
			std::string("00000000000000000000000000000000"),
			std::string("36E5F6B5C5E06070F0EFCA96227A863E"),
			std::string("F3477E7CD95417AF89A6B8794C310CF0"),
			std::string("4541669A7EAAEE61E708DC7CBCC5EB62"),
			std::string("03000000000000000000000000000000"),
			std::string("05000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			std::string("14000000000000005500000000000000"),
			std::string("13000000000000000000000000000000"),
			// generated by libsodium
			std::string("D1A00481C8F19ECE2070271B5D998FD0"),
			std::string("5BC3ACAF241883EFAA11D4554704EF70"),
			std::string("4844B6A0345BA7B688D345D4BB90B164"),
			std::string("C4BC6F4BA5258216624AED8416A23081"),
			std::string("67E592B5167E669BE51E6F907AB2795C"),
			std::string("A96C7AAA30F5F70D4F466CBDCD1F8431"),
			std::string("837AD6CE4A89DBE067817498CC3AA0AA")
		};
		HexConverter::Decode(expected, 20, m_expected);

		const std::vector<std::string> keys =
		{
			std::string("DDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFC"),
			std::string("EEA6A7251C1E72916D11C2CB214D3C252539121D8E234E652D651FA4C8CFF880"),
			std::string("746869732069732033322D62797465206B657920666F7220506F6C7931333035"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000036E5F6B5C5E06070F0EFCA96227A863E"),
			std::string("36E5F6B5C5E06070F0EFCA96227A863E00000000000000000000000000000000"),
			std::string("1C9240A5EB55D38AF333888604F6B5F0473917C1402B80099DCA5CBC207075C0"),
			std::string("0200000000000000000000000000000000000000000000000000000000000000"),
			std::string("0100000000000000000000000000000000000000000000000000000000000000"),
			std::string("0100000000000000000000000000000000000000000000000000000000000000"),
			std::string("0200000000000000000000000000000000000000000000000000000000000000"),
			std::string("0100000000000000040000000000000000000000000000000000000000000000"),
			std::string("0100000000000000040000000000000000000000000000000000000000000000"),
			std::string("9E9D85AAD102FDF3867984CAD7436C36D1A00481C8F19ECE2070271B5D998FD0"),
			std::string("B1DF3FB9EA530109228401A375516AF7337AAA04EBD1F9BB79B0EE97AD6DD946"),
			std::string("548E3E7495C8DDD028EF42C85BEC26CAF49B402592A25E37D54CD086C742620D"),
			std::string("95C9DDBAF2A0D598517EB8E3869CE1E1DCE86384F8C7B9CE8F2B157DD297469B"),
			std::string("FC7B0C21141632AE850B31A9CD0BA1BDCD68689AE88817ECC294AD5F1217395B"),
			std::string("A2C48C332C649467416B072DB19F6376EC75BCCDB1CF03C4AD86BA2D1B69D00C"),
			std::string("6B554DA6070086A0D81DA6F3A18B57951DD94959499DFFA5946769E4CFE08420")
		};
		HexConverter::Decode(keys, 20, m_key);

		const std::vector<std::string> message =
		{
			std::string("797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1"),
			std::string("8E993B9F48681273C29650BA32FC76CE48332EA7164D96A4476FB8C531A1186AC0DFC17C98DCE87B4DA7F011EC48C97271D2C20F9B928FE2270D6FB863D51738B48EEEE314A7CC8AB9"
						"32164548E526AE90224368517ACFEABD6BB3732BC0E9DA99832B61CA01B6DE56244A9E88D5F9B37973F622A43D14A6599B1F654CB45A74E355A5"),
			std::string("48656C6C6F20776F726C6421"),
			std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			std::string("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69"
						"636174696F6E20617320616C6C206F722070617274206F6620616E204945544620496E7465726E65742D4472616674206F722052464320616E6420616E792073"
						"746174656D656E74206D6164652077697468696E2074686520636F6E74657874206F6620616E204945544620616374697669747920697320636F6E7369646572"
						"656420616E20224945544620436F6E747269627574696F6E222E20537563682073746174656D656E747320696E636C756465206F72616C2073746174656D656E"
						"747320696E20494554462073657373696F6E732C2061732077656C6C206173207772697474656E20616E6420656C656374726F6E696320636F6D6D756E696361"
						"74696F6E73206D61646520617420616E792074696D65206F7220706C6163652C207768696368206172652061646472657373656420746F"),
			std::string("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69"
						"636174696F6E20617320616C6C206F722070617274206F6620616E204945544620496E7465726E65742D4472616674206F722052464320616E6420616E792073"
						"746174656D656E74206D6164652077697468696E2074686520636F6E74657874206F6620616E204945544620616374697669747920697320636F6E7369646572"
						"656420616E20224945544620436F6E747269627574696F6E222E20537563682073746174656D656E747320696E636C756465206F72616C2073746174656D656E"
						"747320696E20494554462073657373696F6E732C2061732077656C6C206173207772697474656E20616E6420656C656374726F6E696320636F6D6D756E696361"
						"74696F6E73206D61646520617420616E792074696D65206F7220706C6163652C207768696368206172652061646472657373656420746F"),
			std::string("2754776173206272696C6C69672C20616E642074686520736C6974687920746F7665730A446964206779726520616E642067696D626C6520696E207468652077"
						"6162653A0A416C6C206D696D737920776572652074686520626F726F676F7665732C0A416E6420746865206D6F6D65207261746873206F757467726162652E"),
			std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11000000000000000000000000000000"),
			std::string("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101"),
			std::string("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			std::string("E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000"),
			std::string("E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000"),
			std::string(""),
			std::string("E9"),
			std::string("F062"),
			std::string("D815EC"),
			std::string("15E0213E"),
			std::string("B5ED4BC907"),
			std::string("AA99E9E0635B")
		};
		HexConverter::Decode(message, 20, m_message);

		/*lint -restore */
	}

	void Poly1305Test::Kat(IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> code(Generator->TagSize());
		SymmetricKey kp(Key);

		Generator->Initialize(kp);
		Generator->Update(Message, 0, Message.size());
		Generator->Finalize(code, 0);

		if (code != Expected)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Output do not match the vector! -PK1"));
		}
	}

	void Poly1305Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void Poly1305Test::Params(IMac* Generator)
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
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -PP1"));
			}
		}
	}

	void Poly1305Test::Stress(IMac* Generator)
	{
		const uint MINMSG = 1;
		const uint MAXMSG = 16384;
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> code1(Generator->TagSize());
		std::vector<byte> code2(Generator->TagSize());
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXMSG);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXMSG, MINMSG));
				msg.resize(INPLEN);

				IntegerTools::Fill(key, 0, key.size(), rnd);
				IntegerTools::Fill(msg, 0, msg.size(), rnd);
				SymmetricKey kp(key);

				// compute
				Generator->Initialize(kp);
				Generator->Compute(msg, code1);
				// update/finalize
				Generator->Initialize(kp);
				Generator->Update(msg, 0, msg.size());
				Generator->Finalize(code2, 0);

				if (code1 != code2)
				{
					throw TestException(std::string("Stress"), Generator->Name(), std::string("MAC output is not equal! -PS1"));
				}
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
