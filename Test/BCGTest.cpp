#include "BCGTest.h"
#include "RandomUtils.h"
#include "../CEX/BCG.h"
#include "../CEX/CTR.h"
#include "../CEX/HKDF.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHX.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Drbg::BCG;
	using Enumeration::BlockCiphers;
	using Exception::CryptoGeneratorException;
	using Tools::IntegerTools;
	using Enumeration::Providers;
	using Prng::SecureRandom;
	using Cipher::SymmetricKeySize;

	const std::string BCGTest::CLASSNAME = "BCGTest";
	const std::string BCGTest::DESCRIPTION = "Block Cipher Generator implementations vector comparison tests.";
	const std::string BCGTest::SUCCESS = "SUCCESS! All BCG tests have executed succesfully.";

	BCGTest::BCGTest()
		:
		m_expected(0),
		m_key(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	BCGTest::~BCGTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_nonce);
	}

	const std::string BCGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &BCGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string BCGTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("BCGTest: Passed Block Cipher Generator exception handling tests.."));

			Reseed();
			OnProgress(std::string("BCGTest: Passed Block Cipher Generator auto-reseed tests.."));

			Stress();
			OnProgress(std::string("BCGTest: Passed Block Cipher Generator stress tests.."));

			BCG* cgen = new BCG(Providers::None);
			Kat(cgen, m_key[0], m_nonce[0], m_expected[0]);
			Kat(cgen, m_key[0], m_nonce[1], m_expected[1]);
			Kat(cgen, m_key[1], m_nonce[0], m_expected[2]);
			Kat(cgen, m_key[1], m_nonce[1], m_expected[3]);
			OnProgress(std::string("BCGTest: Passed BCG known answer tests.."));
			delete cgen;

			OnProgress(std::string("BCGTest: Evaluate random qualities using ChiSquare, Mean, and Ordered Runs for each generator variant"));
			BCG* cgenacp = new BCG(Providers::ACP);
			Evaluate(cgenacp);
			delete cgenacp;
			OnProgress(std::string("BCGTest: Passed Generator random evaluation tests.."));

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

	void BCGTest::Evaluate(IDrbg* Rng)
	{
		Cipher::SymmetricKeySize ks = Rng->LegalKeySizes()[0];
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> cust(ks.IVSize());
		SecureRandom rnd;
		size_t i;

		rnd.Generate(key, 0, key.size());
		rnd.Generate(cust, 0, cust.size());
		SymmetricKey kp(key, cust);
		Rng->Initialize(kp);

		try
		{
			const size_t SEGLEN = SAMPLE_SIZE / 8;
			std::vector<uint8_t> smp(SAMPLE_SIZE);

			for (i = 0; i < 8; ++i)
			{
				Rng->Generate(smp, i * SEGLEN, SEGLEN);
			}

			RandomUtils::Evaluate(Rng->Name(), smp);
		}
		catch (TestException const &ex)
		{
			throw TestException(std::string("Evaluate"), Rng->Name(), ex.Message() + std::string("-BE1"));
		}
	}

	void BCGTest::Exception()
	{
		// test initialization
		try
		{
			BCG gen;
			// invalid key size
			std::vector<uint8_t> key(1);
			SymmetricKey kp(key);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -BE3"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator state -1
		try
		{
			BCG gen;
			std::vector<uint8_t> m(16);
			// cipher was not initialized
			gen.Generate(m);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -BE5"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator state -2
		try
		{
			BCG gen;			
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);
			gen.Initialize(kp);
			std::vector<uint8_t> m(16);
			// array is too small
			gen.Generate(m, 0, m.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -BE6"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test max reseed exceeded
		try
		{
			BCG gen(Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize(), 0x32);
			std::vector<uint8_t> nonce(ks.IVSize(), 0x64);
			SymmetricKey kp(key, nonce);
			gen.Initialize(kp);
			
			for (size_t i = 0; i < gen.MaxReseedCount() + 1; ++i)
			{
				gen.Update(key);
			}

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -BE7"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void BCGTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
		};
		HexConverter::Decode(key, 2, m_key);

		const std::vector<std::string> nonce =
		{
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		};
		HexConverter::Decode(nonce, 2, m_nonce);

		const std::vector<std::string> expected =
		{
			std::string("2E7F5986BE7D284D5318635AE28AD21858AA30B578D3DFD449CB49316B8B6E8BB4C93CF5ABD50ABB2144F4615C50C036B59D0F09374C4EAAE73BA8256BBFE1F9"
				"E12439CC63144D7AAD536E4169C82918309D4B07B0491E310462695C037DE4AE75A7C521271387CC8D4D048F4CD1F528013AF9194869905836B31FB180650A84"
				"99917A86F7BD07607D49D30536F406CA5CB860D2BFAE5D0BC0233EBF65DB0C2F41248773401DF1F167B83EABC72D9BC2ACB70DA2562B8A5833A92ADE3B1950DE"
				"ED59D6D0EA45F15B2AB89DCC3986E5396826674DC2A3E8FB54F2A4CD66456433DA66D0B37292FF883017721475E669CAC91331C7BAA88D453DFEE411CF8640C1"
				"2423A7423585283E98673AF7934B285061046130A43451ACFCD144143DC44D6F68F32FBA8C65A1AC24EC6290D143BF9622181974C8A32FE0C1D9595E5063A5DE"
				"51FA1ACDEFDAF55D37857C4992196F8951DA83B62A727572443329AD3A402DCC797BB50115CB614E2C0D36FA94FFA2EC1CB8CD6FD934EC4AF15869E663D07014"
				"412CF9B20C08987F11DFA3ABB4CC34AF67E7F49DE6591792B42938777B89A8B55F3EFB31078AC6AB6816AE55A9433BED47EA9E3C196703299AF17CFAD7BCE1FF"
				"E92901557ED606FF986C9331353BFB320261E1C0D6FA11B2DF1C70CB16FCD9CEE48DBEFCECE9BF852F5C0FCA1519FA271E0DF7B0A314365F9CCB962CF0EA8EAA"),
			std::string("4EC82F4D643E12E403049041516D62311789D4330CA1615696777D04633C87D6A366E13BC6836D2A5AA537AB0A56BB0EC5822309583CB0FDF2DBA258AFB71340"
				"E2881FED1D80389DE1872F58341F27F5B47E529F71FD12A7807F0391A69503A6F8D0627D7513FD68884BFFDD1E1D7BF0577EAF901650E86BC0144E17A34098F5"
				"24814C1497C8AFDFA54C9D75FA13D9976EFACDCEE0594FD9584F23A6AF41DE0E83B8B769772346A653DC46EDDCF6EE0AA7CC2A6778D4E0542EA79F081509409E"
				"C6B8EA8CB0DDD35BE9D480473025DC6508B98906C1DDE83429C129E19C5A0415E87703B117167A16F383E330398EA918BA89687F35697E5C49674D4222C266CB"
				"16AC1445BF4FC31A3ED28CAB3C74DDD4D9D99F369CFD5CF9FC70E3C2C77434AF3D108C3BB89A1B6D805FF9F3AA958C2214706399B49CCD84B92CCEC801F18E34"
				"32EEF1B1360A1E085C438AFB174F9E20BE4773908B901A050C991D6B6C3910C142E5027684FD051CA568C5A25D3C62E761D5EA514AE29E8E77E75C9A93914527"
				"87FB4B841D0AFC52BA82145ADEB11942C7525A4C477BD00EFF20DEED7FD9231F0F4538A28334FF629B98F702C5BCE7BCBD203D05E74DE0267A0E4E4EBC358DDC"
				"F80413596B5047E1F907D69AFD2E8DC9D98558AC8B0638A0EB9650AA557FCB99648205716BEC9FB766F849BC56CCEB63DDBC3A456D40E5D94890E0B00B7EC1DF"),
			std::string("49E28DD760B84B07EB1F848663718EFCAA0DB7A2028C36453D0333E4A3BC801AF063F5D824A2063FBFD455F3FC9822AE6646039026976C5EFA8FC6A847CB5109"
				"0C2DCC519C92811C84E24D991643BCD69283C981F9C7C9A02EF610DA7350EF22C24D57DCAA275B4D3E38762E414A2C2BB54EA69E886B3C65788A1B13C8DB896D"
				"6070BD39771AAFFBB2BC86FF54F917EE6BDA97E53CE48D1361FC382628716B2DC7ABE6A4E7E116C42E950C249595F2496CF7961CF4FB4AD3F0685FCA0F2C055B"
				"99486C26FDD57EE4DFC18348E02815ADFFAF7512A2030E50BAC822F6AF4FD72A006083753A4699DB43EA72E6BCF32E835FE41F6EE72DA12C0468D305F4F3E838"
				"44478A26C2C1F8CE9D4742E9C4E87CDF0241EE2CC05E8FCAC08CA6E211E3ADF1BDF2459D552CFB456D236DCA3E8AFB8D9AE029F4A49B0DE38334A8920720E9B1"
				"839F3BFC7DA4956E0CCA51C8D89F78FF83B5A26A7D38CFD5665378A51B05B3487E4452FC6DED5EB66299B1B3AD7A205EA165FA349C2EA2F602A76CA9E4867A7D"
				"765641E5DE925F94484922D6C514CBFE0653A4946F05EE4C239FC77C34BA187B99ED6CF6BF048E045DD0C28D0B2CD150236E18212155E05BD08CBFB5FD5B92B7"
				"F974163E206732A0AF9C3BBA36FFD188B54E72F54A016FFE5E8A7B4953E6559DFC971E135C75B42BF4DC046F0700347820680CC57173B259805BB0964EBCDE30"),
			std::string("BC6F0EBDDA35796F2F54BE5694FC5930E41F82B9F04738A2439552A3327DE0B2A78A3A28B27656BA1765426476CCD56E7F3A997224AE848E6F1D4942C24C9623"
				"DF7599A671CFDBE4EA387071099C424AAFE0A98B1F79C2E250EEAD157083C7EA6499200D62132C12D772FBC014B6C942AB9C4680AE616EDA8EC6F8519FE35786"
				"D6BA6509A2723B81EC92554CCAFFC1A83C2C359CFE7F933B721EB0D80653D2EF84AA775A97C0E786B5D94A948165505B08A42148A40CF09252FCC21D5C397335"
				"95A9D47C00C33065AF38B646A557EDA7BB9C47D4D4F0D9E0088F8EE9B6C7F125A2F5E8DAD87B3E9A0D7285333856E3F40E3689D35605DC6AA4E821D1CD594595"
				"CADF061A3F8FE349CA978A4C5DB5B8AC90350577AD4F85BE745C654BC0BEAB94651734916242A217E2A6517C8B07AA640C7DC049B32916CBC2AE25B852222B03"
				"D10FC97EF797436DB013D44672B6E70230BF00CFBE3D81DB51041E02379B89292DA2A583DD95E18B3C6712B1B09DA95877F2FFA6120FCED45A2108F785D0F531"
				"38BFFE3423A2EBCB94F551F234C0F6CD4C11E7177581BBED7CAE4C0C946DADC76AB0B55C47ACD30F9C70941A1FC8A08E113F5CCA3DA1CFA9D35C6C5AFDABCA71"
				"E39A79C11D6F8F7D03207CF9D180E35232A5B2A222DBAD2C4EA70F4A2A1FD37ADBF6E84786070E7E39A29E6BABE6828280231C9837BAFB7A1B13B422E5DF1A2B")
		};
		HexConverter::Decode(expected, 4, m_expected);

		/*lint -restore */
	}

	void BCGTest::Kat(IDrbg* Rng, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		const size_t EXPLEN = Expected.size();
		std::vector<uint8_t> exp(EXPLEN);
		SymmetricKey kp(Key, Nonce);

		// generate
		Rng->Initialize(kp);
		Rng->Generate(exp, 0, EXPLEN);

		if (exp != Expected)
		{
			throw TestException(std::string("Kat"), Rng->Name(), std::string("Output does not match the known answer! -BK1"));
		}
	}

	void BCGTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void BCGTest::Reseed()
	{
		const size_t SMPLEN = 10240;
		const size_t SMPCNK = 1024;

		BCG gen(Providers::CSP);
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[0];
		std::vector<uint8_t> key(ks.KeySize(), 0x32);
		std::vector<uint8_t> iv(ks.IVSize(), 0x64);
		std::vector<uint8_t> otp(SMPLEN);
		SymmetricKey kp(key, iv);
		size_t i;
		size_t j;

		// set a low reseed threshold
		gen.ReseedThreshold() = SMPCNK;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				// re-initialize
				gen.Initialize(kp);

				// generator will re-seed itself 10x on every test cycle
				for (j = 0; j < SMPLEN / SMPCNK; ++j)
				{
					gen.Generate(otp, j * SMPCNK, SMPCNK);
				}
			}
			catch (CryptoException &ex)
			{
				throw TestException(std::string("Reseed"), gen.Name(), ex.Message());
			}
		}
	}

	void BCGTest::Stress()
	{
		BCG gen1(Providers::None);
		BCG gen2(Providers::None);
		std::vector<uint8_t> inp;
		std::vector<uint8_t> key(32);
		std::vector<uint8_t> iv(32);
		std::vector<uint8_t> otp1;
		std::vector<uint8_t> otp2;
		SecureRandom rnd;
		size_t i;

		const uint32_t MINPRL = 1;
		const uint32_t MAXPRL = 10240;

		inp.reserve(SAMPLE_SIZE);
		otp1.reserve(SAMPLE_SIZE);
		otp2.reserve(SAMPLE_SIZE);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t SMPLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			inp.resize(SMPLEN, 0x00);
			otp1.resize(SMPLEN, 0x00);
			otp2.resize(SMPLEN, 0x00);

			// fill parameters with random
			rnd.Generate(key, 0, key.size());
			rnd.Generate(iv, 0, iv.size());
			SymmetricKey kp(key, iv);

			// sequential generator output
			gen1.Initialize(kp);
			gen1.Generate(otp1, 0, SMPLEN);

			// parallelized generator output
			gen2.Initialize(kp);
			gen2.Generate(otp2, 0, SMPLEN);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Stress"), gen1.Name(), std::string("Generation output is not equal! -TS2"));
			}
		}
	}
}
