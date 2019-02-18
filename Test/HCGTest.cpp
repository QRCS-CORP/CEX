#include "HCGTest.h"
#include "RandomUtils.h"
#include "../CEX/CSP.h"
#include "../CEX/Digests.h"
#include "../CEX/HCG.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA256.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using namespace Drbg;
	using Enumeration::Digests;
	using Utility::IntegerTools;
	using Prng::SecureRandom;

	const std::string HCGTest::CLASSNAME = "HCGTest";
	const std::string HCGTest::DESCRIPTION = "HCG implementations vector comparison tests.";
	const std::string HCGTest::SUCCESS = "SUCCESS! All HCG tests have executed succesfully.";

	HCGTest::HCGTest()
		:
		m_expected(0),
		m_key(0),
		m_progressEvent()
	{
		Initialize();
	}

	HCGTest::~HCGTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
	}

	const std::string HCGTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HCGTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HCGTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("HCGTest: Passed HMAC Generator exception handling tests.."));

			Reseed();
			OnProgress(std::string("HCGTest: Passed HMAC Generator auto-reseed tests.."));

			Stress();
			OnProgress(std::string("HCGTest: Passed HMAC Generator stress tests.."));

			HCG* gen256 = new HCG(SHA2Digests::SHA256, Providers::None);
			Kat(gen256, m_key[0], m_expected[0]);
			Kat(gen256, m_key[1], m_expected[1]);
			Kat(gen256, m_key[2], m_expected[2]);
			OnProgress(std::string("HCGTest: Passed HMAC-SHA256 Generator known answer tests.."));

			HCG* gen512 = new HCG(SHA2Digests::SHA512, Providers::None);
			Kat(gen256, m_key[0], m_expected[3]);
			Kat(gen256, m_key[1], m_expected[4]);
			Kat(gen256, m_key[2], m_expected[5]);
			OnProgress(std::string("HCGTest: Passed HMAC-SHA512 Generator known answer tests.."));

			OnProgress(std::string("HCGTest: Evaluate random qualities using ChiSquare, Mean, and Ordered Runs for each generator variant"));
			Evaluate(gen256);
			Evaluate(gen512);
			OnProgress(std::string("HCGTest: Passed HMAC Generator random evaluation tests.."));

			delete gen256;
			delete gen512;

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

	void HCGTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid digest choice
			HCG gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE1"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test constructor -2
		try
		{
			// invalid null digest instance
			HCG gen(nullptr);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			// invalid key size
			std::vector<byte> key(1);
			SymmetricKey kp(key);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE3"));
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
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			std::vector<byte> m(16);
			// cipher was not initialized
			gen.Generate(m);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE4"));
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
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			SymmetricKey kp(key);

			gen.Initialize(kp);
			std::vector<byte> m(16);
			// array is too small
			gen.Generate(m, 0, m.size() + 1);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE5"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid generator request
		try
		{
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			SymmetricKey kp(key);
			gen.Initialize(kp);
			// more than the max request size -64kb
			std::vector<byte> m(gen.MaxRequestSize() + 1);
			gen.Generate(m, 0, m.size());

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE6"));
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
			HCG gen(SHA2Digests::SHA256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize(), 0x32);
			std::vector<byte> nonce(ks.NonceSize(), 0x64);
			SymmetricKey kp(key, nonce);
			gen.Initialize(kp);

			for (size_t i = 0; i < gen.MaxReseedCount() + 1; ++i)
			{
				gen.Update(key);
			}

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -CE8"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void HCGTest::Evaluate(IDrbg* Rng)
	{
		Cipher::SymmetricKeySize ks = Rng->LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> cust(ks.NonceSize());
		SecureRandom rnd;
		size_t i;

		rnd.Generate(key, 0, key.size());
		rnd.Generate(cust, 0, cust.size());
		SymmetricKey kp(key, cust);
		Rng->Initialize(kp);

		try
		{
			const size_t SEGLEN = SAMPLE_SIZE / 8;
			std::vector<byte> smp(SAMPLE_SIZE);

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

	void HCGTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> expected =
		{
			std::string("D80DB6CC45FE5113F83DB805BDE72356E067626E46AD3CA1919CB8F58003C9149BE140635B728DFD5A0B7F3826242D4F87D66AE0E7DD9C0FD05E4D8DB471FCFF"
				"DBD057758BC433D1A4AEE651AA4FE119B7A365DAE216E3A8330B15896C02A8C2B563D2663B2FBCFFF89614E77A85792F610F1FEC42EB5F51EB92FA414A98B843"
				"A5A0D9069561F5F1D9641E99C1880E2C98BD07AD04FB8366B2B6036F37799A2A78494CDC29F4B1DC9141282C06E756D35056506BD76BEAB27EC5342D93EDC086"
				"7A39D0EF1B2362D244592947CBB3170D92DFB6E44553E38BFF29BFC5D17A541AB8E3826929553E1319BABA18B1E97DC870AAB31053D64C62C1E31E201416B96E"
				"A0A55DB7CF74BE984DF752ABF6422E468B57BA1809E98828943283097EC2665F6CD0F8D5C39E043A543526CB4FC6223E85B7DE18D8E5C976C2BBE9C3984A0AB9"
				"CA56D046F1580F397A784DEE056BE04CCF795D199AB4415C1FDB7D597A98AAE01BA7DA2E4FE44594720F637B813BAF06A6667DF2FFDD15B1A71880D1BB5D4C78"
				"28F71E5D932A53EC67BA3CBCAD6D13EAD45F6E1638ADD127DDED2A2A2FE4BC8A11132BBCB6079ECC6D3368820B152DC90DF3476BA1A9E73BC75505FD1AEB463B"
				"1F61EB5FF2D1B3C7C4846943B352347769D94DD760E66D2CFEBB4BAD2C62E195B037927A4815A208BB1110A5256D263F4C654225C3EA9C1F6F2F0730E2CE7851"),
			std::string("75152BA498DCAC775400C042869CE7C13B33869A9530973D27833694A3F710DC0B8AF960E7A32134AAEE1B24B11E9A304B61254BD1CA9C61D792A07CA944E310"
				"96A38CDC8F1DFD20371D50AAB944A40E8FFC120D78E5524D7BD5F0F46A61AFF3649CB537B8E9714EB5DE59FC6F134E2F9E0AC6C065D0C784453D70178DE4B0FD"
				"5A51D5FBB82B4E6AAC84910721189EC42C92FEE161A31F6FAD0BB70C7722E2F5CA17B1A0ED195426048922CFB227BEA65D6F2974DD8741A264D251C874C4FFC0"
				"ED37806636A6AD0499887DB2171D491BB4F19800A185531E91C1A002BD6374C0076AF4DDED9813207D6094AEB7CA893319C10813E94A4DD988076B302EDA3FCF"
				"0EB7F8DA829126768A6EC55580DB023A14C2798F9B2803C0DC226B29BFE4EB2ADA3C75A3A98C244AAC2931643CD81F6455C5EC7774C80CC0018D9CED67CAA4FF"
				"6E80E1BBE6E0A48B9C192965BEEF650C600FA36351D1D340399A8AB1C24EF1E3C0D76D7503A2FC9199598E3BF71DD36ADA94AEC88D2A22D43C657E6A0580A975"
				"8E5A0A3A1574B19C64C171BCCB7CE831CD68B5B8FACC2A32CA69309294B98DABF6DA4336DD98DB260D678007812E994AB4972BF67ECABC2DC97C9947CEDAAC28"
				"BABC0C32BA4AE055AF52417922CD9EDD05112BA2831392E0E4F6B16BBF80642592E4F5BC95C379870393212E54A579BD518929350BAC1C7EA90B6856516EAE44"),
			std::string("AD82AD2E7128714C0649BE09603B1FB721D1BB4E08EA9AF244C91AE9F922CBA6313D35BC0D56ECB08E8E31350EB9E53A52E3FE188F0F940C7C022B48BC5DDE33"
				"87FBD5BDC441E4474F936BD72BE68CEDB08F07666ACFCBA2972EABB62F6795E228A50FD38A39DBFB2411ABD7EC39EFD056F44CD3680B71B48CB8568A363B67C4"
				"16AE39ABFF4AC4980682482FAD59314FF86C61E5F41DC9069C151157AECE2A8438A3115BB88BF734A2BD34C8B7CCC74D6E9AFC5049A2750B013F8B5235B3A65D"
				"EE883420811D659B03D8D15087EED422FA57C40E9B4E7A268064536EEA44F63E6695FF419E3F61CFBD8BA24A7BB67F93DF2D66EB6D8D1246A6E9D24660555C96"
				"C3960842659A2979E60CFF10B4D66293D5578FF42AE00443C5BD501CA758B33A196BED98E3269FBBF97DABE14C66E8D9D951CDDC3FE037B328A02EF3F8854480"
				"801AA3448F6A268C419162CB7104F4734A30E957B4BE3890BDFECC709ED8F50BF9B7AFC98222BB90A8E9DC75207127BC0739793231BD9CB740A1676CAF112B9A"
				"A62CEC1AC6404B80D71D3E7DBEB04B9C64D90A7BC4F5BF5169A27E19464CA401AD79F5896DF2F0D96AB510B9F4809B751DC3C90B06F085FEE252A6C843B4B80E"
				"200A5F61FF0E9AC1FD94A9BBB0C5F4F29B37F0CB502442D9A0F8D8C35998760F91E244A1882C7994D6B29053F2DA234AF8F45F889873E02F8D8AA1C9A0694C89"),
			std::string("D80DB6CC45FE5113F83DB805BDE72356E067626E46AD3CA1919CB8F58003C9149BE140635B728DFD5A0B7F3826242D4F87D66AE0E7DD9C0FD05E4D8DB471FCFF"
				"DBD057758BC433D1A4AEE651AA4FE119B7A365DAE216E3A8330B15896C02A8C2B563D2663B2FBCFFF89614E77A85792F610F1FEC42EB5F51EB92FA414A98B843"
				"A5A0D9069561F5F1D9641E99C1880E2C98BD07AD04FB8366B2B6036F37799A2A78494CDC29F4B1DC9141282C06E756D35056506BD76BEAB27EC5342D93EDC086"
				"7A39D0EF1B2362D244592947CBB3170D92DFB6E44553E38BFF29BFC5D17A541AB8E3826929553E1319BABA18B1E97DC870AAB31053D64C62C1E31E201416B96E"
				"A0A55DB7CF74BE984DF752ABF6422E468B57BA1809E98828943283097EC2665F6CD0F8D5C39E043A543526CB4FC6223E85B7DE18D8E5C976C2BBE9C3984A0AB9"
				"CA56D046F1580F397A784DEE056BE04CCF795D199AB4415C1FDB7D597A98AAE01BA7DA2E4FE44594720F637B813BAF06A6667DF2FFDD15B1A71880D1BB5D4C78"
				"28F71E5D932A53EC67BA3CBCAD6D13EAD45F6E1638ADD127DDED2A2A2FE4BC8A11132BBCB6079ECC6D3368820B152DC90DF3476BA1A9E73BC75505FD1AEB463B"
				"1F61EB5FF2D1B3C7C4846943B352347769D94DD760E66D2CFEBB4BAD2C62E195B037927A4815A208BB1110A5256D263F4C654225C3EA9C1F6F2F0730E2CE7851"),
			std::string("75152BA498DCAC775400C042869CE7C13B33869A9530973D27833694A3F710DC0B8AF960E7A32134AAEE1B24B11E9A304B61254BD1CA9C61D792A07CA944E310"
				"96A38CDC8F1DFD20371D50AAB944A40E8FFC120D78E5524D7BD5F0F46A61AFF3649CB537B8E9714EB5DE59FC6F134E2F9E0AC6C065D0C784453D70178DE4B0FD"
				"5A51D5FBB82B4E6AAC84910721189EC42C92FEE161A31F6FAD0BB70C7722E2F5CA17B1A0ED195426048922CFB227BEA65D6F2974DD8741A264D251C874C4FFC0"
				"ED37806636A6AD0499887DB2171D491BB4F19800A185531E91C1A002BD6374C0076AF4DDED9813207D6094AEB7CA893319C10813E94A4DD988076B302EDA3FCF"
				"0EB7F8DA829126768A6EC55580DB023A14C2798F9B2803C0DC226B29BFE4EB2ADA3C75A3A98C244AAC2931643CD81F6455C5EC7774C80CC0018D9CED67CAA4FF"
				"6E80E1BBE6E0A48B9C192965BEEF650C600FA36351D1D340399A8AB1C24EF1E3C0D76D7503A2FC9199598E3BF71DD36ADA94AEC88D2A22D43C657E6A0580A975"
				"8E5A0A3A1574B19C64C171BCCB7CE831CD68B5B8FACC2A32CA69309294B98DABF6DA4336DD98DB260D678007812E994AB4972BF67ECABC2DC97C9947CEDAAC28"
				"BABC0C32BA4AE055AF52417922CD9EDD05112BA2831392E0E4F6B16BBF80642592E4F5BC95C379870393212E54A579BD518929350BAC1C7EA90B6856516EAE44"),
			std::string("AD82AD2E7128714C0649BE09603B1FB721D1BB4E08EA9AF244C91AE9F922CBA6313D35BC0D56ECB08E8E31350EB9E53A52E3FE188F0F940C7C022B48BC5DDE33"
				"87FBD5BDC441E4474F936BD72BE68CEDB08F07666ACFCBA2972EABB62F6795E228A50FD38A39DBFB2411ABD7EC39EFD056F44CD3680B71B48CB8568A363B67C4"
				"16AE39ABFF4AC4980682482FAD59314FF86C61E5F41DC9069C151157AECE2A8438A3115BB88BF734A2BD34C8B7CCC74D6E9AFC5049A2750B013F8B5235B3A65D"
				"EE883420811D659B03D8D15087EED422FA57C40E9B4E7A268064536EEA44F63E6695FF419E3F61CFBD8BA24A7BB67F93DF2D66EB6D8D1246A6E9D24660555C96"
				"C3960842659A2979E60CFF10B4D66293D5578FF42AE00443C5BD501CA758B33A196BED98E3269FBBF97DABE14C66E8D9D951CDDC3FE037B328A02EF3F8854480"
				"801AA3448F6A268C419162CB7104F4734A30E957B4BE3890BDFECC709ED8F50BF9B7AFC98222BB90A8E9DC75207127BC0739793231BD9CB740A1676CAF112B9A"
				"A62CEC1AC6404B80D71D3E7DBEB04B9C64D90A7BC4F5BF5169A27E19464CA401AD79F5896DF2F0D96AB510B9F4809B751DC3C90B06F085FEE252A6C843B4B80E"
				"200A5F61FF0E9AC1FD94A9BBB0C5F4F29B37F0CB502442D9A0F8D8C35998760F91E244A1882C7994D6B29053F2DA234AF8F45F889873E02F8D8AA1C9A0694C89")
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
						"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F")
		};
		HexConverter::Decode(key, 3, m_key);
		/*lint -restore */
	}

	void HCGTest::Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		const size_t EXPLEN = Expected.size();
		std::vector<byte> exp(EXPLEN);
		SymmetricKey kp(Key);

		// generate
		Rng->Initialize(kp);
		Rng->Generate(exp, 0, EXPLEN);

		if (exp != Expected)
		{
			throw TestException(std::string("Kat"), Rng->Name(), std::string("Output does not match the known answer! -HK1"));
		}
	}

	void HCGTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void HCGTest::Reseed()
	{
		const size_t SMPLEN = 10240;
		const size_t SMPCNK = 1024;

		HCG gen(SHA2Digests::SHA256, Providers::CSP);
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize(), 0x32);
		std::vector<byte> iv(ks.NonceSize(), 0x64);
		std::vector<byte> otp(SMPLEN);
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

	void HCGTest::Stress()
	{
		HCG gen(SHA2Digests::SHA256);
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t OTPLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				otp.resize(OTPLEN);
				IntegerTools::Fill(key, 0, key.size(), rnd);
				SymmetricKey kp(key);
				// initialize and generate
				gen.Initialize(kp);
				gen.Generate(otp, 0, OTPLEN);
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), gen.Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
