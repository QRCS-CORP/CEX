#include "HCGTest.h"
#include "RandomUtils.h"
#include "../CEX/CSP.h"
#include "../CEX/Digests.h"
#include "../CEX/HCG.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA2256.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using namespace Drbg;
	using Enumeration::Digests;
	using Tools::IntegerTools;
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

			HCG* gen256 = new HCG(SHA2Digests::SHA2256, Providers::None);
			Kat(gen256, m_key[0], m_expected[0]);
			Kat(gen256, m_key[1], m_expected[1]);
			Kat(gen256, m_key[2], m_expected[2]);
			OnProgress(std::string("HCGTest: Passed HMAC-SHA2256 Generator known answer tests.."));

			HCG* gen512 = new HCG(SHA2Digests::SHA2512, Providers::None);
			Kat(gen256, m_key[0], m_expected[3]);
			Kat(gen256, m_key[1], m_expected[4]);
			Kat(gen256, m_key[2], m_expected[5]);
			OnProgress(std::string("HCGTest: Passed HMAC-SHA2512 Generator known answer tests.."));

			Reseed();
			OnProgress(std::string("HCGTest: Passed HMAC Generator auto-reseed tests.."));

			Stress();
			OnProgress(std::string("HCGTest: Passed HMAC Generator stress tests.."));

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
			HCG gen(SHA2Digests::SHA2256, Providers::CSP);
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
			HCG gen(SHA2Digests::SHA2256, Providers::CSP);
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
			HCG gen(SHA2Digests::SHA2256, Providers::CSP);
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
			HCG gen(SHA2Digests::SHA2256, Providers::CSP);
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
			HCG gen(SHA2Digests::SHA2256, Providers::CSP);
			SymmetricKeySize ks = gen.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize(), 0x32);
			std::vector<byte> nonce(ks.IVSize(), 0x64);
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
		std::vector<byte> cust(ks.IVSize());
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
			std::string("3CBA7FBC038C7FE9EEE6AFB54E3C57F8DD015895C2500098FC812B139F876EA2B7ACBB532BF6B215B573C424F4C8959B66A197AFDD42C41D08ACA285A6E6CB81"
				"6A23F67117B33C76DAD1C35B913C0132A68A1E0FACF02655BCA5D394D85A96AA9F942E30805B3B4C42C180E90CD351C454C9889F0276716A2A88042DAB60889E"
				"9AF41DCB7C1897D09FA5C4CA77C117D26054240EB2955D3E9E42EAD71D562CC0DC64040C6247E3326BBAF40441DA5795F98A163DF9457A06B31BD5FDD122FAFE"
				"C757EB5B81BE2A2EE37503523451660410C247C6A142DF274C6C18DCD598753CA7D4B734383828E536C4A448DFA4B3E2F5A80F7B6C06BE6AC7A66D93FA042360"
				"7793D1E3383ADC94E60B3CEF0B05A886E8E0C6FB1EB3A227CFF8AFD1D3A04D5B948EF70FA22D743CCDB370D8CE989B9953B0D1C6FE2A33F4F8B9B70EFE2B12DA"
				"F9C2208CE80AEB9B556871123717FB5A85FE21B0BC127AB11EDD28068F597883E0C89E621D746DDD597D536A517A22D7A7F138E00A8CBDC02A6A0F5688828CEB"
				"F30E9DD53A99334D22ED87FAF62ACFD75797245BC586714C1073B72AA33F6D2E64F040B03950A50EB6A7C03CDDE86D500168B88A296D04684891AC030658C170"
				"D684900CA86095E840F7AE2391D00201BBF2A914403A1F4E067451DD3A1129C69ECDCDFEA6837752FD3EA5ED7CBA7B3FB3483FD54CE33000DDF1EA69EAC03E25"),
			std::string("660DD19A7746EF1A3777FE77C716F241C5DCD2E2555758E0905DD36D2FFE7B51D13C57C94FE2B22023849324BADC386F1D13001E1E95356D044B109205386778"
				"86063720462727D64ECB4FE9CCF92C385571E8296706CA19980AD225719C905AE5014D3E14046D1A7DA9C4A9FD8F721251FED955E0E28ABF662DC6DC6BCC8FB8"
				"29C2A6EF2FACC09FE8D7525CA092883EB29937CFB6196D2E78CC2777BB6DEC8EA213CF92196D382F52827AD328DAF81D6F29B1344DDAD932BD8070DEAFF1C6BE"
				"DF31E49CC450CE234E723761C5E78144460EBE020DB6E009DAD57183CA1D310E0BCB68F6FD7511875EEB3C0A02F9D62DFAD542DEB2ABFB3F8CAB6B0401B3D28C"
				"070A40801C6CBC0AEA798D009DC0FF760B26A049BAB016B303B57DFAA404690F6094BBAE25C41C01A043FA5277B4B224359B1391DA4E2D4C3501CEC679069AD0"
				"9647CE518C1A0EE1DD855EC350E44EB9F7037FBC6226F95A891C7568AB5C92A396962D0AD91A6A51640D6E93F7DDA74040087CAFD50F1EEAC19BB452E82E63E7"
				"84D52097315597AB0F36793463955B10899DC8903698AAD2BF1220AE135BB9C451D59D12C157F9B5A78B070766E68046C7236BF6D14E8FDF1A3D046D41DA6B45"
				"55F0C141AC692CDD76B9460641045C0A1E5CD9128187FAC2F6BA70E797E97AF28B121E0EF7E23A13DDD41F7D3DB2AD3C157C8487C9D38C8FE4554F5F58AAF78D"),
			std::string("0ADABF332FCA05A155F1ABED09887839C0CFC3C7854581B553003929CC1C18E66FBE7253FBC4129B512EBF39716FDE660FBFA85B864376D957BF363B25C36E9F"
				"65D7B0C6F8B7B9A21BBBDA921149C20A77D232DB5A81F479EBF2F010538B12AB19D6D74F3DFBDE041248CE10A8FD47C7FF9213FA587C8B2F24515ED539F546E9"
				"9D55134A8D5A71C715D96B90CC8BC08BF6B0FB869F0923EE0D2DF2EAA44437B037E7FAF47C95884BDA0028061FE9D889F3826F88DF96CD3662061745477A5196"
				"1B41AF707736D3CBF2FF36846D5063DBBECD6850882535B740F68A419882ED784356FD6BF7ED71B05562BD40357942092391B84800D24DF8F5E6B517A7E0AE0B"
				"7A87943AC2B4984DA6E0EEDA2481463072379DD0CC18DF60546D924EC3DE481C7B9E32C3FB63F46909A905DD0D0C1309D915A392DE026FBC7A9C0FA67EEA524F"
				"22B13BE2457C76409A738061772DC589C6DE10FEB6833D3D021C6D328CD66654C4866AADF25267494FC57CA0CE29A1797BB1BCCE7FE67B0A6905FAB440E39E16"
				"98513ACE18AA1DFB167AA1C1C45EC80C013105CC844E0E2A8E0C67311B72B1DFEFDF0587BA3DA0C01C6973A5834316A49C3B71E5D8C61744243479315EA9FFBE"
				"1648CD133CACB5EA1B4329CE7DCC2A4A519348A65EC02430082372331154443DE4A7E02787979A17E925689031651A64E90735BF5131C8CF5F980107D604B334"),
			std::string("3CBA7FBC038C7FE9EEE6AFB54E3C57F8DD015895C2500098FC812B139F876EA2B7ACBB532BF6B215B573C424F4C8959B66A197AFDD42C41D08ACA285A6E6CB81"
				"6A23F67117B33C76DAD1C35B913C0132A68A1E0FACF02655BCA5D394D85A96AA9F942E30805B3B4C42C180E90CD351C454C9889F0276716A2A88042DAB60889E"
				"9AF41DCB7C1897D09FA5C4CA77C117D26054240EB2955D3E9E42EAD71D562CC0DC64040C6247E3326BBAF40441DA5795F98A163DF9457A06B31BD5FDD122FAFE"
				"C757EB5B81BE2A2EE37503523451660410C247C6A142DF274C6C18DCD598753CA7D4B734383828E536C4A448DFA4B3E2F5A80F7B6C06BE6AC7A66D93FA042360"
				"7793D1E3383ADC94E60B3CEF0B05A886E8E0C6FB1EB3A227CFF8AFD1D3A04D5B948EF70FA22D743CCDB370D8CE989B9953B0D1C6FE2A33F4F8B9B70EFE2B12DA"
				"F9C2208CE80AEB9B556871123717FB5A85FE21B0BC127AB11EDD28068F597883E0C89E621D746DDD597D536A517A22D7A7F138E00A8CBDC02A6A0F5688828CEB"
				"F30E9DD53A99334D22ED87FAF62ACFD75797245BC586714C1073B72AA33F6D2E64F040B03950A50EB6A7C03CDDE86D500168B88A296D04684891AC030658C170"
				"D684900CA86095E840F7AE2391D00201BBF2A914403A1F4E067451DD3A1129C69ECDCDFEA6837752FD3EA5ED7CBA7B3FB3483FD54CE33000DDF1EA69EAC03E25"),
			std::string("660DD19A7746EF1A3777FE77C716F241C5DCD2E2555758E0905DD36D2FFE7B51D13C57C94FE2B22023849324BADC386F1D13001E1E95356D044B109205386778"
				"86063720462727D64ECB4FE9CCF92C385571E8296706CA19980AD225719C905AE5014D3E14046D1A7DA9C4A9FD8F721251FED955E0E28ABF662DC6DC6BCC8FB8"
				"29C2A6EF2FACC09FE8D7525CA092883EB29937CFB6196D2E78CC2777BB6DEC8EA213CF92196D382F52827AD328DAF81D6F29B1344DDAD932BD8070DEAFF1C6BE"
				"DF31E49CC450CE234E723761C5E78144460EBE020DB6E009DAD57183CA1D310E0BCB68F6FD7511875EEB3C0A02F9D62DFAD542DEB2ABFB3F8CAB6B0401B3D28C"
				"070A40801C6CBC0AEA798D009DC0FF760B26A049BAB016B303B57DFAA404690F6094BBAE25C41C01A043FA5277B4B224359B1391DA4E2D4C3501CEC679069AD0"
				"9647CE518C1A0EE1DD855EC350E44EB9F7037FBC6226F95A891C7568AB5C92A396962D0AD91A6A51640D6E93F7DDA74040087CAFD50F1EEAC19BB452E82E63E7"
				"84D52097315597AB0F36793463955B10899DC8903698AAD2BF1220AE135BB9C451D59D12C157F9B5A78B070766E68046C7236BF6D14E8FDF1A3D046D41DA6B45"
				"55F0C141AC692CDD76B9460641045C0A1E5CD9128187FAC2F6BA70E797E97AF28B121E0EF7E23A13DDD41F7D3DB2AD3C157C8487C9D38C8FE4554F5F58AAF78D"),
			std::string("0ADABF332FCA05A155F1ABED09887839C0CFC3C7854581B553003929CC1C18E66FBE7253FBC4129B512EBF39716FDE660FBFA85B864376D957BF363B25C36E9F"
				"65D7B0C6F8B7B9A21BBBDA921149C20A77D232DB5A81F479EBF2F010538B12AB19D6D74F3DFBDE041248CE10A8FD47C7FF9213FA587C8B2F24515ED539F546E9"
				"9D55134A8D5A71C715D96B90CC8BC08BF6B0FB869F0923EE0D2DF2EAA44437B037E7FAF47C95884BDA0028061FE9D889F3826F88DF96CD3662061745477A5196"
				"1B41AF707736D3CBF2FF36846D5063DBBECD6850882535B740F68A419882ED784356FD6BF7ED71B05562BD40357942092391B84800D24DF8F5E6B517A7E0AE0B"
				"7A87943AC2B4984DA6E0EEDA2481463072379DD0CC18DF60546D924EC3DE481C7B9E32C3FB63F46909A905DD0D0C1309D915A392DE026FBC7A9C0FA67EEA524F"
				"22B13BE2457C76409A738061772DC589C6DE10FEB6833D3D021C6D328CD66654C4866AADF25267494FC57CA0CE29A1797BB1BCCE7FE67B0A6905FAB440E39E16"
				"98513ACE18AA1DFB167AA1C1C45EC80C013105CC844E0E2A8E0C67311B72B1DFEFDF0587BA3DA0C01C6973A5834316A49C3B71E5D8C61744243479315EA9FFBE"
				"1648CD133CACB5EA1B4329CE7DCC2A4A519348A65EC02430082372331154443DE4A7E02787979A17E925689031651A64E90735BF5131C8CF5F980107D604B334")
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

		HCG gen(SHA2Digests::SHA2256, Providers::CSP);
		Cipher::SymmetricKeySize ks = gen.LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize(), 0x32);
		std::vector<byte> iv(ks.IVSize(), 0x64);
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
		HCG gen(SHA2Digests::SHA2256);
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
				rnd.Generate(key, 0, key.size());
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
