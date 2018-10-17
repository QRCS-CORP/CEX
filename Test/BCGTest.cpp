#include "BCGTest.h"
#include "RandomUtils.h"
#include "../CEX/BCG.h"
#include "../CEX/CTR.h"
#include "../CEX/HKDF.h"
#include "../CEX/IntUtils.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHX.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;
	using namespace Drbg;
	using namespace Cipher::Symmetric::Block::Mode;
	using Utility::IntUtils;
	using Prng::SecureRandom;

	const std::string BCGTest::DESCRIPTION = "Block Cipher Generator implementations vector comparison tests.";
	const std::string BCGTest::FAILURE = "FAILURE! ";
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
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_nonce);
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

			Stress();
			OnProgress(std::string("BCGTest: Passed Block Cipher Generatorstress tests.."));

			// rijndael engine
			BCG* drbg1 = new BCG(BlockCiphers::RHX, BlockCipherExtensions::None, Providers::None);
			Kat(drbg1, m_key[0], m_nonce[0], m_expected[0]);
			BCG* drbg2 = new BCG(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, Providers::None);
			Kat(drbg2, m_key[0], m_nonce[0], m_expected[1]);
			BCG* drbg3 = new BCG(BlockCiphers::RHX, BlockCipherExtensions::HKDF512, Providers::None);
			Kat(drbg3, m_key[1], m_nonce[0], m_expected[2]);
			BCG* drbg4 = new BCG(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, Providers::None);
			Kat(drbg4, m_key[0], m_nonce[0], m_expected[3]);
			BCG* drbg5 = new BCG(BlockCiphers::RHX, BlockCipherExtensions::SHAKE512, Providers::None);
			Kat(drbg5, m_key[1], m_nonce[0], m_expected[4]);
			OnProgress(std::string("BCGTest: Passed BCG-RHX known answer tests.."));
			// serpent engine
			BCG* drbg6 = new BCG(BlockCiphers::SHX, BlockCipherExtensions::None, Providers::None);
			Kat(drbg6, m_key[0], m_nonce[0], m_expected[5]);
			BCG* drbg7 = new BCG(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, Providers::None);
			Kat(drbg7, m_key[0], m_nonce[0], m_expected[6]);
			BCG* drbg8 = new BCG(BlockCiphers::SHX, BlockCipherExtensions::HKDF512, Providers::None);
			Kat(drbg8, m_key[1], m_nonce[0], m_expected[7]);
			BCG* drbg9 = new BCG(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, Providers::None);
			Kat(drbg9, m_key[0], m_nonce[0], m_expected[8]);
			BCG* drbg10 = new BCG(BlockCiphers::SHX, BlockCipherExtensions::SHAKE512, Providers::None);
			Kat(drbg10, m_key[1], m_nonce[0], m_expected[9]);
			OnProgress(std::string("BCGTest: Passed BCG-SHX known answer tests.."));

			OnProgress(std::string(""));
			OnProgress(std::string("BCGTest: Evaluate random qualities using ChiSquare, Mean, and Ordered Runs for each generator variant"));
			Evaluate(drbg1);
			Evaluate(drbg2);
			Evaluate(drbg3);
			Evaluate(drbg4);
			Evaluate(drbg5);
			Evaluate(drbg6);
			Evaluate(drbg7);
			Evaluate(drbg8);
			Evaluate(drbg9);
			Evaluate(drbg10);

			delete drbg1;
			delete drbg2;
			delete drbg3;
			delete drbg4;
			delete drbg5;
			delete drbg6;
			delete drbg7;
			delete drbg8;
			delete drbg9;
			delete drbg10;

			OnProgress(std::string("BCGTest: Passed Block Cipher Generator random evaluation tests.."));

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

	void BCGTest::Evaluate(IDrbg* Rng)
	{
		std::vector<byte> otp(SAMPLE_SIZE);
		Key::Symmetric::SymmetricKeySize ks = Rng->LegalKeySizes()[1];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
		SecureRandom rnd;
		double x;
		std::string status;

		IntUtils::Fill(key, 0, key.size(), rnd);
		IntUtils::Fill(iv, 0, iv.size(), rnd);
		SymmetricKey kp(key, iv);

		Rng->Initialize(kp);
		Rng->Generate(otp);

		// mean value test
		x = TestUtils::MeanValue(otp);

		status = (Rng->Name() + std::string(": Mean distribution value is ") + TestUtils::ToString(x) + std::string(" % (127.5 is optimal)"));

		if (x < 122.5 || x > 132.5)
		{
			status += std::string("(FAIL)");
		}
		else if (x < 125.0 || x > 130.0)
		{
			status += std::string("(WARN)");
		}
		else
		{
			status += std::string("(PASS)");
		}

		OnProgress(std::string(status));

		// ChiSquare
		x = TestUtils::ChiSquare(otp) * 100;
		status = (std::string("ChiSquare: random would exceed this value ") + TestUtils::ToString(x) + std::string(" percent of the time "));

		if (x < 1.0 || x > 99.0)
		{
			status += std::string("(FAIL)");
		}
		else if (x < 5.0 || x > 95.0)
		{
			status += std::string("(WARN)");
		}
		else
		{
			status += std::string("(PASS)");
		}
		OnProgress(std::string(status));

		// ordered runs
		if (TestUtils::OrderedRuns(otp))
		{
			throw TestException(std::string("BCG"), std::string("Exception: Ordered runs test failure! -VE1"));
		}

		// succesive zeroes
		if (TestUtils::SuccesiveZeros(otp))
		{
			throw TestException(std::string("BCG"), std::string("Exception: Succesive zeroes test failure! -VE2"));
		}
	}

	void BCGTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid block cipher choice
			BCG drbg(BlockCiphers::None);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE1"));
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
			// invalid null block cipher instance
			BCG drbg(nullptr);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE2"));
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
			BCG drbg(BlockCiphers::Rijndael);
			// invalid key size
			std::vector<byte> k(1);
			drbg.Initialize(k);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE3"));
		}
		catch (CryptoGeneratorException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel degree
		try
		{
			BCG drbg(BlockCiphers::Rijndael);
			SymmetricKeySize ks = drbg.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize());
			drbg.Initialize(k);
			// invalid max parallel -99
			drbg.ParallelMaxDegree(99);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE4"));
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
			BCG drbg(BlockCiphers::Rijndael);
			std::vector<byte> m(16);
			// cipher was not initialized
			drbg.Generate(m);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE5"));
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
			BCG drbg(BlockCiphers::Rijndael);			
			SymmetricKeySize ks = drbg.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize());
			std::vector<byte> n(ks.NonceSize());
			drbg.Initialize(k, n);
			std::vector<byte> m(16);
			// array is too small
			drbg.Generate(m, 0, m.size() + 1);

			throw TestException(std::string("BCG"), std::string("Exception: Exception handling failure! -BE6"));
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
			std::string("00000000000000000000000000000080")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		const std::vector<std::string> expected =
		{
			std::string("4F48B3FEC548525A5E64182A29A1D035EE7A491436D49D8639E9B8AE77176CCBAFB3CA08D062D6BD5505851531BBA5DCC2543FE3CCF62B9422E369440D19B6E0"), // aes256
			std::string("8373DFB16F3F61D14F96B2A26DD358B6EC7893BD70179E573C8A516A71BDA0CF595262B6CE43F05DA1B3C404FB0019B4FDC17EB11E15ABECAE55416241EB4A9C"), // rhx-hkdf-256
			std::string("D11C91E5D5490EBBDBB7B27B866D06B5DAE2ECB60C39503C911BA17A925954897DE982D0E5913D155D2F0F2BE175CD8FB31F50E7CB7593BE2B56F2F210606CC1"), // rhx-hkdf-512
			std::string("0C22A85505046FDF17D3968B6BDE2AF95274A329B844686EE82C7C7A5CC7AB20598CA5D484091892968FA65835BB67CEDBD15D12984EB7836F0E32239B3AFB35"), // rhx-shake-256
			std::string("60A95DE7B5BA9697AF3E9B7278F41543D0465C18D14DACA3A23649786E2A32015E321FF104A2034B6EF322291F52C0BFA31AC67E9AB991DFEB0B0C74157221BB"), // rhx-shake-512
			std::string("4AF4B64FD67455988C903464D0F50DFF2537342A895B5AFC4A09F16903D944A1C88D6BB3304EAE36543D2263FA90FD6B93240595E2D0FEC81173445A38B2D022"), // sepent256
			std::string("AC054DC3FFC1A13AEABA21AA98359DE8A5ED0311FFDA13BBB92BAF17D78EAB3BAD14B17519DDE09BB97028D244463BBD9EC65437B2822DB6199C6AE298FCE898"), // shx-hkdf-256
			std::string("AE1CC1D37270A23F06A2A7E4C1059AB868A3C326CFF4794BDEA8CCE1B22095D2784C0EF2F2948718314ADD3DF5F6741DE33C44312EFD2C8F3AB40ED2F98B707B"), // shx-hkdf-512
			std::string("8C975A9C35104588B60C76D17BE4BF84DC7AA367A2954DFE9514FA4C4E87B1546C849320932CEF4FBACBB83437A62E31EA769CBFB34B15CE078222A60B3B8285"), // shx-shake-256
			std::string("86574FABC40DC40D2951DD97A8D31010482A11B49C024F6AE46DA41F63F5FC5A8DA12CD7113D09FF7DC0A898D7CED764503636AF702AC0D4DD808C0ED9ABFFC3")  // shx-shake-512
		};
		HexConverter::Decode(expected, 10, m_expected);

		/*lint -restore */
	}

	void BCGTest::Kat(IDrbg* Rng, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t EXPLEN = Expected.size();
		std::vector<byte> exp(EXPLEN);
		SymmetricKey kp(Key, Nonce);

		// generate
		Rng->Initialize(kp);
		Rng->Generate(exp, 0, EXPLEN);

		if (exp != Expected)
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -BK1"));
		}
	}

	void BCGTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void BCGTest::Stress()
	{
		CTR cpr(BlockCiphers::Rijndael);
		const uint MINPRL = static_cast<uint>(cpr.ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(cpr.ParallelProfile().ParallelBlockSize() * 4);
		BCG drbg(BlockCiphers::Rijndael, BlockCipherExtensions::None, Providers::None);
		Key::Symmetric::SymmetricKeySize ks = cpr.LegalKeySizes()[1];

		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXM_ALLOC);
		inp.reserve(MAXM_ALLOC);
		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			cpt.resize(INPLEN, 0x00);
			inp.resize(INPLEN, 0x00);
			otp.resize(INPLEN, 0x00);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(iv, 0, iv.size(), rnd);
			SymmetricKey kp(key, iv);

			// encrypt with aes
			cpr.Initialize(true, kp);
			cpr.Transform(inp, 0, cpt, 0, INPLEN);
			// decrypt
			drbg.Initialize(kp);
			drbg.Generate(otp, 0, INPLEN);

			if (otp != cpt)
			{
				throw TestException(std::string("Stress: Transformation output is not equal! -TS1"));
			}
		}
	}
}
