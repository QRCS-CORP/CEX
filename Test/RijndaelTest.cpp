#include "RijndaelTest.h"
#if defined(__AVX__)
#	include "../CEX/AHX.h"
#endif
#include "../CEX/CTR.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Cipher::Block::Mode::CTR;
	using Utility::IntegerTools;
	using Prng::SecureRandom;
	using namespace Cipher::Block;

	const std::string RijndaelTest::CLASSNAME = "RijndaelTest";
	const std::string RijndaelTest::DESCRIPTION = "NIST AES specification FIPS 197 Known Answer Tests.";
	const std::string RijndaelTest::SUCCESS = "SUCCESS! AES tests have executed succesfully.";

	//~~~Constructor~~~//

	RijndaelTest::RijndaelTest(bool TestNI)
		:
		m_cipherText(0),
		m_keys(0),
		m_plainText(0),
		m_progressEvent(),
		m_testAesNi(TestNI)
	{
		Initialize();
	}

	RijndaelTest::~RijndaelTest()
	{
		IntegerTools::Clear(m_cipherText);
		IntegerTools::Clear(m_keys);
		IntegerTools::Clear(m_plainText);
		m_testAesNi = false;
	}

	//~~~Accessors~~~//

	const std::string RijndaelTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RijndaelTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string RijndaelTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("RijndaelTest: Passed Rijndael exception handling tests.."));

#if defined(__AVX__)
			if (m_testAesNi)
			{
				AHX* cpr1 = new AHX();
				Kat(cpr1, m_keys[0], m_plainText[0], m_cipherText[0]);
				Kat(cpr1, m_keys[1], m_plainText[1], m_cipherText[1]);
				Kat(cpr1, m_keys[2], m_plainText[2], m_cipherText[2]);
				Kat(cpr1, m_keys[3], m_plainText[3], m_cipherText[3]);
				Kat(cpr1, m_keys[4], m_plainText[4], m_cipherText[4]);
				Kat(cpr1, m_keys[5], m_plainText[5], m_cipherText[5]);
				Kat(cpr1, m_keys[6], m_plainText[6], m_cipherText[6]);
				Kat(cpr1, m_keys[7], m_plainText[7], m_cipherText[7]);
				Kat(cpr1, m_keys[8], m_plainText[8], m_cipherText[8]);
				Kat(cpr1, m_keys[9], m_plainText[9], m_cipherText[9]);
				Kat(cpr1, m_keys[10], m_plainText[10], m_cipherText[10]);
				Kat(cpr1, m_keys[11], m_plainText[11], m_cipherText[11]);
				delete cpr1;

				AHX* cpr2 = new AHX(BlockCipherExtensions::HKDF256);
				Kat(cpr2, m_keys[24], m_plainText[0], m_cipherText[24]);
				delete cpr2;
				AHX* cpr3 = new AHX(BlockCipherExtensions::HKDF512);
				Kat(cpr3, m_keys[25], m_plainText[0], m_cipherText[25]);
				delete cpr3;
				AHX* cpr4 = new AHX(BlockCipherExtensions::SHAKE256);
				Kat(cpr4, m_keys[24], m_plainText[0], m_cipherText[26]);
				delete cpr4;
				AHX* cpr5 = new AHX(BlockCipherExtensions::SHAKE512);
				Kat(cpr5, m_keys[25], m_plainText[0], m_cipherText[27]);
				delete cpr5;
			}
			else
#endif
			{
				RHX* cpr1 = new RHX();
				Kat(cpr1, m_keys[0], m_plainText[0], m_cipherText[0]);
				Kat(cpr1, m_keys[1], m_plainText[1], m_cipherText[1]);
				Kat(cpr1, m_keys[2], m_plainText[2], m_cipherText[2]);
				Kat(cpr1, m_keys[3], m_plainText[3], m_cipherText[3]);
				Kat(cpr1, m_keys[4], m_plainText[4], m_cipherText[4]);
				Kat(cpr1, m_keys[5], m_plainText[5], m_cipherText[5]);
				Kat(cpr1, m_keys[6], m_plainText[6], m_cipherText[6]);
				Kat(cpr1, m_keys[7], m_plainText[7], m_cipherText[7]);
				Kat(cpr1, m_keys[8], m_plainText[8], m_cipherText[8]);
				Kat(cpr1, m_keys[9], m_plainText[9], m_cipherText[9]);
				Kat(cpr1, m_keys[10], m_plainText[10], m_cipherText[10]);
				Kat(cpr1, m_keys[11], m_plainText[11], m_cipherText[11]);
				delete cpr1;

				RHX* cpr2 = new RHX(BlockCipherExtensions::HKDF256);
				Kat(cpr2, m_keys[24], m_plainText[0], m_cipherText[24]);
				delete cpr2;
				RHX* cpr3 = new RHX(BlockCipherExtensions::HKDF512);
				Kat(cpr3, m_keys[25], m_plainText[0], m_cipherText[25]);
				delete cpr3;
				RHX* cpr4 = new RHX(BlockCipherExtensions::SHAKE256);
				Kat(cpr4, m_keys[24], m_plainText[0], m_cipherText[26]);
				delete cpr4;
				RHX* cpr5 = new RHX(BlockCipherExtensions::SHAKE512);
				Kat(cpr5, m_keys[25], m_plainText[0], m_cipherText[27]);
				delete cpr5;
			}

			OnProgress(std::string("RijndaelTest: Passed Rijndael FIPS 197 KAT tests.."));

#if defined(__AVX__)
			if (m_testAesNi)
			{
				AHX* cpr1 = new AHX();
				MonteCarlo(cpr1, m_keys[12], m_plainText[12], m_cipherText[12]);
				MonteCarlo(cpr1, m_keys[13], m_plainText[13], m_cipherText[13]);
				MonteCarlo(cpr1, m_keys[14], m_plainText[14], m_cipherText[14]);
				MonteCarlo(cpr1, m_keys[15], m_plainText[15], m_cipherText[15]);
				MonteCarlo(cpr1, m_keys[16], m_plainText[16], m_cipherText[16]);
				MonteCarlo(cpr1, m_keys[17], m_plainText[17], m_cipherText[17]);
				MonteCarlo(cpr1, m_keys[18], m_plainText[18], m_cipherText[18]);
				MonteCarlo(cpr1, m_keys[19], m_plainText[19], m_cipherText[19]);
				MonteCarlo(cpr1, m_keys[20], m_plainText[20], m_cipherText[20]);
				MonteCarlo(cpr1, m_keys[21], m_plainText[21], m_cipherText[21]);
				MonteCarlo(cpr1, m_keys[22], m_plainText[22], m_cipherText[22]);
				MonteCarlo(cpr1, m_keys[23], m_plainText[23], m_cipherText[23]);
				delete cpr1;

				AHX* cpr2 = new AHX(BlockCipherExtensions::HKDF256);
				MonteCarlo(cpr2, m_keys[24], m_plainText[0], m_cipherText[28]);
				delete cpr2;
				AHX* cpr3 = new AHX(BlockCipherExtensions::HKDF512);
				MonteCarlo(cpr3, m_keys[25], m_plainText[0], m_cipherText[29]);
				delete cpr3;
				AHX* cpr4 = new AHX(BlockCipherExtensions::SHAKE256);
				MonteCarlo(cpr4, m_keys[24], m_plainText[0], m_cipherText[30]);
				delete cpr4;
				AHX* cpr5 = new AHX(BlockCipherExtensions::SHAKE512);
				MonteCarlo(cpr5, m_keys[25], m_plainText[0], m_cipherText[31]);
				delete cpr5;
			}
			else
#endif
			{
				RHX* cpr1 = new RHX();
				MonteCarlo(cpr1, m_keys[12], m_plainText[12], m_cipherText[12]);
				MonteCarlo(cpr1, m_keys[13], m_plainText[13], m_cipherText[13]);
				MonteCarlo(cpr1, m_keys[14], m_plainText[14], m_cipherText[14]);
				MonteCarlo(cpr1, m_keys[15], m_plainText[15], m_cipherText[15]);
				MonteCarlo(cpr1, m_keys[16], m_plainText[16], m_cipherText[16]);
				MonteCarlo(cpr1, m_keys[17], m_plainText[17], m_cipherText[17]);
				MonteCarlo(cpr1, m_keys[18], m_plainText[18], m_cipherText[18]);
				MonteCarlo(cpr1, m_keys[19], m_plainText[19], m_cipherText[19]);
				MonteCarlo(cpr1, m_keys[20], m_plainText[20], m_cipherText[20]);
				MonteCarlo(cpr1, m_keys[21], m_plainText[21], m_cipherText[21]);
				MonteCarlo(cpr1, m_keys[22], m_plainText[22], m_cipherText[22]);
				MonteCarlo(cpr1, m_keys[23], m_plainText[23], m_cipherText[23]);
				delete cpr1;

				RHX* cpr2 = new RHX(BlockCipherExtensions::HKDF256);
				MonteCarlo(cpr2, m_keys[24], m_plainText[0], m_cipherText[28]);
				delete cpr2;
				RHX* cpr3 = new RHX(BlockCipherExtensions::HKDF512);
				MonteCarlo(cpr3, m_keys[25], m_plainText[0], m_cipherText[29]);
				delete cpr3;
				RHX* cpr4 = new RHX(BlockCipherExtensions::SHAKE256);
				MonteCarlo(cpr4, m_keys[24], m_plainText[0], m_cipherText[30]);
				delete cpr4;
				RHX* cpr5 = new RHX(BlockCipherExtensions::SHAKE512);
				MonteCarlo(cpr5, m_keys[25], m_plainText[0], m_cipherText[31]);
				delete cpr5;
			}

			OnProgress(std::string("RijndaelTest: Passed Rijndael extended Monte Carlo tests.."));

#if defined(__AVX__)
			if (m_testAesNi)
			{
				CTR* cpr1 = new CTR(BlockCiphers::AHX);
				Parallel(cpr1);
				OnProgress(std::string("RijndaelTest: Passed Rijndael parallel to sequential equivalence test.."));

				Stress(cpr1);
				OnProgress(std::string("RijndaelTest: Passed Rijndaelstress tests.."));
				delete cpr1;
			}
			else
#endif
			{
				CTR* cpr2 = new CTR(BlockCiphers::Rijndael);
				Parallel(cpr2);
				OnProgress(std::string("RijndaelTest: Passed Rijndael parallel to sequential equivalence test.."));

				Stress(cpr2);
				OnProgress(std::string("RijndaelTest: Passed Rijndaelstress tests.."));
				delete cpr2;
			}
			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void RijndaelTest::Exception()
	{
		// test initialization with illegal key input size
		try
		{
			RHX cpr;
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> k(ks.KeySize() + 1);
			SymmetricKey kp(k);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE1"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test illegal custom setting through enum constructor
		try
		{
			RHX cpr(BlockCipherExtensions::Custom);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE2"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test illegal null value through instance constructor
		try
		{
			RHX cpr(nullptr);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -RE3"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RijndaelTest::Kat(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key);

		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, enc, 0);

		if (enc != Expected)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Encrypted arrays are not equal!"));
		}

		Cipher->Initialize(false, kp);
		Cipher->Transform(enc, 0, dec, 0);

		if (dec != Message)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted arrays are not equal!"));
		}
	}

	void RijndaelTest::MonteCarlo(IBlockCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0);
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Arrays are not equal! -RM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0);
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Arrays are not equal! -RM2"));
		}
	}

	void RijndaelTest::Parallel(ICipherMode* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
		Prng::SecureRandom rnd;
		size_t prlSize = Cipher->ParallelProfile().ParallelBlockSize();

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.resize(INPLEN);
			cpt2.resize(INPLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, INPLEN, rnd);
			SymmetricKey kp(key, iv);

			Cipher->ParallelProfile().ParallelBlockSize() = Cipher->ParallelProfile().ParallelMinimumSize();

			// sequential
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, INPLEN);

			// parallel
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, INPLEN);

			if (cpt1 != cpt2)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -TP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, INPLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -TP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void RijndaelTest::Stress(ICipherMode* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

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
			cpt.resize(INPLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, INPLEN, rnd);
			SymmetricKey kp(key, iv);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, INPLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, INPLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -TS1"));
			}
		}
	}

	//~~~Private Functions~~~//

	void RijndaelTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e417 */
		const std::vector<std::string> keys =
		{
			// fips
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			// gladman
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			// hx cipher original vectors
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};
		HexConverter::Decode(keys, 26, m_keys);

		const std::vector<std::string> plainText =
		{
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),

			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22"),
			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22"),
			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22")

		};
		HexConverter::Decode(plainText, 24, m_plainText);

		const std::vector<std::string> cipherText =
		{
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),

			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168"),
			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168"),
			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168"),

			std::string("EB6B1FC020CC3362F2EEDC95B4DB0F5F"),
			std::string("29E7C52BA5DC968A0AD23AF93EA6E0E0"),
			std::string("1335B6AFC51238E28536EDCD587A3697"),
			std::string("046AB3836C6FA2DDD3964A5C7E4BC3E8"),

			std::string("8B2D43CAD3F2F0B80A15AAF07DCFC696"),
			std::string("686A2F305D9C8F2D1F9A8EC598F269F3"),
			std::string("3F15DBA9166C355EEB2333078967390B"),
			std::string("5ddd6f44ba84bcca80189d098eec5293")
		};
		HexConverter::Decode(cipherText, 32, m_cipherText);
		/*lint -restore */
	}

	void RijndaelTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
