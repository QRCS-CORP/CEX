#include "SerpentTest.h"
#include "../CEX/CTR.h"
#include "../CEX/SHX.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Cipher::Block::Mode::CTR;
	using Tools::IntegerTools;
	using Prng::SecureRandom;
	using namespace Cipher::Block;
	using namespace TestFiles::Nessie;
 
	const std::string SerpentTest::CLASSNAME = "SerpentTest";
	const std::string SerpentTest::DESCRIPTION = "Serpent Nessie tests, with 100 and 1000 round Monte Carlo runs.";
	const std::string SerpentTest::SUCCESS = "SUCCESS! All Serpent tests have executed succesfully.";

	//~~~Constructor~~~//

	SerpentTest::SerpentTest()
		:
		m_expected(0),
		m_keys(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	SerpentTest::~SerpentTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_keys);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string SerpentTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SerpentTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string SerpentTest::Run()
	{
		try
		{
			Exception();
			OnProgress(std::string("SerpentTest: Passed Serpent exception handling tests.."));
			// serpent-128 vectors
			Kat128();
			OnProgress(std::string("SerpentTest: Passed Serpent-128 known answer and monte carlo tests.."));
			// serpent-192 vectors
			Kat192();
			OnProgress(std::string("SerpentTest: Passed Serpent-192 known answer and monte carlo tests.."));
			// serpent-256 vectors
			Kat256();
			OnProgress(std::string("SerpentTest: Passed Serpent-256 known answer and monte carlo tests.."));

			SHX* cpr1 = new SHX(BlockCipherExtensions::HKDF256);
			KatEx(cpr1, m_keys[0], m_message[0], m_expected[0]);
			delete cpr1;
			SHX* cpr2 = new SHX(BlockCipherExtensions::HKDF512);
			KatEx(cpr2, m_keys[1], m_message[0], m_expected[1]);
			delete cpr2;
			SHX* cpr3 = new SHX(BlockCipherExtensions::SHAKE256);
			KatEx(cpr3, m_keys[0], m_message[0], m_expected[2]);
			delete cpr3;
			SHX* cpr4 = new SHX(BlockCipherExtensions::SHAKE512);
			KatEx(cpr4, m_keys[1], m_message[0], m_expected[3]);
			delete cpr4;
			OnProgress(std::string("SerpentTest: Passed SHX extended cipher known answer tests.."));

			SHX* cpr5 = new SHX(BlockCipherExtensions::HKDF256);
			MonteCarloEx(cpr5, m_keys[0], m_message[0], m_expected[4]);
			delete cpr5;
			SHX* cpr6 = new SHX(BlockCipherExtensions::HKDF512);
			MonteCarloEx(cpr6, m_keys[1], m_message[0], m_expected[5]);
			delete cpr6;
			SHX* cpr7 = new SHX(BlockCipherExtensions::SHAKE256);
			MonteCarloEx(cpr7, m_keys[0], m_message[0], m_expected[6]);
			delete cpr7;
			SHX* cpr8 = new SHX(BlockCipherExtensions::SHAKE512);
			MonteCarloEx(cpr8, m_keys[1], m_message[0], m_expected[7]);
			delete cpr8;
			OnProgress(std::string("SerpentTest: Passed SHX monte carlo known answer tests.."));

			CTR* cpr = new CTR(BlockCiphers::Serpent);
			Parallel(cpr);
			OnProgress(std::string("SerpentTest: Passed Serpent parallel to sequential equivalence test.."));

			Stress(cpr);
			OnProgress(std::string("SerpentTest: Passed Serpent stress tests.."));
			delete cpr;

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

	void SerpentTest::Exception()
	{
		// test initialization with illegal key input size
		try
		{
			SHX cpr;
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<uint8_t> k(ks.KeySize() + 1);
			SymmetricKey kp(k);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Kat"), cpr.Name(), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SerpentTest::Kat(std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected)
	{
		std::vector<uint8_t> exp(16);
		std::vector<uint8_t> otp(16);
		std::vector<uint8_t> msg = Message;
		SHX cpr;
		Cipher::SymmetricKey kp(Key);

		cpr.Initialize(true, kp);
		cpr.EncryptBlock(msg, otp);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat"), cpr.Name(), std::string("Arrays are not equal! -SC1"));
		}

		cpr.Initialize(false, kp);
		cpr.DecryptBlock(otp, msg);

		if (msg != Message)
		{
			throw TestException(std::string("Kat"), cpr.Name(), std::string("Arrays are not equal! -SC2"));
		}
	}

	void SerpentTest::Kat128()
	{
		// 128 bit keys
		std::vector<uint8_t> cip(16);
		std::vector<uint8_t> key(16);
		std::vector<uint8_t> pln(16);
		std::vector<uint8_t> mnt(16);
		std::string cipstr = "";
		std::string keystr = "";
		std::string plnstr = "";
		std::string mntstr = "";
		std::string mnt1kstr = "";

		TestUtils::FileRead(SERPENTCTEXT128, cipstr);

		if (cipstr.size() == 0)
		{
			throw TestException(std::string("Kat128"), std::string("SERPENTCTEXT128"), std::string("Could not find the test file! -SKS1"));
		}
		TestUtils::FileRead(SERPENTKEY128, keystr);
		if (keystr.size() == 0)
		{
			throw TestException(std::string("Kat128"), std::string("SERPENTKEY128"), std::string("Could not find the test file! -SKS2"));
		}
		TestUtils::FileRead(SERPENTPTEXT128, plnstr);
		if (plnstr.size() == 0)
		{
			throw TestException(std::string("Kat128"), std::string("SERPENTPTEXT128"), std::string("Could not find the test file! -SKS3"));
		}
		TestUtils::FileRead(SERPENTM100X128, mntstr);
		if (mntstr.size() == 0)
		{
			throw TestException(std::string("Kat128"), std::string("SERPENTM100X128"), std::string("Could not find the test file! -SKS4"));
		}
		TestUtils::FileRead(SERPENTM1000X128, mnt1kstr);
		if (mnt1kstr.size() == 0)
		{
			throw TestException(std::string("Kat128"), std::string("SERPENTM1000X128"), std::string("Could not find the test file! -SKS5"));
		}

		for (size_t i = 0; i < keystr.size(); i += 32)
		{
			// less monte carlo tests than vector
			bool domonte = i * 32 < mntstr.size();

			HexConverter::Decode(cipstr.substr(i, 32), cip);
			HexConverter::Decode(keystr.substr(i, 32), key);
			HexConverter::Decode(plnstr.substr(i, 32), pln);

			// *note* reversed endian ordered keys in Nessie test vectors
			TestUtils::Reverse(key);

			if (domonte)
			{
				HexConverter::Decode(mntstr.substr(i, 32), mnt);
				// monte carlo 100 rounds
				MonteCarlo(key, pln, mnt);
				// 1000 rounds
				HexConverter::Decode(mnt1kstr.substr(i, 32), mnt);
				MonteCarlo(key, pln, mnt, 1000);
			}

			// vector comparison
			Kat(key, pln, cip);
		}
	}

	void SerpentTest::Kat192()
	{
		std::vector<uint8_t> cip(16);
		std::vector<uint8_t> key(16);
		std::vector<uint8_t> pln(16);
		std::vector<uint8_t> mnt(16);
		std::string cipstr = "";
		std::string keystr = "";
		std::string plnstr = "";
		std::string mntstr = "";
		std::string mnt1kstr = "";

		// 192 bit keys
		TestUtils::FileRead(SERPENTCTEXT192, cipstr);
		if (cipstr.size() == 0)
		{
			throw TestException(std::string("Kat192"), std::string("SERPENTCTEXT192"), std::string("Could not find the test file! -SKM1"));
		}

		TestUtils::FileRead(SERPENTKEY192, keystr);
		if (keystr.size() == 0)
		{
			throw TestException(std::string("Kat192"), std::string("SERPENTKEY192"), std::string("Could not find the test file! -SKM2"));
		}

		TestUtils::FileRead(SERPENTPTEXT192, plnstr);
		if (plnstr.size() == 0)
		{
			throw TestException(std::string("Kat192"), std::string("SERPENTPTEXT192"), std::string("Could not find the test file! -SKM3"));
		}

		TestUtils::FileRead(SERPENTM100X192, mntstr);
		if (mntstr.size() == 0)
		{
			throw TestException(std::string("Kat192"), std::string("SERPENTM100X192"), std::string("Could not find the test file! -SKM4"));
		}

		TestUtils::FileRead(SERPENTM1000X192, mnt1kstr);
		if (mnt1kstr.size() == 0)
		{
			throw TestException(std::string("Kat192"), std::string("SERPENTM1000X192"), std::string("Could not find the test file! -SKM5"));
		}

		for (size_t i = 0, j = 0; j < keystr.size(); i += 32, j += 48)
		{
			bool domonte = i * 32 < mntstr.size();

			HexConverter::Decode(cipstr.substr(i, 32), cip);
			HexConverter::Decode(keystr.substr(j, 48), key);
			HexConverter::Decode(plnstr.substr(i, 32), pln);
			TestUtils::Reverse(key);

			if (domonte)
			{
				HexConverter::Decode(mntstr.substr(i, 32), mnt);
				// monte carlo 100 rounds
				MonteCarlo(key, pln, mnt);
				// 1000 rounds
				HexConverter::Decode(mnt1kstr.substr(i, 32), mnt);
				MonteCarlo(key, pln, mnt, 1000);
			}

			// vector comparison
			Kat(key, pln, cip);
		}
	}

	void SerpentTest::Kat256()
	{
		std::vector<uint8_t> cip(16);
		std::vector<uint8_t> key(16);
		std::vector<uint8_t> pln(16);
		std::vector<uint8_t> mnt(16);
		std::string cipstr = "";
		std::string keystr = "";
		std::string plnstr = "";
		std::string mntstr = "";
		std::string mnt1kstr = "";

		// 256 bit keys
		TestUtils::FileRead(SERPENTCTEXT256, cipstr);
		if (cipstr.size() == 0)
		{
			throw TestException(std::string("Kat256"), std::string("SERPENTCTEXT256"), std::string("Could not find the test file! -SKL1"));
		}

		TestUtils::FileRead(SERPENTKEY256, keystr);
		if (keystr.size() == 0)
		{
			throw TestException(std::string("Kat256"), std::string("SERPENTKEY256"), std::string("Could not find the test file! -SKL2"));
		}

		TestUtils::FileRead(SERPENTPTEXT256, plnstr);
		if (plnstr.size() == 0)
		{
			throw TestException(std::string("Kat256"), std::string("SERPENTPTEXT256"), std::string("Could not find the test file! -SKL3"));
		}

		TestUtils::FileRead(SERPENTM100X256, mntstr);
		if (mntstr.size() == 0)
		{
			throw TestException(std::string("Kat256"), std::string("SERPENTM100X256"), std::string("Could not find the test file! -SKL4"));
		}

		TestUtils::FileRead(SERPENTM1000X256, mnt1kstr);
		if (mnt1kstr.size() == 0)
		{
			throw TestException(std::string("Kat256"), std::string("SERPENTM1000X256"), std::string("Could not find the test file! -SKL5"));
		}

		for (size_t i = 0, j = 0; j < keystr.size(); i += 32, j += 64)
		{
			bool domonte = i * 32 < mntstr.size();

			HexConverter::Decode(cipstr.substr(i, 32), cip);
			HexConverter::Decode(keystr.substr(j, 64), key);
			HexConverter::Decode(plnstr.substr(i, 32), pln);
			TestUtils::Reverse(key);

			if (domonte)
			{
				HexConverter::Decode(mntstr.substr(i, 32), mnt);
				// monte carlo 100 rounds
				MonteCarlo(key, pln, mnt);
				// 1000 rounds
				HexConverter::Decode(mnt1kstr.substr(i, 32), mnt);
				MonteCarlo(key, pln, mnt, 1000);
			}

			// vector comparison
			Kat(key, pln, cip);
		}
	}

	void SerpentTest::KatEx(IBlockCipher* Cipher, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> enc(MSGLEN);
		std::vector<uint8_t> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key);

		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, enc, 0);

		if (enc != Expected)
		{
			throw TestException(std::string("KatEx"), Cipher->Name(), std::string("Encrypted arrays are not equal!"));
		}

		Cipher->Initialize(false, kp);
		Cipher->Transform(enc, 0, dec, 0);

		if (dec != Message)
		{
			throw TestException(std::string("KatEx"), Cipher->Name(), std::string("Decrypted arrays are not equal!"));
		}
	}

	void SerpentTest::MonteCarloEx(IBlockCipher* Cipher, std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> msg = Message;
		std::vector<uint8_t> enc(MSGLEN);
		std::vector<uint8_t> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0);
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarloEx"), Cipher->Name(), std::string("Arrays are not equal!"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0);
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarloEx"), Cipher->Name(), std::string("Arrays are not equal!"));
		}
	}

	void SerpentTest::MonteCarlo(std::vector<uint8_t> &Key, std::vector<uint8_t> &Message, std::vector<uint8_t> &Expected, size_t Count)
	{
		std::vector<uint8_t> otp(16);
		std::vector<uint8_t> msg = Message;
		SHX cpr;
		Cipher::SymmetricKey kp(Key);

		cpr.Initialize(true, kp);

		for (size_t i = 0; i != Count; i++)
		{
			cpr.Transform(otp, otp);
		}

		if (otp != Expected)
		{
			throw TestException(std::string("MonteCarlo"), cpr.Name(), std::string("Arrays are not equal! -SM1"));
		}
	}

	void SerpentTest::Parallel(ICipherMode* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<uint8_t> cpt1;
		std::vector<uint8_t> cpt2;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> otp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> iv(ks.IVSize());
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, INPLEN);
			SymmetricKey kp(key, iv);

			Cipher->ParallelProfile().SetBlockSize(Cipher->ParallelProfile().ParallelBlockSize());

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
		Cipher->ParallelProfile().SetBlockSize(prlSize);
	}

	void SerpentTest::Stress(ICipherMode* Cipher)
	{
		const uint32_t MINPRL = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint32_t MAXPRL = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<uint8_t> cpt;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> iv(ks.IVSize());
		std::vector<uint8_t> otp;
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, INPLEN);
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

	void SerpentTest::Initialize()
	{

		const std::vector<std::string> exp =
		{
			// shx kat tests: shx-hkdf256
			std::string("BA559D68B18F09C340D3D1D22D161FEC"),
			// shx-hkdf512
			std::string("46448B72184E8F3215B26C74A1F5702C"),
			// shx-shake256
			std::string("6AB8C4C869216165B59DDD568E27B425"),
			// shx-shake512
			std::string("F43E715FD5FE9EA0526BDBD81B204604"),
			// shx monte-carlo tests: shx-hkdf256
			std::string("B82E6CD9E9EF4223A757EDDCB470AEEA"),
			// shx-hkdf512
			std::string("6717843AB2CA17274A8FAA6975F8352D"),
			// shx-shake256
			std::string("E205E2DD4D8379C47495D95EFAE0A243"),
			// shx-shake512
			std::string("4E5EBEDBBAD24F7F10012A8F6CBBF085")
		};
		HexConverter::Decode(exp, 8, m_expected);

		const std::vector<std::string> keys =
		{
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A38628E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};
		HexConverter::Decode(keys, 2, m_keys);

		const std::vector<std::string> msg =
		{
			std::string("00000000000000000000000000000000")
		};
		HexConverter::Decode(msg, 1, m_message);
	}

	void SerpentTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
