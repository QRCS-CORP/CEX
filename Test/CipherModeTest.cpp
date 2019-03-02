#include "CipherModeTest.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/CTR.h"
#include "../CEX/ECB.h"
#include "../CEX/ICM.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/OFB.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Cipher::Block::Mode;
	using Enumeration::BlockCiphers;
	using Enumeration::CipherModeConvert;
	using Utility::IntegerTools;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;

	const std::string CipherModeTest::CLASSNAME = "CipherModeTest";
	const std::string CipherModeTest::DESCRIPTION = "NIST SP800-38A KATs testing CBC, CFB, CTR, ECB, and OFB modes.";
	const std::string CipherModeTest::SUCCESS = "SUCCESS! Cipher Mode tests have executed succesfully.";

	//~~~Constructor~~~//

	CipherModeTest::CipherModeTest()
		:
		m_expected(0),
		m_keys(0),
		m_message(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	CipherModeTest::~CipherModeTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_keys);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string CipherModeTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CipherModeTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string CipherModeTest::Run()
	{
		// test modes with each key (128/192/256)
		try
		{
			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("CipherModeTest: Passed CBC/CFB/CTR/ECB/ICM/OFB exception handling tests.."));

			CBC* cbcm = new CBC(BlockCiphers::AES);
			CFB* cfbm = new CFB(BlockCiphers::AES);
			CTR* ctrm = new CTR(BlockCiphers::AES);
			ECB* ecbm = new ECB(BlockCiphers::AES);
			ICM* icmm = new ICM(BlockCiphers::AES);
			OFB* ofbm = new OFB(BlockCiphers::AES);

			// CBC 128bit key
			Kat(cbcm, m_keys[0], m_nonce[0], m_message[0], m_expected[0], true);
			Kat(cbcm, m_keys[0], m_nonce[0], m_message[1], m_expected[1], false);
			// 192bit
			Kat(cbcm, m_keys[1], m_nonce[0], m_message[2], m_expected[2], true);
			Kat(cbcm, m_keys[1], m_nonce[0], m_message[3], m_expected[3], false);
			// 256bit
			Kat(cbcm, m_keys[2], m_nonce[0], m_message[4], m_expected[4], true);
			Kat(cbcm, m_keys[2], m_nonce[0], m_message[5], m_expected[5], false);
			OnProgress(std::string("CipherModeTest: Passed CBC 128/192/256 bit key encryption/decryption tests.."));

			// CFB 128bit key
			Register();
			OnProgress(std::string("CipherModeTest: Passed CFB-256 8-bit feedback register tests.."));
			Kat(cfbm, m_keys[0], m_nonce[0], m_message[6], m_expected[6], true);
			Kat(cfbm, m_keys[0], m_nonce[0], m_message[7], m_expected[7], false);
			// 192bit
			Kat(cfbm, m_keys[1], m_nonce[0], m_message[8], m_expected[8], true);
			Kat(cfbm, m_keys[1], m_nonce[0], m_message[9], m_expected[9], false);
			// 256bit
			Kat(cfbm, m_keys[2], m_nonce[0], m_message[10], m_expected[10], true);
			Kat(cfbm, m_keys[2], m_nonce[0], m_message[11], m_expected[11], false);
			OnProgress(std::string("CipherModeTest: Passed CFB 128/192/256 bit key encryption/decryption tests.."));

			// CTR 128bit key
			Kat(ctrm, m_keys[0], m_nonce[1], m_message[12], m_expected[12], true);
			Kat(ctrm, m_keys[0], m_nonce[1], m_message[13], m_expected[13], false);
			// 192bit
			Kat(ctrm, m_keys[1], m_nonce[1], m_message[14], m_expected[14], true);
			Kat(ctrm, m_keys[1], m_nonce[1], m_message[15], m_expected[15], false);
			// 256bit
			Kat(ctrm, m_keys[2], m_nonce[1], m_message[16], m_expected[16], true);
			Kat(ctrm, m_keys[2], m_nonce[1], m_message[17], m_expected[17], false);
			OnProgress(std::string("CipherModeTest: Passed CTR 128/192/256 bit key encryption/decryption tests.."));

			// ECB 128bit key
			Kat(ecbm, m_keys[0], m_nonce[2], m_message[18], m_expected[18], true);
			Kat(ecbm, m_keys[0], m_nonce[2], m_message[19], m_expected[19], false);
			// 192bit
			Kat(ecbm, m_keys[1], m_nonce[2], m_message[20], m_expected[20], true);
			Kat(ecbm, m_keys[1], m_nonce[2], m_message[21], m_expected[21], false);
			// 256bit
			Kat(ecbm, m_keys[2], m_nonce[2], m_message[22], m_expected[22], true);
			Kat(ecbm, m_keys[2], m_nonce[2], m_message[23], m_expected[23], false);
			OnProgress(std::string("CipherModeTest: Passed ECB 128/192/256 bit key encryption/decryption tests.."));

			// ICM 128bit key
			Kat(icmm, m_keys[0], m_nonce[1], m_message[24], m_expected[24], true);
			Kat(icmm, m_keys[0], m_nonce[1], m_message[25], m_expected[25], false);
			// 192bit
			Kat(icmm, m_keys[1], m_nonce[1], m_message[26], m_expected[26], true);
			Kat(icmm, m_keys[1], m_nonce[1], m_message[27], m_expected[27], false);
			// 256bit
			Kat(icmm, m_keys[2], m_nonce[1], m_message[28], m_expected[28], true);
			Kat(icmm, m_keys[2], m_nonce[1], m_message[29], m_expected[29], false);
			OnProgress(std::string("CipherModeTest: Passed ICM 128/192/256 bit key encryption/decryption tests.."));

			// OFB 128bit key
			Kat(ofbm, m_keys[0], m_nonce[0], m_message[30], m_expected[30], true);
			Kat(ofbm, m_keys[0], m_nonce[0], m_message[31], m_expected[31], false);
			// 192bit
			Kat(ofbm, m_keys[1], m_nonce[0], m_message[32], m_expected[32], true);
			Kat(ofbm, m_keys[1], m_nonce[0], m_message[33], m_expected[33], false);
			// 256bit
			Kat(ofbm, m_keys[2], m_nonce[0], m_message[34], m_expected[34], true);
			Kat(ofbm, m_keys[2], m_nonce[0], m_message[35], m_expected[35], false);
			OnProgress(std::string("CipherModeTest: Passed OFB 128/192/256 bit key encryption/decryption tests.."));

			Stress(cbcm);
			OnProgress(std::string("Passed CBC stress tests.."));

			Stress(cfbm);
			OnProgress(std::string("Passed CFB stress tests.."));

			Stress(ctrm);
			OnProgress(std::string("Passed CTR stress tests.."));

			Stress(icmm);
			OnProgress(std::string("Passed ICM stress tests.."));

			Stress(ofbm);
			OnProgress(std::string("Passed OFB stress tests.."));

			delete cbcm;
			delete cfbm;
			delete ctrm;
			delete ecbm;
			delete icmm;
			delete ofbm;

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

	void CipherModeTest::Exception()
	{
		// test every modes enumeration constructors for invalid block-cipher type //

		try
		{
			CBC cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CBC), std::string("Exception handling failure! -ME1"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CFB cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CFB), std::string("Exception handling failure! -ME2"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CTR cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CTR), std::string("Exception handling failure! -ME3"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ECB cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ECB), std::string("Exception handling failure! -ME4"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ICM cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ICM), std::string("Exception handling failure! -ME5"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			OFB cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::OFB), std::string("Exception handling failure! -ME6"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test every modes pointer constructor for invalid cipher //

		try
		{
			CBC cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CBC), std::string("Exception handling failure! -ME7"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CFB cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CFB), std::string("Exception handling failure! -ME8"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CTR cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CTR), std::string("Exception handling failure! -ME9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ECB cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ECB), std::string("Exception handling failure! -ME10"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ICM cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ICM), std::string("Exception handling failure! -ME11"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			OFB cpr(nullptr);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::OFB), std::string("Exception handling failure! -ME12"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test every modes initialization with an invalid key size //

		try
		{
			CBC cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CBC), std::string("Threefish"), std::string("Exception handling failure! -ME13"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CFB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CFB), std::string("Threefish"), std::string("Exception handling failure! -ME14"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CTR cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CTR), std::string("Threefish"), std::string("Exception handling failure! -ME15"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ECB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ECB), std::string("Threefish"), std::string("Exception handling failure! -ME16"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ICM cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ICM), std::string("Threefish"), std::string("Exception handling failure! -ME17"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			OFB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::OFB), std::string("Threefish"), std::string("Exception handling failure! -ME18"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test each modes initialization with an invalid nonce size //

		try
		{
			CBC cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize() - 1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CBC), std::string("Threefish"), std::string("Exception handling failure! -ME19"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CFB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(0);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CFB), std::string("Threefish"), std::string("Exception handling failure! -ME20"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CTR cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize() - 1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CTR), std::string("Threefish"), std::string("Exception handling failure! -ME21"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ICM cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize() - 1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ICM), std::string("Threefish"), std::string("Exception handling failure! -ME23"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			OFB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize() - 1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::OFB), std::string("Threefish"), std::string("Exception handling failure! -ME24"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test each mode for invalid parallel options //

		try
		{
			CBC cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CBC), std::string("Threefish"), std::string("Exception handling failure! -ME25"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			CFB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::CFB), std::string("Threefish"), std::string("Exception handling failure! -ME26"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ECB cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ECB), std::string("Threefish"), std::string("Exception handling failure! -ME27"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			ICM cpr(Enumeration::BlockCiphers::AES);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), CipherModeConvert::ToName(CipherModes::ICM), std::string("Threefish"), std::string("Exception handling failure! -ME28"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CipherModeTest::Kat(ICipherMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<std::vector<byte>> &Message, std::vector<std::vector<byte>> &Expected, bool Encryption)
	{
		std::vector<byte> otp(16);

		if (Nonce.size() == 0)
		{
			SymmetricKey kp(Key);
			Cipher->Initialize(Encryption, kp);
		}
		else
		{
			SymmetricKey kp(Key, Nonce);
			Cipher->Initialize(Encryption, kp);
		}

		for (size_t i = 0; i < 4; ++i)
		{
			Cipher->Transform(Message[i], 0, otp, 0, otp.size());

			if (otp != Expected[i])
			{
				throw TestException(std::string("Kat"), Cipher->Name(), "Encrypted arrays are not equal! -CK1");
			}
		}
	}

	void CipherModeTest::Register()
	{
		std::vector<byte> inp;
		HexConverter::Decode(std::string("6BC1BEE22E409F96E93D7E117393172AAE2D"), inp); // F.3.11 CFB8-AES256.Encrypt
		std::vector<byte> otp;
		HexConverter::Decode(std::string("DC1F1A8520A64DB55FCC8AC554844E889700"), otp);
		std::vector<byte> enc(inp.size());
		std::vector<byte> msg(inp.size());

		// test 1-byte feedback-register against the official vectors
		CFB* mcfb = new CFB(BlockCiphers::AES, 1);
		SymmetricKey kp(m_keys[2], m_nonce[0]);

		// encryption test
		mcfb->Initialize(true, kp);
		mcfb->Transform(inp, 0, enc, 0, enc.size());

		if (!IntegerTools::Compare(enc, 0, otp, 0, otp.size()))
		{
			throw TestException(std::string("CfbPartial"), mcfb->Name(), "Encrypted arrays are not equal! -CC1");
		}

		// decryption
		mcfb->Initialize(false, kp);
		mcfb->Transform(enc, 0, msg, 0, msg.size());

		if (!IntegerTools::Compare(inp, 0, msg, 0, otp.size()))
		{
			throw TestException(std::string("CfbPartial"), mcfb->Name(), "Encrypted arrays are not equal! -CC2");
		}
	}

	//~~~Private Functions~~~//

	void CipherModeTest::Initialize()
	{
		const std::vector<std::string> keys =
		{
			std::string("2B7E151628AED2A6ABF7158809CF4F3C"),//F.1/F.2/F.3/F.5 -128
			std::string("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"),//F.1/F.2/F.3/F.5 -192
			std::string("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"),//F.1/F.2/F.3/F.5 -256
		};
		HexConverter::Decode(keys, 3, m_keys);

		const std::vector<std::string> nonce =
		{
			std::string("000102030405060708090A0B0C0D0E0F"),//F.1/F.2/F.3
			std::string("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),//F.5
			std::string("")
		};
		HexConverter::Decode(nonce, 3, m_nonce);

		const std::vector<std::vector<std::string>> input =
		{
			// cbc input
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.1 CBC-AES128.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("7649ABAC8119B246CEE98E9B12E9197D"),//F.2.2 CBC-AES128.DECRYPT
				std::string("5086CB9B507219EE95DB113A917678B2"),
				std::string("73BED6B8E3C1743B7116E69E22229516"),
				std::string("3FF1CAA1681FAC09120ECA307586E1A7")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.3 CBC-AES192.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("4F021DB243BC633D7178183A9FA071E8"),//F.2.4 CBC-AES192.DECRYPT
				std::string("B4D9ADA9AD7DEDF4E5E738763F69145A"),
				std::string("571B242012FB7AE07FA9BAAC3DF102E0"),
				std::string("08B0E27988598881D920A9E64F5615CD")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.5 CBC-AES256.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),//F.2.6 CBC-AES256.DECRYPT
				std::string("9CFC4E967EDB808D679F777BC6702C7D"),
				std::string("39F23369A9D9BACFA530E26304231461"),
				std::string("B2EB05E2C39BE9FCDA6C19078C6A9D1B")
			},

			// cfb input
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.13 CFB128-AES128.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("3B3FD92EB72DAD20333449F8E83CFB4A"),//F.3.14 CFB128-AES128.DECRYPT
				std::string("C8A64537A0B3A93FCDE3CDAD9F1CE58B"),
				std::string("26751F67A3CBB140B1808CF187A4F4DF"),
				std::string("C04B05357C5D1C0EEAC4C66F9FF7F2E6")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.15 CFB128-AES192.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("CDC80D6FDDF18CAB34C25909C99A4174"),//F.3.16 CFB128-AES192.DECRYPT
				std::string("67CE7F7F81173621961A2B70171D3D7A"),
				std::string("2E1E8A1DD59B88B1C8E60FED1EFAC4C9"),
				std::string("C05F9F9CA9834FA042AE8FBA584B09FF")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.17 CFB128-AES256.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("DC7E84BFDA79164B7ECD8486985D3860"),//F.3.18 CFB128-AES256.DECRYPT
				std::string("39FFED143B28B1C832113C6331E5407B"),
				std::string("DF10132415E54B92A13ED0A8267AE2F9"),
				std::string("75A385741AB9CEF82031623D55B1E471")
			},

			// ctr input
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.1 CTR-AES128.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("874D6191B620E3261BEF6864990DB6CE"),//F.5.2 CTR-AES128.DECRYPT
				std::string("9806F66B7970FDFF8617187BB9FFFDFF"),
				std::string("5AE4DF3EDBD5D35E5B4F09020DB03EAB"),
				std::string("1E031DDA2FBE03D1792170A0F3009CEE")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.3 CTR-AES192.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("1ABC932417521CA24F2B0459FE7E6E0B"),//F.5.4 CTR-AES192.DECRYPT
				std::string("090339EC0AA6FAEFD5CCC2C6F4CE8E94"),
				std::string("1E36B26BD1EBC670D1BD1D665620ABF7"),
				std::string("4F78A7F6D29809585A97DAEC58C6B050")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.5 CTR-AES256.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("601EC313775789A5B7A7F504BBF3D228"),//F.5.6 CTR-AES256.DECRYPT
				std::string("F443E3CA4D62B59ACA84E990CACAF5C5"),
				std::string("2B0930DAA23DE94CE87017BA2D84988D"),
				std::string("DFC9C58DB67AADA613C2DD08457941A6")
			},

			{
				// ecb input
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.1 ECB-AES128.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("3AD77BB40D7A3660A89ECAF32466EF97"),//F.1.2 ECB-AES128.DECRYPT
				std::string("F5D3D58503B9699DE785895A96FDBAAF"),
				std::string("43B1CD7F598ECE23881B00E3ED030688"),
				std::string("7B0C785E27E8AD3F8223207104725DD4")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.3 ECB-AES192.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("BD334F1D6E45F25FF712A214571FA5CC"),//F.1.4 ECB-AES192.DECRYPT
				std::string("974104846D0AD3AD7734ECB3ECEE4EEF"),
				std::string("EF7AFD2270E2E60ADCE0BA2FACE6444E"),
				std::string("9A4B41BA738D6C72FB16691603C18E0E")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.5 ECB-AES256.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("F3EED1BDB5D2A03C064B5A7E3DB181F8"),//F.1.6 ECB-AES256.DECRYPT
				std::string("591CCB10D410ED26DC5BA74A31362870"),
				std::string("B6ED21B99CA6F4F9F153E7B1BEAFED1D"),
				std::string("23304B7A39F9F3FF067D8D8F9E24ECC7")
			},

			// icm input
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),// original vectors
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710"),
			},
			{
				std::string("3B3FD92EB72DAD20333449F8E83CFB4A"),
				std::string("7789508D16918F03F53C52DAC54ED825"),
				std::string("9740051E9C5FECF64344F7A82260EDCC"),
				std::string("304C6528F659C77866A510D9C1D6AE5E")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("CDC80D6FDDF18CAB34C25909C99A4174"),
				std::string("FCC28B8D4C63837C09E81700C1100401"),
				std::string("8D9A9AEAC0F6596F559C6D4DAF59A5F2"),
				std::string("6D9F200857CA6C3E9CAC524BD9ACC92A")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("DC7E84BFDA79164B7ECD8486985D3860"),
				std::string("4FEBDC6740D20B3AC88F6AD82A4FB08D"),
				std::string("71AB47A086E86EEDF39D1C5BBA97C408"),
				std::string("0126141D67F37BE8538F5A8BE740E484")
			},

			// ofb input
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.1 OFB-AES128.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710"),
			},
			{
				std::string("3B3FD92EB72DAD20333449F8E83CFB4A"),//F.4.2 OFB-AES128.DECRYPT
				std::string("7789508D16918F03F53C52DAC54ED825"),
				std::string("9740051E9C5FECF64344F7A82260EDCC"),
				std::string("304C6528F659C77866A510D9C1D6AE5E")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.3 OFB-AES192.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("CDC80D6FDDF18CAB34C25909C99A4174"),//F.4.4 OFB-AES192.DECRYPT
				std::string("FCC28B8D4C63837C09E81700C1100401"),
				std::string("8D9A9AEAC0F6596F559C6D4DAF59A5F2"),
				std::string("6D9F200857CA6C3E9CAC524BD9ACC92A")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.5 OFB-AES256.ENCRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("DC7E84BFDA79164B7ECD8486985D3860"),//F.4.6 OFB-AES256.DECRYPT
				std::string("4FEBDC6740D20B3AC88F6AD82A4FB08D"),
				std::string("71AB47A086E86EEDF39D1C5BBA97C408"),
				std::string("0126141D67F37BE8538F5A8BE740E484")
			}
		};

		m_message.resize(input.size());

		for (size_t i = 0; i < input.size(); ++i)
		{
			HexConverter::Decode(input[i], 4, m_message[i]);
		}

		const std::vector<std::vector<std::string>> output =
		{
			// cbc output
			{
				std::string("7649ABAC8119B246CEE98E9B12E9197D"),//F.2.1 CBC-AES128.ENCRYPT
				std::string("5086CB9B507219EE95DB113A917678B2"),
				std::string("73BED6B8E3C1743B7116E69E22229516"),
				std::string("3FF1CAA1681FAC09120ECA307586E1A7"),
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.2 CBC-AES128.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("4F021DB243BC633D7178183A9FA071E8"),//F.2.3 CBC-AES192.ENCRYPT
				std::string("B4D9ADA9AD7DEDF4E5E738763F69145A"),
				std::string("571B242012FB7AE07FA9BAAC3DF102E0"),
				std::string("08B0E27988598881D920A9E64F5615CD")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.4 CBC-AES192.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),//F.2.5 CBC-AES256.ENCRYPT
				std::string("9CFC4E967EDB808D679F777BC6702C7D"),
				std::string("39F23369A9D9BACFA530E26304231461"),
				std::string("B2EB05E2C39BE9FCDA6C19078C6A9D1B")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.2.6 CBC-AES256.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},

			// cfb output
			{
				std::string("3B3FD92EB72DAD20333449F8E83CFB4A"),//F.3.13 CFB128-AES128.ENCRYPT
				std::string("C8A64537A0B3A93FCDE3CDAD9F1CE58B"),
				std::string("26751F67A3CBB140B1808CF187A4F4DF"),
				std::string("C04B05357C5D1C0EEAC4C66F9FF7F2E6")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.14 CFB128-AES128.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("CDC80D6FDDF18CAB34C25909C99A4174"),//F.3.15 CFB128-AES192.ENCRYPT
				std::string("67CE7F7F81173621961A2B70171D3D7A"),
				std::string("2E1E8A1DD59B88B1C8E60FED1EFAC4C9"),
				std::string("C05F9F9CA9834FA042AE8FBA584B09FF")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.16 CFB128-AES192.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("DC7E84BFDA79164B7ECD8486985D3860"),//F.3.17 CFB128-AES256.ENCRYPT
				std::string("39FFED143B28B1C832113C6331E5407B"),
				std::string("DF10132415E54B92A13ED0A8267AE2F9"),
				std::string("75A385741AB9CEF82031623D55B1E471")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.3.6  CFB128-AES256.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},

			// ctr output
			{
				std::string("874D6191B620E3261BEF6864990DB6CE"),//F.5.1 CTR-AES128.ENCRYPT
				std::string("9806F66B7970FDFF8617187BB9FFFDFF"),
				std::string("5AE4DF3EDBD5D35E5B4F09020DB03EAB"),
				std::string("1E031DDA2FBE03D1792170A0F3009CEE")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.2 CTR-AES128.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("1ABC932417521CA24F2B0459FE7E6E0B"),//F.5.3 CTR-AES192.ENCRYPT
				std::string("090339EC0AA6FAEFD5CCC2C6F4CE8E94"),
				std::string("1E36B26BD1EBC670D1BD1D665620ABF7"),
				std::string("4F78A7F6D29809585A97DAEC58C6B050")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.4 CTR-AES192.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("601EC313775789A5B7A7F504BBF3D228"),//F.5.5 CTR-AES256.ENCRYPT
				std::string("F443E3CA4D62B59ACA84E990CACAF5C5"),
				std::string("2B0930DAA23DE94CE87017BA2D84988D"),
				std::string("DFC9C58DB67AADA613C2DD08457941A6")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.5.6 CTR-AES256.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},

			// ecb output
			{
				std::string("3AD77BB40D7A3660A89ECAF32466EF97"),//F.1.1 ECB-AES128.ENCRYPT
				std::string("F5D3D58503B9699DE785895A96FDBAAF"),
				std::string("43B1CD7F598ECE23881B00E3ED030688"),
				std::string("7B0C785E27E8AD3F8223207104725DD4")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.2 ECB-AES128.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("BD334F1D6E45F25FF712A214571FA5CC"),//F.1.3 ECB-AES192.ENCRYPT
				std::string("974104846D0AD3AD7734ECB3ECEE4EEF"),
				std::string("EF7AFD2270E2E60ADCE0BA2FACE6444E"),
				std::string("9A4B41BA738D6C72FB16691603C18E0E")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.4 ECB-AES192.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("F3EED1BDB5D2A03C064B5A7E3DB181F8"),//F.1.5 ECB-AES256.ENCRYPT
				std::string("591CCB10D410ED26DC5BA74A31362870"),
				std::string("B6ED21B99CA6F4F9F153E7B1BEAFED1D"),
				std::string("23304B7A39F9F3FF067D8D8F9E24ECC7")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.1.6 ECB-AES256.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},

			// icm
			{
				std::string("874D6191B620E3261BEF6864990DB6CE"),// original vectors
				std::string("40942591D7B44F49ABC19D33A44EF654"),
				std::string("CE58D2F0018F92A25F2CBB66138B9D76"),
				std::string("30FA4A40B1672EF346B79A7CBA910BA2")
			},
			{
				std::string("D7B3065D2F4DD190C1E65F8D02A25AAE"),
				std::string("9930FF4BDF266CD6C04AA04524AFA020"),
				std::string("69D0CBA83E8C9A45F9938DD72BE12255"),
				std::string("F6290B2D9871729C8D39CBDE9D2B92EC")
			},
			{
				std::string("1ABC932417521CA24F2B0459FE7E6E0B"),
				std::string("A96BA67E491106663D7EC507A8F99D84"),
				std::string("382BC373AD0FBFD0A0ADB80E0F6ACDF0"),
				std::string("2A0E8D70E1894D15B174E68EC3BA75BC")
			},
			{
				std::string("BCB520A9E4E30F9F92D4234144773855"),
				std::string("FB84A7A41B712986AA21BDAB2C4617D4"),
				std::string("857945DFCEA502AE10CA145ABA393AED"),
				std::string("B10E893D690CBA3C80F3F5BEFC7A8B86")
			},
			{
				std::string("601EC313775789A5B7A7F504BBF3D228"),
				std::string("274FDF42688E0EFFC86060F23F872DD5"),
				std::string("AC26133443FDB106D84329E99C4E1001"),
				std::string("A10D0C7966054DB1210DACEDD7ECBEF4")
			},
			{
				std::string("D7A1F94E836E007820570F93503DFD62"),
				std::string("C6898972365FA9599E58658650671309"),
				std::string("ED4548D266493BFACE25F4AB3CD386E6"),
				std::string("56B43C21DEB9AD4EDFA9B71DD6C06D60")
			},

			// ofb output
			{
				std::string("3B3FD92EB72DAD20333449F8E83CFB4A"),//F.4.1 OFB-AES128.ENCRYPT
				std::string("7789508D16918F03F53C52DAC54ED825"),
				std::string("9740051E9C5FECF64344F7A82260EDCC"),
				std::string("304C6528F659C77866A510D9C1D6AE5E"),
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.2 OFB-AES128.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("CDC80D6FDDF18CAB34C25909C99A4174"),//F.4.3 OFB-AES192.ENCRYPT
				std::string("FCC28B8D4C63837C09E81700C1100401"),
				std::string("8D9A9AEAC0F6596F559C6D4DAF59A5F2"),
				std::string("6D9F200857CA6C3E9CAC524BD9ACC92A")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.4 OFB-AES192.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			},
			{
				std::string("DC7E84BFDA79164B7ECD8486985D3860"),//F.4.5 OFB-AES256.ENCRYPT
				std::string("4FEBDC6740D20B3AC88F6AD82A4FB08D"),
				std::string("71AB47A086E86EEDF39D1C5BBA97C408"),
				std::string("0126141D67F37BE8538F5A8BE740E484")
			},
			{
				std::string("6BC1BEE22E409F96E93D7E117393172A"),//F.4.6 OFB-AES256.DECRYPT
				std::string("AE2D8A571E03AC9C9EB76FAC45AF8E51"),
				std::string("30C81C46A35CE411E5FBC1191A0A52EF"),
				std::string("F69F2445DF4F9B17AD2B417BE66C3710")
			}

		};

		m_expected.resize(output.size());

		for (size_t i = 0; i < output.size(); ++i)
		{
			HexConverter::Decode(output[i], 4, m_expected[i]);
		}
	}

	void CipherModeTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void CipherModeTest::Stress(ICipherMode* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXM_ALLOC);
		inp.reserve(MAXM_ALLOC);
		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			const size_t ALNLEN = MSGLEN - (MSGLEN % Cipher->BlockSize());

			cpt.resize(ALNLEN);
			inp.resize(ALNLEN);
			otp.resize(ALNLEN);

			IntegerTools::Fill(inp, 0, ALNLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, ALNLEN);

			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, ALNLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -TS1"));
			}
		}
	}
}
