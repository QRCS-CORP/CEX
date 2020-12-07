#include "AeadTest.h"
#include "../CEX/GCM.h"
#include "../CEX/HBA.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Enumeration::AeadModes;
	using Enumeration::AeadModeConvert;
	using Enumeration::BlockCiphers;
	using Exception::CryptoAuthenticationFailure;
	using Exception::CryptoCipherModeException;
	using Cipher::Block::Mode::GCM;
	using Cipher::Block::Mode::HBA;
	using Cipher::Block::IBlockCipher;
	using Tools::IntegerTools;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKeySize;

	const std::string AeadTest::CLASSNAME = "AeadTest";
	const std::string AeadTest::DESCRIPTION = "Authenticate Encrypt and Associated Data (AEAD) Cipher Mode Tests.";
	const std::string AeadTest::SUCCESS = "SUCCESS! AEAD tests have executed succesfully.";

	//~~~Constructor~~~//

	AeadTest::AeadTest()
		:
		m_associatedText(0),
		m_cipherText(0),
		m_key(0),
		m_nonce(0),
		m_plainText(0),
		m_progressEvent()
	{
		Initialize();
	}

	AeadTest::~AeadTest()
	{
		IntegerTools::Clear(m_associatedText);
		IntegerTools::Clear(m_cipherText);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_nonce);
		IntegerTools::Clear(m_plainText);
	}

	//~~~Accessors~~~//

	const std::string AeadTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AeadTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string AeadTest::Run()
	{
		try
		{
			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("AeadTest: Passed HBA exception handling tests.."));

			// HBA
			// AES-256-HMAC-256
			HBA* hbaa256h256 = new HBA(BlockCiphers::AES, StreamAuthenticators::HMACSHA2256);
			Kat(hbaa256h256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[0]);
			Kat(hbaa256h256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[1]);
			Kat(hbaa256h256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[2]);
			// AES-256-KMAC-256
			HBA* hbaa256k256 = new HBA(BlockCiphers::AES, StreamAuthenticators::KMAC256);
			Kat(hbaa256k256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[3]);
			Kat(hbaa256k256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[4]);
			Kat(hbaa256k256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[5]);
			// RHX-256-HMAC-256
			HBA* hbar256h256 = new HBA(BlockCiphers::RHXH256, StreamAuthenticators::HMACSHA2256);
			Kat(hbar256h256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[6]);
			Kat(hbar256h256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[7]);
			Kat(hbar256h256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[8]);
			// RSX-256-KMAC-256
			HBA * hbar256k256 = new HBA(BlockCiphers::RHXS256, StreamAuthenticators::KMAC256);
			Kat(hbar256k256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[9]);
			Kat(hbar256k256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[10]);
			Kat(hbar256k256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[11]);
			// RHX-512-HMAC-512
			HBA* hbar512h512 = new HBA(BlockCiphers::RHXH512, StreamAuthenticators::HMACSHA2512);
			Kat(hbar512h512, m_key[1], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[12]);
			Kat(hbar512h512, m_key[1], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[13]);
			Kat(hbar512h512, m_key[1], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[14]);
			// RSX-512-KMAC-512
			HBA* hbar512k512 = new HBA(BlockCiphers::RHXS512, StreamAuthenticators::KMAC512);
			Kat(hbar512k512, m_key[1], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[15]);
			Kat(hbar512k512, m_key[1], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[16]);
			Kat(hbar512k512, m_key[1], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[17]);
			// RSX-1024-KMAC-1024
			HBA* hbar1024k1024 = new HBA(BlockCiphers::RHXS1024, StreamAuthenticators::KMAC1024);
			Kat(hbar1024k1024, m_key[2], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[18]);
			Kat(hbar1024k1024, m_key[2], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[19]);
			Kat(hbar1024k1024, m_key[2], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[20]);
			OnProgress(std::string("AeadTest: Passed HBA known answer comparison tests.."));

			Sequential(hbar256h256, m_plainText[0], m_cipherText[21], m_cipherText[22], m_cipherText[23]);
			Sequential(hbar256k256, m_plainText[0], m_cipherText[24], m_cipherText[25], m_cipherText[26]);
			Sequential(hbar512h512, m_plainText[0], m_cipherText[27], m_cipherText[28], m_cipherText[29]);
			Sequential(hbar512k512, m_plainText[0], m_cipherText[30], m_cipherText[31], m_cipherText[32]);
			Sequential(hbar1024k1024, m_plainText[0], m_cipherText[33], m_cipherText[34], m_cipherText[35]);
			OnProgress(std::string("AeadTest: Passed HBA sequential transformation calls test.."));

			Parallel(hbar256k256);
			OnProgress(std::string("AeadTest: Passed HBA parallel tests.."));

			Stress(hbar256k256);
			OnProgress(std::string("AeadTest: Passed HBA stress tests.."));

			delete hbaa256h256;
			delete hbaa256k256;
			delete hbar256k256;
			delete hbar256h256;
			delete hbar512h512;
			delete hbar512k512;
			delete hbar1024k1024;

			// GCM
			GCM* gcma = new GCM(Enumeration::BlockCiphers::AES);
			Kat(gcma, m_key[3], m_nonce[3], m_associatedText[3], m_plainText[3], m_cipherText[36]);
			Kat(gcma, m_key[4], m_nonce[4], m_associatedText[4], m_plainText[4], m_cipherText[37]);
			Kat(gcma, m_key[5], m_nonce[5], m_associatedText[5], m_plainText[5], m_cipherText[38]);
			Kat(gcma, m_key[6], m_nonce[6], m_associatedText[6], m_plainText[6], m_cipherText[39]);
			Kat(gcma, m_key[7], m_nonce[7], m_associatedText[7], m_plainText[7], m_cipherText[40]);
			Kat(gcma, m_key[8], m_nonce[8], m_associatedText[8], m_plainText[8], m_cipherText[41]);
			Kat(gcma, m_key[9], m_nonce[9], m_associatedText[9], m_plainText[9], m_cipherText[42]);
			Kat(gcma, m_key[10], m_nonce[10], m_associatedText[10], m_plainText[10], m_cipherText[43]);
			Kat(gcma, m_key[11], m_nonce[11], m_associatedText[11], m_plainText[11], m_cipherText[44]);
			Kat(gcma, m_key[12], m_nonce[12], m_associatedText[12], m_plainText[12], m_cipherText[45]);
			Kat(gcma, m_key[13], m_nonce[13], m_associatedText[13], m_plainText[13], m_cipherText[46]);
			Kat(gcma, m_key[14], m_nonce[14], m_associatedText[14], m_plainText[14], m_cipherText[47]);
			Kat(gcma, m_key[15], m_nonce[15], m_associatedText[15], m_plainText[15], m_cipherText[48]);
			Kat(gcma, m_key[16], m_nonce[16], m_associatedText[16], m_plainText[16], m_cipherText[49]);
			Kat(gcma, m_key[17], m_nonce[17], m_associatedText[17], m_plainText[17], m_cipherText[50]);
			Kat(gcma, m_key[18], m_nonce[18], m_associatedText[18], m_plainText[18], m_cipherText[51]);
			Kat(gcma, m_key[19], m_nonce[19], m_associatedText[19], m_plainText[19], m_cipherText[52]);
			Kat(gcma, m_key[20], m_nonce[20], m_associatedText[20], m_plainText[20], m_cipherText[53]);
			delete gcma;

			OnProgress(std::string("AeadTest: Passed GCM known answer comparison tests.."));

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

	void AeadTest::Exception()
	{
		// test modes enumeration constructors for invalid block-cipher type //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::None, Enumeration::StreamAuthenticators::HMACSHA2256);

			throw TestException(std::string("Constructor Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE3"));
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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::None);

			throw TestException(std::string("Constructor Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE4"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test modes pointer constructor for invalid cipher //

		try
		{
			HBA cpr(nullptr, Enumeration::StreamAuthenticators::HMACSHA2256);

			throw TestException(std::string("Constructor Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE7"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test modes initialization with an invalid key size //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA2256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Initialization Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE10"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test modes initialization with an invalid nonce size //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA2256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(0);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Initialization Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE13"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test mode for invalid parallel options //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA2256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Parallel Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE16"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test mode uninitialized associated data calls //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA2256);
			std::vector<byte> aad(16);

			// set associated data on an uninitialized cipher
			cpr.SetAssociatedData(aad, 0, aad.size());

			throw TestException(std::string("Associated Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE19"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test mode for improperly sized cipher-text arrays //

		try
		{
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA2256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];

			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);

			std::vector<byte> pln(16, 0x00);
			// the output ciphertext array must be the plaintext size + the MAC tag size
			std::vector<byte> cpt((pln.size() + cpr.TagSize()) - 1);

			// imitialize for encryption
			cpr.Initialize(true, kp);
			// ciphertext is too small, will throw an exception
			cpr.Transform(pln, 0, cpt, 0, pln.size());

			throw TestException(std::string("Transform Exception"), AeadModeConvert::ToName(AeadModes::HBA), std::string("Exception handling failure! -AE22"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void AeadTest::Kat(IAeadMode* Cipher, const std::vector<byte> &Key, const std::vector<byte> &Nonce, 
		const std::vector<byte> &AssociatedText, const std::vector<byte> &PlainText, const std::vector<byte> &CipherText)
	{
		const size_t CPTLEN = CipherText.size();
		const size_t TXTLEN = PlainText.size();
		std::vector<byte> dec(CPTLEN);
		std::vector<byte> enc(CPTLEN);
		std::vector<byte> mac(CPTLEN - TXTLEN);

		SymmetricKey kp(Key, Nonce);
		Cipher->Initialize(true, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}

		// test encryption

		Cipher->Transform(PlainText, 0, enc, 0, PlainText.size());

		if (CipherText != enc)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AK1"));
		}

		// test decryption

		Cipher->Initialize(false, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}

		Cipher->Transform(enc, 0, dec, 0, TXTLEN);

		// check the decrypted output against the plaintext
		if (IntegerTools::Compare(PlainText, 0, dec, 0, PlainText.size()) == false)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AK3"));
		}
	}

	void AeadTest::Parallel(IAeadMode* Cipher)
	{
		std::vector<byte> data;
		std::vector<byte> dec1;
		std::vector<byte> dec2;
		std::vector<byte> enc1;
		std::vector<byte> enc2;
		std::vector<byte> key(32);
		std::vector<SymmetricKeySize> keySizes = Cipher->LegalKeySizes();
		std::vector<byte> nonce(keySizes[0].IVSize());
		std::vector<byte> assoc(16);
		size_t i;
		Prng::SecureRandom rng;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const uint BLKLEN = rng.NextUInt32(static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4), static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize()));

			data.resize(BLKLEN);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			SymmetricKey kp(key, nonce);

			// parallel encryption mode
			enc1.resize(BLKLEN + Cipher->TagSize());
			Cipher->ParallelProfile().IsParallel() = true;
			// note: changes to parallel block-size must be set before every Initialize() call
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc1, 0, data.size());

			// sequential mode
			enc2.resize(BLKLEN + Cipher->TagSize());
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc2, 0, data.size());

			if (enc1 != enc2)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AP1"));
			}

			// parallel decryption mode
			dec1.resize(BLKLEN);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc1, 0, dec1, 0, enc1.size() - Cipher->TagSize());

			// sequential decryption mode
			dec2.resize(BLKLEN);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc2, 0, dec2, 0, enc2.size() - Cipher->TagSize());

			if (dec1 != dec2)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AP2"));
			}

			if (dec1 != data)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AP3"));
			}
		}
	}

	void AeadTest::Sequential(IAeadMode* Cipher, const std::vector<byte> &PlainText, 
		const std::vector<byte> &Output1, const std::vector<byte> &Output2, const std::vector<byte> &Output3)
	{
		SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> ad(20, 0x01);
		std::vector<byte> dec1(PlainText.size());
		std::vector<byte> dec2(PlainText.size());
		std::vector<byte> dec3(PlainText.size());
		std::vector<byte> key(ks.KeySize(), 0x02);
		std::vector<byte> nonce(16, 0x03);
		std::vector<byte> otp1(Output1.size());
		std::vector<byte> otp2(Output2.size());
		std::vector<byte> otp3(Output3.size());

		SymmetricKey kp(key, nonce);

		Cipher->Initialize(true, kp);
		Cipher->SetAssociatedData(ad, 0, ad.size());
		Cipher->Transform(PlainText, 0, otp1, 0, PlainText.size());

		if (otp1 != Output1)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS1"));
		}

		Cipher->Transform(PlainText, 0, otp2, 0, PlainText.size());

		if (otp2 != Output2)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS2"));
		}

		Cipher->Transform(PlainText, 0, otp3, 0, PlainText.size());

		if (otp3 != Output3)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS3"));
		}

		// test inverse operation -decryption mode
		Cipher->Initialize(false, kp);
		Cipher->SetAssociatedData(ad, 0, ad.size());

		try
		{
			Cipher->Transform(otp1, 0, dec1, 0, dec1.size());
		}
		catch (CryptoAuthenticationFailure const &)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS4"));
		}

		if (dec1 != PlainText)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS5"));
		}

		try
		{
			Cipher->Transform(otp2, 0, dec2, 0, dec2.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS6"));
		}

		if (dec2 != PlainText)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS7"));
		}

		try
		{
			Cipher->Transform(otp3, 0, dec3, 0, dec3.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS8"));
		}

		if (dec3 != PlainText)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS9"));
		}
	}

	void AeadTest::Stress(IAeadMode* Cipher)
	{
		SymmetricKeySize keySize = Cipher->LegalKeySizes()[0];
		std::vector<byte> data;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> key(32);
		std::vector<byte> nonce(keySize.IVSize());
		std::vector<byte> assoc(16);

		Prng::SecureRandom rng;
		data.reserve(MAX_ALLOC);
		dec.reserve(MAX_ALLOC);
		enc.reserve(MAX_ALLOC);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t BLKLEN = rng.NextUInt32(10000, 100);
			data.resize(BLKLEN);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			SymmetricKey kp(key, nonce);

			enc.resize(BLKLEN + Cipher->TagSize());
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc, 0, data.size());

			dec.resize(BLKLEN);
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());

			try
			{
				Cipher->Transform(enc, 0, dec, 0, enc.size() - Cipher->TagSize());
			}
			catch (CryptoAuthenticationFailure const&)
			{
				throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS1"));
			}
			
			if (data != dec)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS2"));
			}

			data.clear();
			dec.clear();
			enc.clear();
		}
	}

	//~~~Private Functions~~~//

	void AeadTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> key =
		{
			// HBA
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
				"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			// GCM
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308"),
			std::string("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308")
		};
		HexConverter::Decode(key, 21, m_key);

		const std::vector<std::string> nonce =
		{
			// HBA
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0"),
			std::string("10000000000000000000000000000000"),
			std::string("00000000000000000000000000000001"),
			// GCM
			std::string("000000000000000000000000"),
			std::string("000000000000000000000000"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBAD"),
			std::string("9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B"),
			std::string("000000000000000000000000"),
			std::string("000000000000000000000000"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBAD"),
			std::string("9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B"),
			std::string("000000000000000000000000"),
			std::string("000000000000000000000000"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBADDECAF888"),
			std::string("CAFEBABEFACEDBAD"),
			std::string("9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B")
		};
		HexConverter::Decode(nonce, 21, m_nonce);

		const std::vector<std::string> associatedtext =
		{
			// HBA
			std::string("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE"),
			// GCM
			std::string(""),
			std::string(""),
			std::string(""),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string(""),
			std::string(""),
			std::string(""),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string(""),
			std::string(""),
			std::string(""),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
		};
		HexConverter::Decode(associatedtext, 21, m_associatedText);

		const std::vector<std::string> plaintext =
		{
			// HBA
			std::string("00000000000000000000000000000001"),
			std::string("1000000000000000000000000000000000000000000000000000000000000000"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255"),
			// GCM
			std::string(""),
			std::string("00000000000000000000000000000000"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string(""),
			std::string("00000000000000000000000000000000"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string(""),
			std::string("00000000000000000000000000000000"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39")
		};
		HexConverter::Decode(plaintext, 21, m_plainText);

		const std::vector<std::string> ciphertext =
		{
			// HBA
			// hbaa256h256
			std::string("F97125806F996A3C884EA0B3027B6EEE1B996C974B597C2441D1FD16F6469B3B4F3162988ABBE318C73B00891193EF23"),
			std::string("10882F8C5F3CBE941CC3F17E30E52CC1B6980BB1B38069D775B2482C0DCBA150CADBE51A8B1E15E45A51A347C6176165DFFECB22F4E79867F28F103DEB3E9A16"),
			std::string("447ABCEB84D113DD2E70B909D451E60417BA21D8AD599D58EF808D88506414D5B426CB80297C867B9338BEB839116B43B88D5C9FCA5F8DBF30D9D4B518BB6008"
				"C1D7CE58551C4398C3E28C9F9E3E611778F5630BD5F0021D8E05095F6FFB8D51"),
			// hbaa256k256
			std::string("E8FCE5FE91321E8392543D65493F35729085448A9F7B31D100C0910F7FC8ED407C606A99574EE9413A1244AFC92F6E1D"),
			std::string("6260C0B69E281391FCC34E2A504646FC95DB288157868A6E34FF76BF19543D494A2B7E4764858993897D0EA1DEC036A3EA94E77D38480804A3E2197FD81C479B"),
			std::string("0A3265405CCD452F55DC1FBBE6FE66CA6592A166DE05B5B53A825A4C95D6F8D3F515C1C7938849B601FCE1533737B93BBA78AF7DBF1982F1A421F4CD387D77D6"
				"D87297439058E2467D5ED504D6A62F8B47066F7D955A07349A0D047FC217EEBA"),
			// hbar256h256
			std::string("3196573F11BDE0E265BCDA83836062B62AC98559ED16002B6FDDC6DA6204CAB35234AA01546388E33C2EFE549A89153D"),
			std::string("5654C0DD29C2DDAF228D6B135133927FAF440C356CAA2A14AF3BC907B20D5AA46FC088438D77411A57B7EDA6EEFC7B944F37CE367E05C4089CB4F7C70070D437"),
			std::string("58EE8ED312CECC334CDD4065282E1D129884D265B841F87173E133EEE2FEC531C1AEC335567F1D0AF5DA85993B8A86385A5827AB0B563C5153C3DFA6097FA48E"
				"D4EE6675422E5A9102E1C4FE6FD324D531468D92F48A217BCC56C4CA634029DD"),
			// hbar256k256
			std::string("D1B1C7A44B0360C5B32F36865ABE45806F637B4D1378D47AF5F7EE5D369B9DC2950AA9EA2BB48D6D5E5B576542041897"),
			std::string("72266262C11A694A022786517D1222C644FEAD9ECF3C15C5914989BFCD54A6C227108D7A8C5DEA3AED33C084CA446C7FDC3A2ADC8470A589EE624671F5AF5630"),
			std::string("1B593A4FD95A25ED8EA645199BB5A442E110CF2177C7209D5D3C2DE9FAAFCE5225B8E933B7611B89005FB5C0880E33A0E7FC77B9BE73611F94E6A431473B440F"
				"6E3247CFD7602399F4DE7F9AD17CA12351042AADE37ABA4A9B88CBF079060999"),
			// hbar512h512
			std::string("E6A77A113818FA8B56B834C3DCC48DF6DE18D0246756442433EEDD9677A28CF7121853B69350C1CDE26CC948148B5FA0CC61B5B4E752086446F6146CC83A82E1"
				"1F419145078FE315D945D185193C9F90"),
			std::string("9C00C33391FED7C439295DB6D9F6CC895867F904DFD4705225CC1585C87990A7A0E1CA0A739A255CE1ADB4FCF9DFAA515A301EF83F5EF5823D8837CC36825A12"
				"516F5F712B8C19CAEEE4258C0FEBF70DF3C74E9734659DEABE7DD7BF4D8B0EB5"),
			std::string("BC4B2C1333F04897B68FF8E60F7742A7F7320B478C0D11E95972F5FD78F3029EE8F27D11E66BD0C3543D56EE6F3962D6E749CA1F9C424AED232337A72BB766FD"
				"36803A4B8979EA54650F673D556B67A2E484DF2008688BFBA31BF4D2C1368AC563203634D9D2F37053AF36B7E20D78187AFC1E972A74C60DBCFC539F6EABCDF1"),
			// hbar512k512
			std::string("3445EEABB15B39077D7A6FB7E7055FE47E0705B3C4A68DAF308BD382AAC0133BE0D0C9AF7F5048F0A14AE749814C159DF05E4323729B75FAB26B6515C05AC13A"
				"B5EDB03FFF0C67F42100927C94AEDE41"),
			std::string("8238DFB8B88897E4C92490148AAFDB224127D53C84736E9124DDB0899662358B4B2B910B0D6D60CE60BB02B1E51C4593D4A2C35BBF853DE2A422B4A187784ECA"
				"92B7942A08146609B618E800CA4DD3C827E16778EDB75858D7278C575B4AF879"),
			std::string("2CDC038A38D27F58B38AA2130D1AA61D3C837DC2BF645D8379813A7C05B98DD6E3C5844840F12E6AC1D7483C714D8FAF5DD0849C1E6CDE208BE7BA83F12762DC"
				"921F09D58798BD9A9BDEA1C4F3EFB56A09A1ADC4D17CC12F68192AA1FA6640F3A56470F9B000A9A92AB2C97347DB8BE69F1BFF5A9CC152FDF8F1FACD274EC623"),
			// hbar1024k1024
			std::string("4DA46E6DA360C7E2FDE7F32244BB5D38B8E884B2E771301CC0698B4EFB3F19388E93532C4DCD7CCC3CC8A8F39EB0414FAF379D089423E7AAA3949A7BF505F71C"
				"8710B89A9CD303B9F8363A6D3137E3AF29C1491C462022AFA5C15A33103FBD4DE7B9FD0EFE733A6E0DA8AD041448B27AE8C8FEEFE356B6F3D73B227A1B4719BB"
				"60D7EADF94E3E5D688F4C80CA85E9402"),
			std::string("F4BE554E334993E4554291F5ABF973A8C04EF37F425143A73DDD05BDA0E6F6685DE768E8DC59C353F05E4A99F69F44CCEE21E5D7EE383800F68DBCAFEBB1DFA5"
				"75F2DC35DC2EB9A3DB821FF72E363E74047C28CD665C1BAC14D8F4E107984D340AD1A71FE0DE73713C5630036D2AB38A2CD274B9442E9D2B44EB562FB405F3FE"
				"0A37D365DD50B5E04D92B7904D30380DE8AF0E3C90A29C9C13BEE34CDC97EA85"),
			std::string("ADC0D70822B0C191DC6D9BA4AEF8BB11023B415180CA341B6AE52062C08A22CE931324997100AD978CD37A975619C70855B10475D5AA9C3987BC963E2459278F"
				"8434AFEC96565A0974A705F86C1B1BAA3BE89E1B588077DAE6EB0F904809A1AC69E61515E7C28F9D11C22F5D417000413D93909AD818A39D375B00098D67BD28"
				"166A7409C24DD515A623ADAC2ADD285C0F04FED543D307BA81B730AE3C676BBCC75D6ED7E2B251E76E71BCD5945C22734CBC781151C2AC15B7EA1F22FD980C06"),
			// sequential tests
			// hbar256h256
			std::string("03C7368F5A31F4E23192582D7079481A72BEE62B2D683CEBC61AA6F7A7910D302C4A6829767042819DA969F37806C475"),
			std::string("E1591739CDB78EF07BFD9E23DDBA5F23BEF8A70DFD68659AF72BBD9E48B2FD7F387E09EAA7B7D60656A212E697F156F1"),
			std::string("2DE773BA5DB33FCE8ADAD42F8C94BFA8E65F0766BDBCEF387A2226AADAFBF69C16D5653FB4C70BB5CCFC8E103B8F4426"),
			// hbar256k256
			std::string("8D70A81F79DD6C17D767958FB2A378AC90175813CAF056F5AE7B3747F790934282C3F9B845D671518C6C6A86D6A46783"),
			std::string("5307191E6A49765768F9D0FBBA310DD04DE35C86005139EB820FDF1A35C08C234A2242E4909663B959C3CA92C3832447"),
			std::string("D43818CDAC8942BB8C6133DC3FB05D7E539C964B66A8A775C3E1E0434D4BC18A1A1BF298939EE735BF8ADF91ED59157B"),
			// hbar512h512
			std::string("B8D276B0905D55E506449081F54C5ADFF159A85E9DCBF6C203D64E137E937CBF45B41EAF282000E9CFAFCA3A5572479FAC08F634FA4E27D49DD31B68AE4A5B10"
				"D4DE43EE9D677E9F5398F67DF9A449E0"),
			std::string("741E4D9E8E58ED806B6B80EFAB2BB8EEFDF1897D8FC7D127B06227FF691ADCEB70FA102BF5BC55606FBE8F1861EC0A1EC35802705CC920354817FB167B7EE050"
				"CDAC15B2F6AE381E89B5A0075961C9C2"),
			std::string("894F038617C7DD936B7DCABCC437FB6D60E5EB9EC67ACE5227C471E40A2FFDEE4741BF29F0DE9208894D930494543C17560633181E25F834AD18EDAAA14B7622"
				"D05C3305EE84894D160800F9AF413E3E"),
			// hbar512k512
			std::string("0A13C7DFFF0A9156293CE764E7AC23D37CDC8E7ED0D3D92C191AB26C47F441C11D6C632DFF65290C84B048D814138DA53835DA6D6B2DAE5FD8E07BE7B78F36EA"
				"4960C660AAC7CE4A0DCCABFB3BD1BEB8"),
			std::string("F2CD00B5ACCAE2F7258DE9D07A69E302A7A6CE002AAD599E5C2B85414276DA2571EBEEB63C403DCDC204C6EF429B26FD76D332C85A4E9019C5D7E35C26E3DAE9"
				"41B8FF49E06D48E9CD97EF659BC2CAFA"),
			std::string("97AED5C1C69E1E152613EC2A50B4D2ABEBE53A96F5AD12B7E63B46A7A35F2E172210829A4B90AB9B2FF8283F495DE9129987F1885BC45F13C31363553EFD6E1D"
				"DF3A981550CC1F217EAE6F1F3E947C62"),
			// hbar1024k1024
			std::string("72E5E24E238A0A86063C569A515BFFA0A3D10E927DE5ECEB421BDC15164A89078FBD8B40B31E66A199B827D6C5766633D6E7A3B02860639A1FC98BE281647EF8"
				"3CC80D174D0C64329511C88A8C82C1C42A3839D699768F7E0C699FF48B91F668892CBBC4E6AE4BDE2DF8BC9F98077AF46844AA47046894679B8D9340E85F647B"
				"12505EA749E6FE32A7810043BFF47C78"),
			std::string("EA7811290D3285F4336A3B2121C7ACF8587B59965F4405D239AC539EF73F73B4F6BCA389F328BF44B92E55854D04CD50A83848E4B77E2BFF3B69B1D0DCFAE304"
				"B433033BBC7A7C547DC790897814635FE13A20BD6A4834AB89DFA17C93D0DC0E9E1AD6B6663C99EDB3B7C29B54C8A3DECBFAFB1E6306237A20E2E97688C08EA7"
				"F06175EF2B4E441961DF10874C7674C7"),
			std::string("F52132C24198F4A30821114A574B528CC8C3D99B389846FAD05528D58F97D530FCB0ADF86383F800DC8B3EE7A93A6AF3A34064DFAFF08C30BDD5B66A28D904F6"
				"B8C814E3E993DCCB82F2BD1B0333B04991CC296430A48F3672DA5967AB5E6FF3175C7DC5003DAA650856C13247445A8F1A530B5DBF3332622F473C334D1B8EAC"
				"14267B64220EF3AAA2229377BE4E0650"),
			// GCM
			std::string("58E2FCCEFA7E3061367F1D57A4E7455A"),
			std::string("0388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF"),
			std::string("42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F59854D5C2AF327CD64A62CF35ABD2BA6FAB4"),
			std::string("42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E0915BC94FBC3221A5DB94FAE95AE7121A47"),
			std::string("61353B4C2806934A777FF51FA22A4755699B2A714FCDC6F83766E5F97B6C742373806900E49F24B22B097544D4896B424989B5E1EBAC0F07C23F45983612D2E79E3B0785561BE14AACA2FCCB"),
			std::string("8CE24998625615B603A033ACA13FB894BE9112A5C3A211A8BA262A3CCA7E2CA701E4A9A4FBA43C90CCDCB281D48C7C6FD62875D2ACA417034C34AEE5619CC5AEFFFE0BFA462AF43C1699D050"),
			std::string("CD33B28AC773F74BA00ED1F312572435"),
			std::string("98E7247C07F0FE411C267E4384B0F6002FF58D80033927AB8EF4D4587514F0FB"),
			std::string("3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE2569924A7C8587336BFB118024DB8674A14"),
			std::string("3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA27102519498E80F1478F37BA55BD6D27618C"),
			std::string("0F10F599AE14A154ED24B36E25324DB8C566632EF2BBB34F8347280FC4507057FDDC29DF9A471F75C66541D4D4DAD1C9E93A19A58E8B473FA0F062F765DCC57FCF623A24094FCCA40D3533F8"),
			std::string("D27E88681CE3243C4830165A8FDCF9FF1DE9A1D8E6B447EF6EF7B79828666E4581E79012AF34DDD9E2F037589B292DB3E67C036745FA22E7E9B7373BDCF566FF291C25BBB8568FC3D376A6D9"),
			std::string("530F8AFBC74536B9A963B4F1C4CB738B"),
			std::string("CEA7403D4D606B6E074EC5D3BAF39D18D0D1C8A799996BF0265B98B5D48AB919"),
			std::string("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015ADB094DAC5D93471BDEC1A502270E3CC6C"),
			std::string("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F66276FC6ECE0F4E1768CDDF8853BB2D551B"),
			std::string("C3762DF1CA787D32AE47C13BF19844CBAF1AE14D0B976AFAC52FF7D79BBA9DE0FEB582D33934A4F0954CC2363BC73F7862AC430E64ABE499F47C9B1F3A337DBF46A792C45E454913FE2EA8F2"),
			std::string("5A8DEF2F0C9E53F1F75D7853659E2A20EEB2B22AAFDE6419A058AB4F6F746BF40FC0C3B780F244452DA3EBF1C5D82CDEA2418997200EF82E44AE7E3FA44A8266EE1C8EB0C8B5D4CF5AE9F19A")
		};
		HexConverter::Decode(ciphertext, 54, m_cipherText);

		/*lint -restore */
	}

	void AeadTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
