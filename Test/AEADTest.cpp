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
			GCM* gcm1 = new GCM(Enumeration::BlockCiphers::AES);
			//Kat(gcm1, m_key[3], m_nonce[3], m_associatedText[3], m_plainText[3], m_cipherText[36]);
			Kat(gcm1, m_key[4], m_nonce[4], m_associatedText[4], m_plainText[4], m_cipherText[37]);
			Kat(gcm1, m_key[5], m_nonce[5], m_associatedText[5], m_plainText[5], m_cipherText[38]);
			Kat(gcm1, m_key[6], m_nonce[6], m_associatedText[6], m_plainText[6], m_cipherText[39]);
			Kat(gcm1, m_key[7], m_nonce[7], m_associatedText[7], m_plainText[7], m_cipherText[40]);
			Kat(gcm1, m_key[8], m_nonce[8], m_associatedText[8], m_plainText[8], m_cipherText[41]);
			Kat(gcm1, m_key[9], m_nonce[9], m_associatedText[9], m_plainText[9], m_cipherText[42]);
			Kat(gcm1, m_key[10], m_nonce[10], m_associatedText[10], m_plainText[10], m_cipherText[43]);
			Kat(gcm1, m_key[11], m_nonce[11], m_associatedText[11], m_plainText[11], m_cipherText[44]);
			Kat(gcm1, m_key[12], m_nonce[12], m_associatedText[12], m_plainText[12], m_cipherText[45]);
			Kat(gcm1, m_key[13], m_nonce[13], m_associatedText[13], m_plainText[13], m_cipherText[46]);
			Kat(gcm1, m_key[14], m_nonce[14], m_associatedText[14], m_plainText[14], m_cipherText[47]);
			Kat(gcm1, m_key[15], m_nonce[15], m_associatedText[15], m_plainText[15], m_cipherText[48]);
			Kat(gcm1, m_key[16], m_nonce[16], m_associatedText[16], m_plainText[16], m_cipherText[49]);
			Kat(gcm1, m_key[17], m_nonce[17], m_associatedText[17], m_plainText[17], m_cipherText[50]);
			Kat(gcm1, m_key[18], m_nonce[18], m_associatedText[18], m_plainText[18], m_cipherText[51]);
			Kat(gcm1, m_key[19], m_nonce[19], m_associatedText[19], m_plainText[19], m_cipherText[52]);
			Kat(gcm1, m_key[20], m_nonce[20], m_associatedText[20], m_plainText[20], m_cipherText[53]);
			delete gcm1;

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
			std::string("F97125806F996A3C884EA0B3027B6EEEB0730CD980328880393959EA92C9C197648DA3E6EC256F6B5AAECB754510ECE9"),
			std::string("10882F8C5F3CBE941CC3F17E30E52CC1B6980BB1B38069D775B2482C0DCBA1508D5D27B4495E4ECB34204221F4234D3AC7AC53193868C7BEA405EB19B40DB782"),
			std::string("447ABCEB84D113DD2E70B909D451E60417BA21D8AD599D58EF808D88506414D5B426CB80297C867B9338BEB839116B43B88D5C9FCA5F8DBF30D9D4B518BB6008"
				"C17EF1913B63702A892795EF3AEFAF2DF4A3BC7F6B42CF597C1D036B771A64BF"),
			// hbaa256k256
			std::string("E8FCE5FE91321E8392543D65493F3572A614778A9477FE14BBE5C0C8B5940CE52BE666C965B64CCEABB4379D3B8D896C"),
			std::string("6260C0B69E281391FCC34E2A504646FC95DB288157868A6E34FF76BF19543D4933DBFC36E9DD2B9FF1F62C211C7BCFC27DCFA51264844A0AC2A3AEE0C20BCF4E"),
			std::string("0A3265405CCD452F55DC1FBBE6FE66CA6592A166DE05B5B53A825A4C95D6F8D3F515C1C7938849B601FCE1533737B93BBA78AF7DBF1982F1A421F4CD387D77D6"
				"597B65A4CD6C2CC8D7A40A3A49AD322494196F4784B17BED385813F82469ABFD"),
			// hbar256h256
			std::string("3196573F11BDE0E265BCDA83836062B676AEFC22DA61C488DC2585B36DB5B6A9430263A14393C1EA38ED5281EAFABC94"),
			std::string("5654C0DD29C2DDAF228D6B135133927FAF440C356CAA2A14AF3BC907B20D5AA4AEFB348484F4D4D6A5AC545C790EB99A3BF3FF3E533703A07632B108B811B1C8"),
			std::string("58EE8ED312CECC334CDD4065282E1D129884D265B841F87173E133EEE2FEC531C1AEC335567F1D0AF5DA85993B8A86385A5827AB0B563C5153C3DFA6097FA48E"
				"C9FBEAD189BC77072BDA2D510FF166B3C5E0BB9C3A1DD3EBB5459361BD0D8ED3"),
			// hbar256k256
			std::string("D1B1C7A44B0360C5B32F36865ABE458023175AA63B8F049D3256E14AE28319D8B5704C4DAE9BECFEEC6DC90F4290CA50"),
			std::string("72266262C11A694A022786517D1222C644FEAD9ECF3C15C5914989BFCD54A6C23286294733E95E8E53E0D405339EBAF9906B498B7B6489DEE62AF84A6073E5E3"),
			std::string("1B593A4FD95A25ED8EA645199BB5A442E110CF2177C7209D5D3C2DE9FAAFCE5225B8E933B7611B89005FB5C0880E33A0E7FC77B9BE73611F94E6A431473B440F"
				"D44E6FA650CFF592073B9B915727BF6A5D380C40DA5F46808E2E787AB974BCBA"),
			// hbar512h512
			std::string("E6A77A113818FA8B56B834C3DCC48DF644566AB1E7D2887A3237BB66AD64DC2D85434BA39178EEDDB5A74063666FE3160E1E609D743CD1020A3403611EC20650"
				"30C29A27F13003F58FBE1A3DE1393C4B"),
			std::string("9C00C33391FED7C439295DB6D9F6CC895867F904DFD4705225CC1585C87990A76D2012B322E49A138066780F345EFAC118B87BC610CA6649E2168F284A8F63B0"
				"8CEDFC79C03DA00ECBFE651366DE59DB5DA4859F5846F4CEDD057285F4657C9D"),
			std::string("BC4B2C1333F04897B68FF8E60F7742A7F7320B478C0D11E95972F5FD78F3029EE8F27D11E66BD0C3543D56EE6F3962D6E749CA1F9C424AED232337A72BB766FD"
				"BADFB673AF27B237F7857B83E03BCEA7DBEF6C24C166811C6C9AD486792782037A1AC8F20863BB7ADA44C98AC9446D466D1EA1F14B4A69DF52E7DA2628C84345"),
			// hbar512k512
			std::string("3445EEABB15B39077D7A6FB7E7055FE49435BCA7CEAC9A834698FD26D60214AC4BC2146F9BD943044FAF62FA2185736D1CA3E09132C99604F620D000BE22331A"
				"23A4BD7D4C62EBF155EE63994C185976"),
			std::string("8238DFB8B88897E4C92490148AAFDB224127D53C84736E9124DDB0899662358B311AFF28414E352CEE8DB1D0FE4D956E01CA37CAF4EB3AE72D0939CE0FCD9279"
				"9AC66DDCEA05F84DFB59A5AA804C4703BAC8F7B93527C3943B01FFCD48050120"),
			std::string("2CDC038A38D27F58B38AA2130D1AA61D3C837DC2BF645D8379813A7C05B98DD6E3C5844840F12E6AC1D7483C714D8FAF5DD0849C1E6CDE208BE7BA83F12762DC"
				"2F9E1D7C10CBCA7338590E98E190A7F025B8AE1B03B731DC98BEB572E30F674E88F3099932ED7BA7EC20CBA8EEE11166109596CBCC76BA23D32B7A8CF65D0D80"),
			// hbar1024k1024
			std::string("4DA46E6DA360C7E2FDE7F32244BB5D38A0B56F22D4DAF5BB62BD67DA2B68A50FD529CAB1C05CA7221D92864B36EC97E821898D35B5E02CF920CB15C0CC850DD7"
				"CE802A44B1DFC3DC9627DD0E982708A8B10140E1789C2CFB57E5501C9CFD80840CAE2F8C1E1CCF6C27F24644E9DABB05505A00188880EB0F44B285029F301D54"
				"CA4D5B989672906763D049FE1798A5FC"),
			std::string("F4BE554E334993E4554291F5ABF973A8C04EF37F425143A73DDD05BDA0E6F6689A0A2E756E75C85D96C3B6B81FCEB5B49BAD1DF67006DF1ABF79BBDB46D2C275"
				"45D30BEFAC490677F2F77B1F200DEFA029131CADF613EA0DEF0C148C0AD7FCC377BCA535A768DF1D6BBCA0228998C7E07731421D6378BAEC03F3F51F0DCBEE1A"
				"7843FFE10446ABA1FB75ABCE9F159C1417EB045D5999351B5C51B9A895D15115"),
			std::string("ADC0D70822B0C191DC6D9BA4AEF8BB11023B415180CA341B6AE52062C08A22CE931324997100AD978CD37A975619C70855B10475D5AA9C3987BC963E2459278F"
				"A86A7236BAE91B6EE78AD4D6F982C2ECAB6D02FE6DD47A25F65E8CCE73F9761A20AF41A5964CB81CABCA10EE0672BF8254C829F5DC2799E4946A3C92A19446F2"
				"E0CEC7172616FF3579D6740CD7166F26D9CE634D296217FDEEC2375B057F65A1C04EF0FE39794DFD2D21B728827344B1A34AEF937AE034EC22BA1A121A7DE178"),
			// sequential tests
			// hbar256h256
			std::string("03C7368F5A31F4E23192582D7079481A36C62E6E8AEF3CB40F719496F37085101CE929C045EF17FA6856AC6F860805D3"),
			std::string("E1591739CDB78EF07BFD9E23DDBA5F23BEF8A70DFD68659AF72BBD9E48B2FD7F387E09EAA7B7D60656A212E697F156F1"),
			std::string("2DE773BA5DB33FCE8ADAD42F8C94BFA8E65F0766BDBCEF387A2226AADAFBF69C16D5653FB4C70BB5CCFC8E103B8F4426"),
			// hbar256k256
			std::string("8D70A81F79DD6C17D767958FB2A378ACC48E2051E71881B97620F68AFBE864DDD6EED7D04DAC292B8B845E27518BCD8E"),
			std::string("5307191E6A49765768F9D0FBBA310DD04DE35C86005139EB820FDF1A35C08C234A2242E4909663B959C3CA92C3832447"),
			std::string("D43818CDAC8942BB8C6133DC3FB05D7E539C964B66A8A775C3E1E0434D4BC18A1A1BF298939EE735BF8ADF91ED59157B"),
			// hbar512h512
			std::string("B8D276B0905D55E506449081F54C5ADF3F1066FE014AF619168FC71608F06D20566CD3F97D0DEB6ABC7633FC90B5872394781A84BB84E3B2A3A243D90A9A293B"
				"3309D046918B2106FAEC585C97563849"),
			std::string("741E4D9E8E58ED806B6B80EFAB2BB8EEFDF1897D8FC7D127B06227FF691ADCEB70FA102BF5BC55606FBE8F1861EC0A1EC35802705CC920354817FB167B7EE050"
				"CDAC15B2F6AE381E89B5A0075961C9C2"),
			std::string("894F038617C7DD936B7DCABCC437FB6D60E5EB9EC67ACE5227C471E40A2FFDEE4741BF29F0DE9208894D930494543C17560633181E25F834AD18EDAAA14B7622"
				"D05C3305EE84894D160800F9AF413E3E"),
			// hbar512k512
			std::string("0A13C7DFFF0A9156293CE764E7AC23D3404E5EF6A0CC08B606C8225D51417233E12790C4D2175D0251497CA4058ABD415E5E0F6CB4FA2DE87EECF48901A5B882"
				"48EC8F073A9107730D39772F4BC597D8"),
			std::string("F2CD00B5ACCAE2F7258DE9D07A69E302A7A6CE002AAD599E5C2B85414276DA2571EBEEB63C403DCDC204C6EF429B26FD76D332C85A4E9019C5D7E35C26E3DAE9"
				"41B8FF49E06D48E9CD97EF659BC2CAFA"),
			std::string("97AED5C1C69E1E152613EC2A50B4D2ABEBE53A96F5AD12B7E63B46A7A35F2E172210829A4B90AB9B2FF8283F495DE9129987F1885BC45F13C31363553EFD6E1D"
				"DF3A981550CC1F217EAE6F1F3E947C62"),
			// hbar1024k1024
			std::string("72E5E24E238A0A86063C569A515BFFA013CAE53CFA55DA9DAE60606EA10714A7FF0261A7B0CCABCA3DA7019B2084750DE07453213D8E07F0C78454AC0B2748CD"
				"8767C43731D104E4AD65B09BB30901D705A50EFF1D39818616FB6B421D2827807FAC38FEA94BA7C3F63B5541CA0A4BB98D468B83DB8AB84F6B3D2DB7E17FCD0D"
				"2D7804C1D6C25037C5CF2A72ADE12218"),
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
