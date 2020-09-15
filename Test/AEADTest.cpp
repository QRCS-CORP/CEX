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

		// decryption
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
			std::string("10882F8C5F3CBE941CC3F17E30E52CC1DC9C091A2334DF02D5900421806A7056D78DB80D8C8F8F58D68A5D1C2A42A37DA114AC53B5498CB3A5E82ED2D8BD22D6"),
			std::string("447ABCEB84D113DD2E70B909D451E604132E1446E96767C3DA51E6E31A111B5A74FA0D638E29D72CBA73238B0630DC90C88ECC434406457A07B15B9E3B5713B2"
				"DBD81548A026C9E6217AE2B41993B31B477B0E121183FA0D57924EC729AEA8F1"),
			// hbaa256k256
			std::string("E8FCE5FE91321E8392543D65493F3572A614778A9477FE14BBE5C0C8B5940CE52BE666C965B64CCEABB4379D3B8D896C"),
			std::string("6260C0B69E281391FCC34E2A504646FC63F7482B69FC65521737DD05AB708083E78AB1D19CDE0C381176AF6E41E0A66309EC9E5B38BAD27201EED5F1A5AC2FEA"),
			std::string("0A3265405CCD452F55DC1FBBE6FE66CA380503E0B2A6BD41CF65357186065F189FBC779985018FC0FB758C403DCFB860DF12AA92387CF559714286A81302FECD"
				"5CD468018F3359F2D0CF181014D5F40BEF4B793C0A9A8BC8115DDE9558F20B39"),
			// hbar256h256
			std::string("3196573F11BDE0E265BCDA83836062B676AEFC22DA61C488DC2585B36DB5B6A9430263A14393C1EA38ED5281EAFABC94"),
			std::string("5654C0DD29C2DDAF228D6B135133927FEA4E16A292532EF2EAD67E8BBEB8C883BB2A9666F49174A6D04D06BE87158738E91383804CB7922C97F1B3F1209C69AA"),
			std::string("58EE8ED312CECC334CDD4065282E1D12AA5B80D5B62432FFB4EC9A190F58DD3F9D12C39B61C6434E0068B0F70C3FA3D25D0344C1021F9EAC062A33A06B8DDCEA"
				"4B3D4DEEA7552CF5E861BF982F4EDFB7D4059D36863DE830FC5A235C594D4EBB"),
			// hbar256k256
			std::string("D1B1C7A44B0360C5B32F36865ABE458023175AA63B8F049D3256E14AE28319D8B5704C4DAE9BECFEEC6DC90F4290CA50"),
			std::string("72266262C11A694A022786517D1222C693EDB6D3F8FB4BD557D7DDEFB11AFC9E3FD3A186C91928B4641B5F7306FC3870831D62BC870667A243A46CEAE418DC35"),
			std::string("1B593A4FD95A25ED8EA645199BB5A4421F3B371354B83F78F1D97F42B882CBA2B245B310890BCE02AB5E86745837B447FED07B28F812FD16A8B32D9B65996E95"
				"F0C9C030776AC405E87C0E8D61DB7B70A4D24F0B301CBA7445D9FF4DBF75B598"),
			// hbar512h512
			std::string("E6A77A113818FA8B56B834C3DCC48DF644566AB1E7D2887A3237BB66AD64DC2D85434BA39178EEDDB5A74063666FE3160E1E609D743CD1020A3403611EC20650"
				"30C29A27F13003F58FBE1A3DE1393C4B"),
			std::string("9C00C33391FED7C439295DB6D9F6CC89CD79A9DC802A9592A71645876D762571865096352C126FEF6C02B73A848ECCF270F756CFDE658776C59283FC97EB2301"
				"B1266168F2965992824E1206AC99D565187032C688A9D90CAF61008AC79FACE9"),
			std::string("BC4B2C1333F04897B68FF8E60F7742A721EF7C09B7730FED84C99AC88D7C6BCBFEE73C1FE38D1680DD882E9BC1DDEC9D8AC1E4447EFE1CC7047DA1CF1900A110"
				"FD70D83DF717FF907418203D20292D5FC503335B7A2B95C36498623FF953B37962E981A1CAEC223410AFB0EB302B3E1D15F4D3B7157D7783A47606D43C4D61CA"),
			// hbar512k512
			std::string("3445EEABB15B39077D7A6FB7E7055FE49435BCA7CEAC9A834698FD26D60214AC4BC2146F9BD943044FAF62FA2185736D1CA3E09132C99604F620D000BE22331A"
				"23A4BD7D4C62EBF155EE63994C185976"),
			std::string("8238DFB8B88897E4C92490148AAFDB22C824FB1C7BD443FA0510D45BDFDFEC2EE89F3B64D4FF5FC5EC66FF81EAD38ADF73D45AE4E6D604FF8CE6FC7801805B3E"
				"2101B8E403B6516A95AA9650524B1E94E6850A2E886099EF87CAF0D783482F3E"),
			std::string("2CDC038A38D27F58B38AA2130D1AA61D525DD09ABCCCBBD7B45FB40851626482555B352F57B2913EFD722E2A4A3E525CD053C90B1DF89B212A0226D2BE3F7D77"
				"83B37EC9E7DF54B4538BCF45EFCB4C5FC6D941154468894D15F1D2FE9216938768D388F9FACCF1BECAB4418BFC68F67C0CF800F438A3FF9BCA1F24166F772319"),
			// hbar1024k1024
			std::string("4DA46E6DA360C7E2FDE7F32244BB5D38A0B56F22D4DAF5BB62BD67DA2B68A50FD529CAB1C05CA7221D92864B36EC97E821898D35B5E02CF920CB15C0CC850DD7"
				"CE802A44B1DFC3DC9627DD0E982708A8B10140E1789C2CFB57E5501C9CFD80840CAE2F8C1E1CCF6C27F24644E9DABB05505A00188880EB0F44B285029F301D54"
				"CA4D5B989672906763D049FE1798A5FC"),
			std::string("F4BE554E334993E4554291F5ABF973A812E8A4EA91052742C86CFC2A854A48F329D3BF15F749D37C19A8E97105A23B4620D1344A63DD9FA911451061D6A59993"
				"E418F846BF3711A7D491EF8458250355F755BE9C2B865D47463D4C554CE004DA37F10E53502793805427A33B2760C59F5D2ABD3F7E02BCA2FF0DD1C0CFAA0CD2"
				"1814C18D7C380C4AB5AD49AB212F39C6B14BA9496A4DEA7C8A8A391432516CCB"),
			std::string("ADC0D70822B0C191DC6D9BA4AEF8BB1119F234503859673DCA933937F4E493841516FF2A36CD80EC159B580804D8AA20C1360AD7BFF0A445525B602F94A5D344"
				"54FB6B51BD44DE082E74DFF15F40501B55C922BAE24D1C5D7FBA206BA72EBB9398E4948AECE06F539985F5F68302B14B11951D60F49636B96C0B8EF64D26C30E"
				"3044843BE576F5B9AA1CA5CF83591753227A2DE0BB81A243415D26B4E3803BFDA6B292D15D6BFC9DEC495E15699512818788DC21760B16D80A02C130EF301115"),
			// sequential tests
			// hbar256h256
			std::string("03C7368F5A31F4E23192582D7079481A36C62E6E8AEF3CB40F719496F37085101CE929C045EF17FA6856AC6F860805D3"),
			std::string("CEB77499A453635377B137CAC1D3531CDC7FE73549673864DD467D36C0B90D0D1E9AAB11B5EE6F6C32B6A728170F96E0"),
			std::string("6F41692B22E33558728E72BC92EF05AA16743F631A541A0233D919E757EB3EDCCB2A9F221461078B389A6501545C4F2F"),
			// hbar256k256
			std::string("8D70A81F79DD6C17D767958FB2A378ACC48E2051E71881B97620F68AFBE864DDD6EED7D04DAC292B8B845E27518BCD8E"),
			std::string("0D8BE103ACE6A0C61CE21C5D09F6E73B76337728085C46A5751A6FE635370DAED5888CFA0A319EB011903E481AEE308E"),
			std::string("90DB127C10E1FF00511B73910CA36CAC269BCDA7C921A09509FD79C6768AB6B78F6E4B2DD29B68F9B55EBD0CB1DC72AF"),
			// hbar512h512
			std::string("B8D276B0905D55E506449081F54C5ADF3F1066FE014AF619168FC71608F06D20566CD3F97D0DEB6ABC7633FC90B5872394781A84BB84E3B2A3A243D90A9A293B"
				"3309D046918B2106FAEC585C97563849"),
			std::string("22B759041E787D5AB4E07C64A03226136DD7B247E62502ABF790F632BB3BB92CA23C4E0C9C845F1AA34A52B2BBF6C14D251CA3CFE10B34DDE348ECCDFF53701C"
				"27F72FCEE667B87C7DA9CDC17E26F99A"),
			std::string("75E447755B2006D55BB64C5D4B13AAA35BF28C425DD6F1F3A0EDD6E6635E8015221680D371C8D9B0B27BF8A8877EA97FDF6521459C48729D84E60FFE00B4987F"
				"0A87C16C2925EF8B5ADC4CC9A5906523"),
			// hbar512k512
			std::string("0A13C7DFFF0A9156293CE764E7AC23D3404E5EF6A0CC08B606C8225D51417233E12790C4D2175D0251497CA4058ABD415E5E0F6CB4FA2DE87EECF48901A5B882"
				"48EC8F073A9107730D39772F4BC597D8"),
			std::string("7E1DEC82876E3EE98E74E5AA48CC55EC48506EA8F35FD987C58BC50A3A09E0FE0234E3C2AD5F4A3426E093E96A34A653D93B9FCB2077189100BF347265FD9B61"
				"057416FE9C177888A4281C3B1AFE6043"),
			std::string("936E14C39439BD494E6F892F94B00073015C155810DA0439778A837FC5BCF1EC2D83F30F679E77ED10671927AE61BAA365D2152B27686C99761BC0C1F6BDDA36"
				"160821F418FFF6722348E4C811831987"),
			// hbar1024k1024
			std::string("72E5E24E238A0A86063C569A515BFFA013CAE53CFA55DA9DAE60606EA10714A7FF0261A7B0CCABCA3DA7019B2084750DE07453213D8E07F0C78454AC0B2748CD"
				"8767C43731D104E4AD65B09BB30901D705A50EFF1D39818616FB6B421D2827807FAC38FEA94BA7C3F63B5541CA0A4BB98D468B83DB8AB84F6B3D2DB7E17FCD0D"
				"2D7804C1D6C25037C5CF2A72ADE12218"),
			std::string("BEEAC332C9F11A65221FAA4787D4E46B33446399881E375DBE09176A25A69459E319C680B1D2288F8FC398D3526638CFA57E45F97B8828893B8F3198FFFE4E5F"
				"A7B8B0583581D3248B899D4C4AF253DE6A3D2E855C7A0C9850B4E59168B4A130E4FF1D9DEB0F650270567E1E3BA7AD14BC0F6F84D54E55A9B74F968B1B36C76C"
				"8259B8CEC8A2E192A7DF3E7C74FE92DE"),
			std::string("B8D7D54CFD1B0FEA7CDEF15CAB741ED00697AF3C58A9B5E135D604E292CDAB85B4DA59DF8D201CAD1017AF266BFA83319722B205A4562A1F15142DE21A260A32"
				"7F5E4A5312CBECF9E023ADA8ED287779307A994CC841C65423750FD047CA4415691476693CB625428533D5F75C77D2F19687D96628B251BFA21F0DA99765EDD1"
				"C9DD3787D3EA8E9F7E6D62ACDDB14D21"),
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
