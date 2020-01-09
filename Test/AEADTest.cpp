#include "AeadTest.h"
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
	using Cipher::Block::Mode::HBA;
	using Cipher::Block::IBlockCipher;
	using Utility::IntegerTools;
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

			// known answer tests
			// AES-256-HMAC-256
			HBA* hbaa256h256 = new HBA(BlockCiphers::AES, StreamAuthenticators::HMACSHA256);
			Kat(hbaa256h256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[0]);
			Kat(hbaa256h256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[1]);
			Kat(hbaa256h256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[2]);
			delete hbaa256h256;
			// AES-256-KMAC-256
			HBA* hbaa256k256 = new HBA(BlockCiphers::AES, StreamAuthenticators::KMAC256);
			Kat(hbaa256k256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[3]);
			Kat(hbaa256k256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[4]);
			Kat(hbaa256k256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[5]);
			delete hbaa256k256;
			// RHX-256-HMAC-256
			HBA* hbar256h256 = new HBA(BlockCiphers::RHXH256, StreamAuthenticators::HMACSHA256);
			Kat(hbar256h256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[6]);
			Kat(hbar256h256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[7]);
			Kat(hbar256h256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[8]);
			// RSX-256-KMAC-256
			HBA * hbar256k256 = new HBA(BlockCiphers::RHXS256, StreamAuthenticators::KMAC256);
			Kat(hbar256k256, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[9]);
			Kat(hbar256k256, m_key[0], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[10]);
			Kat(hbar256k256, m_key[0], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[11]);
			// RHX-512-HMAC-512
			HBA* hbar512h512 = new HBA(BlockCiphers::RHXH512, StreamAuthenticators::HMACSHA512);
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

			delete hbar256k256;
			delete hbar256h256;
			delete hbar512h512;
			delete hbar512k512;
			delete hbar1024k1024;

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
			HBA cpr(Enumeration::BlockCiphers::None, Enumeration::StreamAuthenticators::HMACSHA256);

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
			HBA cpr(nullptr, Enumeration::StreamAuthenticators::HMACSHA256);

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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA256);
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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA256);
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
			HBA cpr(Enumeration::BlockCiphers::AES, Enumeration::StreamAuthenticators::HMACSHA256);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];

			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
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
		if (!IntegerTools::Compare(PlainText, 0, dec, 0, PlainText.size()))
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
		std::vector<byte> nonce(keySizes[0].NonceSize());
		std::vector<byte> assoc(16);
		size_t i;
		Prng::SecureRandom rng;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const uint32_t BLKLEN = rng.NextUInt32(static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize() * 4), static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize()));

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
		std::vector<byte> nonce(keySize.NonceSize());
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
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0"),
			std::string("10000000000000000000000000000000"),
			std::string("00000000000000000000000000000001")
		};
		HexConverter::Decode(nonce, 3, m_nonce);

		const std::vector<std::string> associated =
		{
			std::string("FACEDEADBEEFABADDAD2FEEDFACEDEADBEEFFEED"),
			std::string("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"),
			std::string("ADBEEFABADDAD2FEEDFACEDEADBEEFFEEDFACEDE")
		};
		HexConverter::Decode(associated, 3, m_associatedText);

		const std::vector<std::string> plain =
		{
			std::string("00000000000000000000000000000001"),
			std::string("1000000000000000000000000000000000000000000000000000000000000000"),
			std::string("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255")
		};
		HexConverter::Decode(plain, 3, m_plainText);

		const std::vector<std::string> cipher =
		{
			// hba kats
			// hbaa256h256
			std::string("51928788D6430A5485CD4A72AAFE1D18AC6974C00A40138518E517B8ED2032AB0E276918C39300BAB5766755DE1A53AC"),
			std::string("8C31CF1E5614E33FAD2B714E9587EB4AA5D29637F1712AE67E5FB3DD43543F42458078536782C018E1DC656CF234C3FC1FBC433225E9874C59A8D23326ABE784"),
			std::string("FA9CF018B9C6EBF882855720A91DD5DBF65983AC10FDF119091054DB6752EF129EE944A7B39B2F0C0CED9B3D0B17F9F9B2A9D183207B83506F9D5E4F47EE5F89"
				"B2755BB9C62DD665953E43580B59F0C67373741DF5BB070E251AFA4AF7C63543"),
			// hbaa256k256
			std::string("F9D0E4FF43722FD0ABBBD4257853F5A2C328036214F5DBF117FB16B4F5D1F871C82DE7AAF0FDB65A9A685B2B3E0C3E3D"),
			std::string("0C96282EBEFF3D67EC652698CC54443E585C773A24EF15B280540399D575BAE781FDC24C8D9C604184E2631BF13D5445E0859EA8141F153E668EBCA2A60BBBAE"),
			std::string("76AF45137CEB570B5894765ED4D56B2FA69E332120E1F6E82CBAFEF2FFD2E62D859F1A2E02B7AE1A97B5593EEE089829D8589B674A9DA12CDE58A208AD7EFE3D"
				"F6C151481FDAEEAD9934C510FE311A4DF37A73917E7EE711054A3E2B7FD5D632"),
			// hbar256h256
			std::string("4D84CB3748DB5306B57937A249BDC350393C51167DAFEDFEA08D1D34A89416A0E12030E428E88AC1E614D1F401D7083B"),
			std::string("0FF25E320AFE0A14953C2C40CB95F185C4F660743655C4952B3A854178EC1D927458CAD7B321A5C14E3FC7B2EA616ED7ED50F1E7EB4D9BF60F12611BC95EAF61"),
			std::string("295DCEF3149C7E6D7BE16E41595EA160B9562D25D1F46A83E80EADE187B7802A534D3AB9284DD8BEBE13F0AD01BEE7B73CE82914E7FB5A29856A345D95ACD620"
				"01D6180A4A4B966FAB12D223C6A2CE21BE1C496A10B90BADA01D048A38D41DEB"),
			// hbar256k256
			std::string("441EF350998DF4C94E1B213E8788200476C92EA60C002D8ABFB814473410AA44FBBC896656D260280F8FC9421694FCDB"),
			std::string("B6488F5240861A271F9D0DC60101EE11EBE18A8E7D7226787CBAAD6DA1D139EEB5CAD502C4A3CCBEFED40E47693684ADD4A52E2B86B2DB73CBFCD760D23E9B06"),
			std::string("87CF79C66478E372F5BD7C0273D25BE8614A7A30FAD3B26C48F9B63EA6C2FDF5E1D154959DA4042AD37955882BD54345D6D5071506148783554EE1D9D0628EC0"
				"BE479E0ED2B91BB8752D25638E9B2C34A61016C6378B1DDB3327E7C7AFE34A63"),
			// hbar512h512
			std::string("3A8D794EE017CDC58589F8B6738ADA41D963325F6F192F969D72C898742DE6FF72185593DE64588BA9DDBB0FA74E11B2833F30E4B1EB4B6678E14DF9FD8EF3A0"
				"7E22FC0D33009C1BF8BD49119DA8BFC8"),
			std::string("0F88C8A8785FE66989DE8E8645F72ECAA6B1C6A19641A704FD4DA44236EED54F0F5D6F8F76FEAB328A23A6F68D6CB46CDA62DFE0B938F491607A432B684AE4F4"
				"5BF2FC0E371E5515CAF58CE18C38C2F7A624D9BF15B72BCACCD826D2BBF68D31"),
			std::string("22E280BCD9C51E57816EC7FE84413C9C787C4E8F777182FE6C0AD6A52ECE844341A00DD22295DCB8864B5BAF73038DFA016FCDA97E421AC281BF967457B97F88"
				"BA792EE35320C49836193B775DE1EA61B04D8CACF02C922B17ADA9B0F092281B65630B1B36C63B9B9C24E73A317B82BEFD8B9832BE7505D52B62775680A362FF"),
			// hbar512k512
			std::string("98C4B8D42A5CB9F9CFDFC1EEB990DB50B3B712C5A6795AD0FF55C8796FEA63446549943738806B4C74A94664556B305C18D06B724A9D1B5C1D23863BC0024B23"
				"8EBB9015242C7A608961CEC6B255437B"),
			std::string("E016F0FD9C83AA0D4B06D91AFBA442BE32DEF9B080296163841DD1BADEB2A8302B79BA21CD0EC11A9A5556596F52353AFA526DE0D92C72D80C4A97B81FF8312B"
				"351D616F53C8FCC9C37F37079B48B8930BD2A607BCB4FCE3E1B046906F2D95D8"),
			std::string("87E21FE9F9E5BFA877027159EE9BB7C74BE3FDD366F9199DEB4C2D179A291F9C6BF4D2747401B815588E06239E21DAC126599D33B416EE5A0236F00E42063B25"
				"E7B295481FC7BBEAF2C263C0E5A9C638CB2502B1F6583700118BB9E3EE417FBF0865BB4996192A55ED2BB0B843B6E777F24212F22E1F78F5AF3AF6A40D2233C4"),
			// hbar1024k1024
			std::string("7C1456FFA0AA1C91DCB61173EEF7C9BE650C4795233812C75669C186EB24C3F232BBDFC0CAC9227D5A3CE175391A80624CA09665D889428052E477BC932555D7"
				"4B94145967C3790F1FDF92A12D36C7F9E9824E575E64BCA44489FFFD453C623DE05C3598BA384BA3153EA8D20B5B1B27D9752F5CA8A53241DC74CE74756CC5D5"
				"CED21C394ABD7F7DBAAA86AB76B25353"),
			std::string("095ABB1A0578D62F68556652F9C0E226AD9304505B23444DC551782A61FE37205B49AE6A186C490BA8C9DF81C243CAEA17C6948BA3FAC8437682E0EA625B2CBC"
				"7396AFE957DEC3BF82DD361E539A422DF9167BF46261E76B28F28337F5A4649604E30819466574929FDB447696F9DB138D2124B2EC1CA29FDF3D6DF705A152B4"
				"BCEC68DD4E3709BEB0BB92085107A33B0A998CCACF7A4129C26AE9F8FB14D3B6"),
			std::string("77E5F39126E696A2AA32A8301BCB18BEED60A3C2EAB977691B1A1F03CB8926B7FA89619BEAD3426EAD24CA2141DD0D084BD927E4F460745A3A17FEA677464C0A"
				"823946B2B09E3CEFA59DE264C1CC1AE076318C3CC467DE55C95450172508A3916E737C31C8B02143901DB0B354FCB13FB92E999C62C5D25839218FE9289FAAEF"
				"1EDB134CE3307304DBD3F3F698B38D6474602C96DB2CFD923C427EEBE3570FC46FC32E7D869895AB0FCCF020BAC6EB0CB4E820B1A3C8C7AD8625FE009904C172"),
			// sequential tests
			// hbar256h256
			std::string("E800D5ED278C7B0916E52ABDE4FF74DE61F5FCC4243E5CC850B1C5A833A25AD31587C33685787AD5D92FD275664B3B18"),
			std::string("822CA77D21FBA07D548C74D2A378481FF4891E4B74B05E324D3AFF5C8BDAAAD0B5ACA49CF1E12E6CA7B2824F8C4D14C0"),
			std::string("D2D773793A9E19829FCB67681A647D33EA2B17BDC206E0ABBED9E0535BA042249D37BF78D8170CF57E6F1AE8E1E8B0FB"),
			// hbar256k256
			std::string("CB9AB62DE052A00B3C066D483E5AA1C7600A03CD1927FB24523A973897A53051D175B091F3C4DE12844A85DA1357984D"),
			std::string("F5573B06605B38B3672AD72E7662C6456728CE49BB2031AEF37EC2E5A2C8F5CA55015A84D71337A61BA1FDC7480CDB2E"),
			std::string("BB31467527BCD59B50C07FC9FB1BE4C536B71C1198ABAE9BC7059C2EF54B3C049CC1F89B224B98167FAB106BAA473F8A"),
			// hbar512h512
			std::string("7975F7F78EE4AE30DE23E9D150BC13650AE38A3D76A3B8FAD86A309E3486A454A7F4A6DB480F806D4137726D01B9D7ED1C69BE05F7812867AF2AE2D6AD4A7434"
				"23A50E356A7F0F31AC20F0F9A071860F"),
			std::string("0B89D7ECD2895BC01D5CD7186758729B2516B4D4CEB8B4BDB0360945C9BE495BB1BFF32DC3C219916F3B2A83F35152B2B7EA0E959637D801388E5440A60EB50F"
				"73A9E21D794191A243EC3486CA95A9B5"),
			std::string("4227B7823CEEA0EC5329E0909EC24582E09A8A9F65A95BAA0FD69E27AD34FE8902D9CFBBB4E27CE9CEF854B7BFF2AC4D9B579D6352689C7BF4223E4EE9360B0A"
				"455E4309A4A38ADDED66FE44F8EC993B"),
			// hbar512k512
			std::string("FE6B3F1498EB38652EDCEBBEB3247456EDAA547E13DFF1CC45582C296206E10A1D8F28720596FF40E41799248445B0A3CD0896C0537C257F062FEF7F19CB65CD"
				"A5ACC5F966FED1842104FD99C59C16E2"),
			std::string("137BFBA9D1A2440D17E884F4FDC9B109FAC3D7331468623EA9DD889331AD6B8535A6A4E3E232325D3ABBE13A97DA461EC6FD9E14E1C248A4CE2CFEF39F5F0E1B"
				"F7EC4898DD4C0D4E4D3CF0654708E5C0"),
			std::string("B87E65C65E63212A68E4DFA0AC1B885FF44EB0510522DBB2736E82D3CA7E886F211E73328E2B27A646EFBF6586C3153CC716CBD8489155E833D304ADEF5899E9"
				"DAB8C5AEFC5E457EA5312C0930F1C599"),
			// hbar1024k1024
			std::string("612B09A500C2E5C9F245426A8CCE7FA0D570E0C1619F84A83FE378ABC0D32DA29709ABB8FF0695FFE81AE00F76EC1C96ADF7165D9743CCA7E1BFF060ED09C151"
				"90BB73002B5B37284BFA304213A26C939BFDE8F2C6CDB769597A49D96C26C8C275409D3ABE8929E74F01CA7F38FB6A8FDAE1AFD984E1FD345FCC67F13C6B10FB"
				"9511E7ECB0DFD40DC633CFD27891E3E8"),
			std::string("D7C164BBF0BBA1F6ABA6EE87517A4E1A6F39ECB83E16415264D791E122EE81D659BC2ED990A50D447A3621BA16AA86442825B68B4EC3807B6707F03C4E64161D"
				"A3518D9C742911C6229D28F2524658B5843EFCD6766F563DABA48093CB7E6BF262336912429CF99AE8508F651A527A8D5B5D175C071E05021CBFABFA9B47ED97"
				"1112BD5F5448A6F45D86494760773C56"),
			std::string("F219DDD039345D01A0906C68C0EDA60ECA8C5E87ECEB3289A50F0102E4517EEEFFF19713A4302A9BFDAC6255F3F01F6C0A508D78E42A9242D8BBF539C7FA253D"
				"978E5F7260A78C6360E97B5AFA69F174C9E44DB0A033A826F22160E4822DF175DA8C265DBCCBC4182CC7F433E6DCD9C9CFABEC46BF3A7C379D7EEE8376A65BDF"
				"CC052EBCC66274CE061F60D3044DF396")
		};
		HexConverter::Decode(cipher, 36, m_cipherText);

		/*lint -restore */
	}

	void AeadTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
