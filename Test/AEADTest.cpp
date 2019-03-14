#include "AeadTest.h"
#include "../CEX/EAX.h"
#include "../CEX/GCM.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Enumeration::AeadModes;
	using Enumeration::AeadModeConvert;
	using Exception::CryptoCipherModeException;
	using Cipher::Block::Mode::EAX;
	using Cipher::Block::Mode::GCM;
	using Cipher::Block::IBlockCipher;
	using Utility::IntegerTools;
	using Cipher::SymmetricKeySize;

	const std::string AeadTest::CLASSNAME = "AeadTest";
	const std::string AeadTest::DESCRIPTION = "Authenticate Encrypt and Associated Data (AEAD) Cipher Mode Tests.";
	const std::string AeadTest::SUCCESS = "SUCCESS! AEAD tests have executed succesfully.";

	//~~~Constructor~~~//

	AeadTest::AeadTest()
		:
		m_associatedText(0),
		m_cipherText(0),
		m_expectedCode(0),
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
		IntegerTools::Clear(m_expectedCode);
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
			OnProgress(std::string("AeadTest: Passed EAX and GCM exception handling tests.."));

			EAX* eax1 = new EAX(Enumeration::BlockCiphers::AES);
			Kat(eax1, m_key[0], m_nonce[0], m_associatedText[0], m_plainText[0], m_cipherText[0], m_expectedCode[0]);
			Kat(eax1, m_key[1], m_nonce[1], m_associatedText[1], m_plainText[1], m_cipherText[1], m_expectedCode[1]);
			Kat(eax1, m_key[2], m_nonce[2], m_associatedText[2], m_plainText[2], m_cipherText[2], m_expectedCode[2]);
			Kat(eax1, m_key[3], m_nonce[3], m_associatedText[3], m_plainText[3], m_cipherText[3], m_expectedCode[3]);
			Kat(eax1, m_key[4], m_nonce[4], m_associatedText[4], m_plainText[4], m_cipherText[4], m_expectedCode[4]);
			Kat(eax1, m_key[5], m_nonce[5], m_associatedText[5], m_plainText[5], m_cipherText[5], m_expectedCode[5]);
			Kat(eax1, m_key[6], m_nonce[6], m_associatedText[6], m_plainText[6], m_cipherText[6], m_expectedCode[6]);
			Kat(eax1, m_key[7], m_nonce[7], m_associatedText[7], m_plainText[7], m_cipherText[7], m_expectedCode[7]);
			Kat(eax1, m_key[8], m_nonce[8], m_associatedText[8], m_plainText[8], m_cipherText[8], m_expectedCode[8]);
			Kat(eax1, m_key[9], m_nonce[9], m_associatedText[9], m_plainText[9], m_cipherText[9], m_expectedCode[9]);
			delete eax1;
			OnProgress(std::string("AeadTest: Passed EAX known answer comparison tests.."));

			EAX* eax2 = new EAX(Enumeration::BlockCiphers::AES);
			Incremental(eax2);
			delete eax2;
			OnProgress(std::string("AeadTest: Passed EAX auto incrementing tests.."));

			EAX* eax3 = new EAX(Enumeration::BlockCiphers::AES);
			Parallel(eax3);
			delete eax3;
			OnProgress(std::string("AeadTest: Passed EAX parallel tests.."));

			EAX* eax4 = new EAX(Enumeration::BlockCiphers::AES);
			Stress(eax4);
			delete eax4;
			OnProgress(std::string("AeadTest: Passed EAX stress tests.."));

			GCM* gcm1 = new GCM(Enumeration::BlockCiphers::AES);
			Kat(gcm1, m_key[10], m_nonce[10], m_associatedText[10], m_plainText[10], m_cipherText[10], m_expectedCode[10]);
			Kat(gcm1, m_key[11], m_nonce[11], m_associatedText[11], m_plainText[11], m_cipherText[11], m_expectedCode[11]);
			Kat(gcm1, m_key[12], m_nonce[12], m_associatedText[12], m_plainText[12], m_cipherText[12], m_expectedCode[12]);
			Kat(gcm1, m_key[13], m_nonce[13], m_associatedText[13], m_plainText[13], m_cipherText[13], m_expectedCode[13]);
			Kat(gcm1, m_key[14], m_nonce[14], m_associatedText[14], m_plainText[14], m_cipherText[14], m_expectedCode[14]);
			Kat(gcm1, m_key[15], m_nonce[15], m_associatedText[15], m_plainText[15], m_cipherText[15], m_expectedCode[15]);
			Kat(gcm1, m_key[16], m_nonce[16], m_associatedText[16], m_plainText[16], m_cipherText[16], m_expectedCode[16]);
			Kat(gcm1, m_key[17], m_nonce[17], m_associatedText[17], m_plainText[17], m_cipherText[17], m_expectedCode[17]);
			Kat(gcm1, m_key[18], m_nonce[18], m_associatedText[18], m_plainText[18], m_cipherText[18], m_expectedCode[18]);
			Kat(gcm1, m_key[19], m_nonce[19], m_associatedText[19], m_plainText[19], m_cipherText[19], m_expectedCode[19]);
			Kat(gcm1, m_key[20], m_nonce[20], m_associatedText[20], m_plainText[20], m_cipherText[20], m_expectedCode[20]);
			Kat(gcm1, m_key[21], m_nonce[21], m_associatedText[21], m_plainText[21], m_cipherText[21], m_expectedCode[21]);
			Kat(gcm1, m_key[22], m_nonce[22], m_associatedText[22], m_plainText[22], m_cipherText[22], m_expectedCode[22]);
			Kat(gcm1, m_key[23], m_nonce[23], m_associatedText[23], m_plainText[23], m_cipherText[23], m_expectedCode[23]);
			Kat(gcm1, m_key[24], m_nonce[24], m_associatedText[24], m_plainText[24], m_cipherText[24], m_expectedCode[24]);
			Kat(gcm1, m_key[25], m_nonce[25], m_associatedText[25], m_plainText[25], m_cipherText[25], m_expectedCode[25]);
			Kat(gcm1, m_key[26], m_nonce[26], m_associatedText[26], m_plainText[26], m_cipherText[26], m_expectedCode[26]);
			Kat(gcm1, m_key[27], m_nonce[27], m_associatedText[27], m_plainText[27], m_cipherText[27], m_expectedCode[27]);
			delete gcm1;
			OnProgress(std::string("AeadTest: Passed GCM known answer comparison tests.."));

			GCM* gcm2 = new GCM(Enumeration::BlockCiphers::AES);
			Incremental(gcm2);
			delete gcm2;
			OnProgress(std::string("AeadTest: Passed GCM auto incrementing tests.."));

			GCM* gcm3 = new GCM(Enumeration::BlockCiphers::AES);
			Parallel(gcm3);
			delete gcm3;
			OnProgress(std::string("AeadTest: Passed GCM parallel tests.."));

			GCM* gcm4 = new GCM(Enumeration::BlockCiphers::AES);
			Stress(gcm4);
			delete gcm4;
			OnProgress(std::string("AeadTest: Passed GCM stress tests.."));

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
		// test every modes enumeration constructors for invalid block-cipher type //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Exception handling failure! -AE1"));
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
			GCM cpr(Enumeration::BlockCiphers::None);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::GCM), std::string("Exception handling failure! -AE2"));
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
			EAX cpr(nullptr);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Exception handling failure! -AE3"));
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
			GCM cpr(nullptr);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::GCM), std::string("Exception handling failure! -AE4"));
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
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE5"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::GCM), std::string("Threefish"), std::string("Exception handling failure! -AE6"));
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
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize() - 1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE7"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(0);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::GCM), std::string("Threefish"), std::string("Exception handling failure! -AE8"));
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
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::GCM), std::string("Threefish"), std::string("Exception handling failure! -AE10"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test each mode for uninitialized finalize call //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> tag(0);

			// call finalize on an uninitialized cipher
			tag.resize(cpr.MaxTagSize());
			cpr.Finalize(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> tag(0);

			// call finalize on an uninitialized cipher
			tag.resize(cpr.MaxTagSize());
			cpr.Finalize(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test each mode for invalid tag size //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> tag(0);

			// use an invalid mac-tag size when calling finalize
			tag.resize(1);
			cpr.Initialize(true, kp);
			cpr.Finalize(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> tag(0);

			// use an invalid mac-tag size when calling finalize
			tag.resize(1);
			cpr.Initialize(true, kp);
			cpr.Finalize(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test each mode uninitialized associated data calls //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> aad(16);

			// set associated data on an uninitialized cipher
			cpr.SetAssociatedData(aad, 0, aad.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> aad(16);

			// set associated data on an uninitialized cipher
			cpr.SetAssociatedData(aad, 0, aad.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test overlapping set associated data calls //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> aad(16);

			cpr.Initialize(true, kp);
			// set associated data for this stream
			cpr.SetAssociatedData(aad, 0, aad.size());
			// set associated data again, without calling finalize to reset the state
			cpr.SetAssociatedData(aad, 0, aad.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> aad(16);

			cpr.Initialize(true, kp);
			// set associated data for this stream
			cpr.SetAssociatedData(aad, 0, aad.size());
			// set associated data again, without calling finalize to reset the state
			cpr.SetAssociatedData(aad, 0, aad.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test uninitialized verify call //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> tag(cpr.MaxTagSize());

			// call verify without initializing or processing data
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			std::vector<byte> tag(cpr.MaxTagSize());

			// call verify without initializing or processing data
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test illegal verify call in encrypt operation mode  //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> tag(cpr.MaxTagSize());

			// initialize for encryption
			cpr.Initialize(true, kp);
			// call verify in wrong operation mode
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> tag(cpr.MaxTagSize());

			// initialize for encryption
			cpr.Initialize(true, kp);
			// call verify in wrong operation mode
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test verify call with invalid tag size  //

		try
		{
			EAX cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> inp(cpr.BlockSize());
			std::vector<byte> otp(cpr.BlockSize());
			std::vector<byte> tag(1);

			// initialize for decryption
			cpr.Initialize(false, kp);
			cpr.Transform(inp, 0, otp, 0, inp.size());
			// the tag is sized too small
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
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
			GCM cpr(Enumeration::BlockCiphers::AES);
			SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);
			std::vector<byte> inp(cpr.BlockSize());
			std::vector<byte> otp(cpr.BlockSize());
			std::vector<byte> tag(1);

			// initialize for decryption
			cpr.Initialize(false, kp);
			cpr.Transform(inp, 0, otp, 0, inp.size());
			// the tag is sized too small
			cpr.Verify(tag, 0, tag.size());

			throw TestException(std::string("Exception"), AeadModeConvert::ToName(AeadModes::EAX), std::string("Threefish"), std::string("Exception handling failure! -AE9"));
		}
		catch (CryptoCipherModeException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void AeadTest::Kat(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, std::vector<byte> &PlainText,
		std::vector<byte> &CipherText, std::vector<byte> &MacCode)
	{
		SymmetricKey kp(Key, Nonce);
		Cipher->Initialize(true, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}

		// test encryption
		std::vector<byte> enc(CipherText.size());
		Cipher->Transform(PlainText, 0, enc, 0, PlainText.size());
		Cipher->Finalize(enc, PlainText.size(), 16);

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
		std::vector<byte> tmp(CipherText.size());
		const size_t BLKLEN = (enc.size() >= 16) ? enc.size() - Cipher->BlockSize() : 0;
		Cipher->Transform(enc, 0, tmp, 0, BLKLEN);

		std::vector<byte> mac(16);
		Cipher->Finalize(mac, 0, 16);

		// Finalizer can be skipped if Verify called
		if (!Cipher->Verify(enc, BLKLEN, 16))
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AeadTest: Tags do not match! -AK2"));
		}

		std::vector<byte> dec(BLKLEN);
		if (BLKLEN != 0)
		{
			std::memcpy(&dec[0], &tmp[0], BLKLEN);
		}
		if (PlainText != dec)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AK3"));
		}
		if (MacCode != mac || MacCode != Cipher->Tag())
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("AeadTest: Tags do not match! -AK4"));
		}
	}

	void AeadTest::Incremental(IAeadMode* Cipher)
	{
		std::vector<byte> ad(10, 0x10);
		std::vector<byte> nonce(Cipher->Enumeral() == Enumeration::CipherModes::EAX ? 16 : 12, 0x11);
		std::vector<byte> key(16, 0x05);
		std::vector<byte> dec(64, 0x07);
		std::vector<byte> enc1(80);

		// get base value
		SymmetricKey kp1(key, nonce);
		Cipher->Initialize(true, kp1);
		// test persisted ad
		Cipher->PreserveAD() = true;
		Cipher->SetAssociatedData(ad, 0, ad.size());
		Cipher->Transform(dec, 0, enc1, 0, dec.size());
		Cipher->Finalize(enc1, dec.size(), 16);

		// 10* finalize on decremented nonce
		std::vector<byte> enc2(80);
		// decrement counter by 10
		nonce[nonce.size() - 1] -= 10;
		SymmetricKey kp2(key, nonce);
		// set to auto increment, with nonce auto-incremented post finalize, last run should equal first output
		Cipher->AutoIncrement() = true;
		Cipher->Initialize(true, kp2);

		// run 10 loops, +1 iteration should be equivalent to test run
		for (size_t i = 0; i < 10; ++i)
		{
			Cipher->Transform(dec, 0, enc2, 0, dec.size());
			Cipher->Finalize(enc2, dec.size(), 16);
		}
		Cipher->AutoIncrement() = false;

		// this output should be different because of nonce -1
		if (enc1 == enc2)
		{
			throw TestException(std::string("Incremental"), Cipher->Name(), std::string("AeadTest: Output does not match! -AI1"));
		}

		// get the code after incrementing nonce one last time
		Cipher->Transform(dec, 0, enc2, 0, dec.size());
		Cipher->Finalize(enc2, dec.size(), 16);

		if (enc1 != enc2)
		{
			throw TestException(std::string("Incremental"), Cipher->Name(), std::string("AeadTest: Output does not match! -AI2"));
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
		Prng::SecureRandom rng;

		for (size_t i = 0; i < 100; ++i)
		{
			const uint32_t BLKLEN = rng.NextUInt32(static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize() * 4), static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize()));

			data.resize(BLKLEN);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			SymmetricKey kp(key, nonce);

			// parallel encryption mode
			enc1.resize(BLKLEN + Cipher->MaxTagSize());
			Cipher->ParallelProfile().IsParallel() = true;
			// note: changes to parallel block-size must be set before every Initialize() call
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc1, 0, data.size());
			Cipher->Finalize(enc1, BLKLEN, Cipher->MaxTagSize());

			// sequential mode
			enc2.resize(BLKLEN + Cipher->MaxTagSize());
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc2, 0, data.size());
			Cipher->Finalize(enc2, BLKLEN, Cipher->MaxTagSize());

			if (enc1 != enc2)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AP1"));
			}

			// parallel decryption mode
			dec1.resize(BLKLEN);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc1, 0, dec1, 0, enc1.size() - Cipher->MaxTagSize());
			Cipher->Finalize(enc1, BLKLEN, Cipher->MaxTagSize());

			// sequential decryption mode
			dec2.resize(BLKLEN);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc2, 0, dec2, 0, enc2.size() - Cipher->MaxTagSize());
			Cipher->Finalize(enc2, BLKLEN, Cipher->MaxTagSize());

			if (dec1 != dec2)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AP2"));
			}
			if (dec1 != data)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AP3"));
			}
			if (!Cipher->Verify(enc1, BLKLEN, Cipher->MaxTagSize()))
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("AeadTest: Tags do not match! -AP4"));
			}
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

		for (size_t i = 0; i < 100; ++i)
		{
			const size_t BLKLEN = rng.NextUInt32(10000, 100);
			data.resize(BLKLEN);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			SymmetricKey kp(key, nonce);

			enc.resize(BLKLEN + Cipher->MaxTagSize());
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc, 0, data.size());
			Cipher->Finalize(enc, BLKLEN, Cipher->MaxTagSize());

			dec.resize(BLKLEN);
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc, 0, dec, 0, enc.size() - Cipher->MaxTagSize());

			if (!Cipher->Verify(enc, BLKLEN, Cipher->MaxTagSize()))
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("AeadTest: Tags do not match! -AS1"));
			}
		}
	}

	//~~~Private Functions~~~//

	void AeadTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> key =
		{
			// eax
			std::string("233952DEE4D5ED5F9B9C6D6FF80FF478"),
			std::string("91945D3F4DCBEE0BF45EF52255F095A4"),
			std::string("01F74AD64077F2E704C0F60ADA3DD523"),
			std::string("D07CF6CBB7F313BDDE66B727AFD3C5E8"),
			std::string("35B6D0580005BBC12B0587124557D2C2"),
			std::string("BD8E6E11475E60B268784C38C62FEB22"),
			std::string("7C77D6E813BED5AC98BAA417477A2E7D"),
			std::string("5FFF20CAFAB119CA2FC73549E20F5B0D"),
			std::string("A4A4782BCFFD3EC5E7EF6D8C34A56123"),
			std::string("8395FCF1E95BEBD697BD010BC766AAC3"),
			// gcm
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
		HexConverter::Decode(key, 28, m_key);

		const std::vector<std::string> nonce =
		{
			// eax
			std::string("62EC67F9C3A4A407FCB2A8C49031A8B3"),
			std::string("BECAF043B0A23D843194BA972C66DEBD"),
			std::string("70C3DB4F0D26368400A10ED05D2BFF5E"),
			std::string("8408DFFF3C1A2B1292DC199E46B7D617"),
			std::string("FDB6B06676EEDC5C61D74276E1F8E816"),
			std::string("6EAC5C93072D8E8513F750935E46DA1B"),
			std::string("1A8C98DCD73D38393B2BF1569DEEFC19"),
			std::string("DDE59B97D722156D4D9AFF2BC7559826"),
			std::string("B781FCF2F75FA5A8DE97A9CA48E522EC"),
			std::string("22E7ADD93CFC6393C57EC0B3C17D6B44"),
			// gcm
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
		HexConverter::Decode(nonce, 28, m_nonce);

		const std::vector<std::string> associated =
		{
			// eax
			std::string("6BFB914FD07EAE6B"),
			std::string("FA3BFD4806EB53FA"),
			std::string("234A3463C1264AC6"),
			std::string("33CCE2EABFF5A79D"),
			std::string("AEB96EAEBE2970E9"),
			std::string("D4482D1CA78DCE0F"),
			std::string("65D2017990D62528"),
			std::string("54B9F04E6A09189A"),
			std::string("899A175897561D7E"),
			std::string("126735FCC320D25A"),
			// gcm
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
		HexConverter::Decode(associated, 28, m_associatedText);

		const std::vector<std::string> plain =
		{
			// eax
			std::string(""),
			std::string("F7FB"),
			std::string("1A47CB4933"),
			std::string("481C9E39B1"),
			std::string("40D0C07DA5E4"),
			std::string("4DE3B35C3FC039245BD1FB7D"),
			std::string("8B0A79306C9CE7ED99DAE4F87F8DD61636"),
			std::string("1BDA122BCE8A8DBAF1877D962B8592DD2D56"),
			std::string("6CF36720872B8513F6EAB1A8A44438D5EF11"),
			std::string("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7"),
			// gcm
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
		HexConverter::Decode(plain, 28, m_plainText);

		const std::vector<std::string> cipher =
		{
			// eax
			std::string("E037830E8389F27B025A2D6527E79D01"),
			std::string("19DD5C4C9331049D0BDAB0277408F67967E5"),
			std::string("D851D5BAE03A59F238A23E39199DC9266626C40F80"),
			std::string("632A9D131AD4C168A4225D8E1FF755939974A7BEDE"),
			std::string("071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"),
			std::string("835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"),
			std::string("02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"),
			std::string("2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"),
			std::string("0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"),
			std::string("CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"),
			// gcm
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
		HexConverter::Decode(cipher, 28, m_cipherText);

		const std::vector<std::string> code =
		{
			// eax
			std::string("E037830E8389F27B025A2D6527E79D01"),
			std::string("5C4C9331049D0BDAB0277408F67967E5"),
			std::string("3A59F238A23E39199DC9266626C40F80"),
			std::string("D4C168A4225D8E1FF755939974A7BEDE"),
			std::string("CB0677E536F73AFE6A14B74EE49844DD"),
			std::string("ABB8644FD6CCB86947C5E10590210A4F"),
			std::string("137327D10649B0AA6E1C181DB617D7F2"),
			std::string("3B60450599BD02C96382902AEF7F832A"),
			std::string("E7F6D2231618102FDB7FE55FF1991700"),
			std::string("CFC46AFC253B4652B1AF3795B124AB6E"),
			// gcm
			std::string("58E2FCCEFA7E3061367F1D57A4E7455A"),
			std::string("AB6E47D42CEC13BDF53A67B21257BDDF"),
			std::string("4D5C2AF327CD64A62CF35ABD2BA6FAB4"),
			std::string("5BC94FBC3221A5DB94FAE95AE7121A47"),
			std::string("3612D2E79E3B0785561BE14AACA2FCCB"),
			std::string("619CC5AEFFFE0BFA462AF43C1699D050"),
			std::string("CD33B28AC773F74BA00ED1F312572435"),
			std::string("2FF58D80033927AB8EF4D4587514F0FB"),
			std::string("9924A7C8587336BFB118024DB8674A14"),
			std::string("2519498E80F1478F37BA55BD6D27618C"),
			std::string("65DCC57FCF623A24094FCCA40D3533F8"),
			std::string("DCF566FF291C25BBB8568FC3D376A6D9"),
			std::string("530F8AFBC74536B9A963B4F1C4CB738B"),
			std::string("D0D1C8A799996BF0265B98B5D48AB919"),
			std::string("B094DAC5D93471BDEC1A502270E3CC6C"),
			std::string("76FC6ECE0F4E1768CDDF8853BB2D551B"),
			std::string("3A337DBF46A792C45E454913FE2EA8F2"),
			std::string("A44A8266EE1C8EB0C8B5D4CF5AE9F19A")
		};
		HexConverter::Decode(code, 28, m_expectedCode);
		/*lint -restore */
	}

	void AeadTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
