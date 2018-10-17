#include "AeadTest.h"
#include "../CEX/EAX.h"
#include "../CEX/GCM.h"
#include "../CEX/IntUtils.h"
#include "../CEX/OCB.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Cipher::Symmetric::Block::IBlockCipher;
	using Cipher::Symmetric::Block::Mode::EAX;
	using Cipher::Symmetric::Block::Mode::GCM;
	using Cipher::Symmetric::Block::Mode::OCB;
	using Utility::IntUtils;

	const std::string AeadTest::DESCRIPTION = "Authenticate Encrypt and Associated Data (AEAD) Cipher Mode Tests.";
	const std::string AeadTest::FAILURE = "FAILURE! ";
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
		IntUtils::ClearVector(m_associatedText);
		IntUtils::ClearVector(m_cipherText);
		IntUtils::ClearVector(m_expectedCode);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_nonce);
		IntUtils::ClearVector(m_plainText);
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
			EAX* cpr1 = new EAX(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = 0; i < EAX_TESTSIZE; ++i)
			{
				Kat(cpr1, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			OnProgress(std::string("AeadTest: Passed EAX known answer comparison tests.."));

			Stress(cpr1);
			OnProgress(std::string("AeadTest: Passed EAX stress tests.."));

			Parallel(cpr1);
			OnProgress(std::string("AeadTest: Passed EAX parallel tests.."));

			Incremental(cpr1);
			OnProgress(std::string("AeadTest: Passed EAX auto incrementing tests.."));

			delete cpr1;

			OCB* cpr2 = new OCB(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = EAX_TESTSIZE; i < EAX_TESTSIZE + OCB_TESTSIZE; ++i)
			{
				Kat(cpr2, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			OnProgress(std::string("AeadTest: Passed OCB known answer comparison tests.."));

			Stress(cpr2);
			OnProgress(std::string("AeadTest: Passed OCB stress tests.."));

			Parallel(cpr2);
			OnProgress(std::string("AeadTest: Passed OCB parallel tests.."));

			Incremental(cpr2);
			OnProgress(std::string("AeadTest: Passed OCB auto incrementing tests.."));

			delete cpr2;

			GCM* cpr3 = new GCM(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = EAX_TESTSIZE + OCB_TESTSIZE; i < EAX_TESTSIZE + OCB_TESTSIZE + GCM_TESTSIZE; ++i)
			{
				Kat(cpr3, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			OnProgress(std::string("AeadTest: Passed GCM known answer comparison tests.."));

			Stress(cpr3);
			OnProgress(std::string("AeadTest: Passed GCM stress tests.."));

			Parallel(cpr3);
			OnProgress(std::string("AeadTest: Passed GCM parallel tests.."));

			Incremental(cpr3);
			OnProgress(std::string("AeadTest: Passed GCM auto incrementing tests.."));

			delete cpr3;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error!")));
		}
	}

	void AeadTest::Kat(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, std::vector<byte> &PlainText,
		std::vector<byte> &CipherText, std::vector<byte> &MacCode)
	{
		Key::Symmetric::SymmetricKey kp(Key, Nonce);
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
			throw TestException(std::string("AeadTest: Encrypted output is not equal! -AK1"));
		}

		// decryption
		Cipher->Initialize(false, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}
		std::vector<byte> tmp(CipherText.size());
		const size_t dlen = (enc.size() >= 16) ? enc.size() - Cipher->BlockSize() : 0;
		Cipher->Transform(enc, 0, tmp, 0, dlen);

		std::vector<byte> mac(16);
		Cipher->Finalize(mac, 0, 16);

		// Finalizer can be skipped if Verify called
		if (!Cipher->Verify(enc, dlen, 16))
		{
			throw TestException(std::string("AeadTest: Tags do not match! -AK2"));
		}

		std::vector<byte> dec(dlen);
		if (dlen != 0)
		{
			std::memcpy(&dec[0], &tmp[0], dlen);
		}
		if (PlainText != dec)
		{
			throw TestException(std::string("AeadTest: Decrypted output is not equal! -AK3"));
		}
		if (MacCode != mac || MacCode != Cipher->Tag())
		{
			throw TestException(std::string("AeadTest: Tags do not match! -AK4"));
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
		Key::Symmetric::SymmetricKey kp1(key, nonce);
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
		Key::Symmetric::SymmetricKey kp2(key, nonce);
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
			throw TestException(std::string("AeadTest: Output does not match! -AI1"));
		}

		// get the code after incrementing nonce one last time
		Cipher->Transform(dec, 0, enc2, 0, dec.size());
		Cipher->Finalize(enc2, dec.size(), 16);

		if (enc1 != enc2)
		{
			throw TestException(std::string("AeadTest: Output does not match! -AI2"));
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
		std::vector<Key::Symmetric::SymmetricKeySize> keySizes = Cipher->LegalKeySizes();
		std::vector<byte> nonce(keySizes[0].NonceSize());
		std::vector<byte> assoc(16);
		Prng::SecureRandom rng;

		for (size_t i = 0; i < 100; ++i)
		{
			uint32_t dlen = rng.NextUInt32(static_cast<uint32_t>(Cipher->ParallelProfile().ParallelMinimumSize() * 10), static_cast<uint32_t>(Cipher->ParallelProfile().ParallelMinimumSize() * 2));
			// important! if manually sizing parallel block, make it evenly divisible by parallel minimum size
			const size_t PRLBLK = dlen - (dlen % Cipher->ParallelProfile().ParallelMinimumSize());

			data.resize(dlen);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			Key::Symmetric::SymmetricKey kp(key, nonce);

			// parallel encryption mode
			enc1.resize(dlen + Cipher->MaxTagSize());
			Cipher->ParallelProfile().IsParallel() = true;
			// note: changes to parallel block-size must be set before every Initialize() call
			Cipher->ParallelProfile().ParallelBlockSize() = PRLBLK;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc1, 0, data.size());
			Cipher->Finalize(enc1, dlen, Cipher->MaxTagSize());

			// sequential mode
			enc2.resize(dlen + Cipher->MaxTagSize());
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc2, 0, data.size());
			Cipher->Finalize(enc2, dlen, Cipher->MaxTagSize());

			if (enc1 != enc2)
			{
				throw TestException(std::string("AeadTest: Encrypted output is not equal! -AP1"));
			}

			// parallel decryption mode
			dec1.resize(dlen);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->ParallelProfile().ParallelBlockSize() = PRLBLK;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc1, 0, dec1, 0, enc1.size() - Cipher->MaxTagSize());
			Cipher->Finalize(enc1, dlen, Cipher->MaxTagSize());

			// sequential decryption mode
			dec2.resize(dlen);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc2, 0, dec2, 0, enc2.size() - Cipher->MaxTagSize());
			Cipher->Finalize(enc2, dlen, Cipher->MaxTagSize());

			if (dec1 != dec2)
			{
				throw TestException(std::string("AeadTest: Decrypted output is not equal! -AP2"));
			}
			if (dec1 != data)
			{
				throw TestException(std::string("AeadTest: Decrypted output is not equal! -AP3"));
			}
			if (!Cipher->Verify(enc1, dlen, Cipher->MaxTagSize()))
			{
				throw TestException(std::string("AeadTest: Tags do not match! -AP4"));
			}
		}
	}

	void AeadTest::Stress(IAeadMode* Cipher)
	{
		Key::Symmetric::SymmetricKeySize keySize = Cipher->LegalKeySizes()[0];
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
			size_t dlen = rng.NextUInt32(10000, 100);
			data.resize(dlen);
			rng.Generate(data);
			rng.Generate(nonce);
			rng.Generate(key);
			rng.Generate(assoc);
			Key::Symmetric::SymmetricKey kp(key, nonce);

			enc.resize(dlen + Cipher->MaxTagSize());
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, enc, 0, data.size());
			Cipher->Finalize(enc, dlen, Cipher->MaxTagSize());

			dec.resize(dlen);
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(enc, 0, dec, 0, enc.size() - Cipher->MaxTagSize());

			if (!Cipher->Verify(enc, dlen, Cipher->MaxTagSize()))
			{
				throw TestException(std::string("AeadTest: Tags do not match! -AS1"));
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
			//ocb
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
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
		HexConverter::Decode(key, 44, m_key);

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
			// ocb
			std::string("BBAA99887766554433221100"),
			std::string("BBAA99887766554433221101"),
			std::string("BBAA99887766554433221102"),
			std::string("BBAA99887766554433221103"),
			std::string("BBAA99887766554433221104"),
			std::string("BBAA99887766554433221105"),
			std::string("BBAA99887766554433221106"),
			std::string("BBAA99887766554433221107"),
			std::string("BBAA99887766554433221108"),
			std::string("BBAA99887766554433221109"),    
			std::string("BBAA9988776655443322110A"),
			std::string("BBAA9988776655443322110B"),
			std::string("BBAA9988776655443322110C"),
			std::string("BBAA9988776655443322110D"),
			std::string("BBAA9988776655443322110E"),
			std::string("BBAA9988776655443322110F"),
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
		HexConverter::Decode(nonce, 44, m_nonce);

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
			// ocb
			std::string(""),
			std::string("0001020304050607"),
			std::string("0001020304050607"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F1011121314151617"),
			std::string("000102030405060708090A0B0C0D0E0F1011121314151617"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			std::string(""),
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
		HexConverter::Decode(associated, 44, m_associatedText);

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
			// ocb
			std::string(""),
			std::string("0001020304050607"),
			std::string(""),
			std::string("0001020304050607"),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F1011121314151617"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F1011121314151617"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			std::string(""),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
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
		HexConverter::Decode(plain, 44, m_plainText);

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
			// ocb
			std::string("785407BFFFC8AD9EDCC5520AC9111EE6"),
			std::string("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"),
			std::string("81017F8203F081277152FADE694A0A00"),
			std::string("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"),
			std::string("571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"),
			std::string("8CF761B6902EF764462AD86498CA6B97"),
			std::string("5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"),
			std::string("1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F"),
			std::string("6DC225A071FC1B9F7C69F93B0F1E10DE"),
			std::string("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF"),
			std::string("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240"),
			std::string("FE80690BEE8A485D11F32965BC9D2A32"),
			std::string("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF"),
			std::string("D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60"),
			std::string("C5CD9D1850C141E358649994EE701B68"),
			std::string("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479"),
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
		HexConverter::Decode(cipher, 44, m_cipherText);

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
			// ocb
			std::string("785407BFFFC8AD9EDCC5520AC9111EE6"),
			std::string("5725BDA0D3B4EB3A257C9AF1F8F03009"),
			std::string("81017F8203F081277152FADE694A0A00"),
			std::string("14054CD1F35D82760B2CD00D2F99BFA9"),
			std::string("3AD7A4FF3835B8C5701C1CCEC8FC3358"),
			std::string("8CF761B6902EF764462AD86498CA6B97"),
			std::string("F40E1C743F52436BDF06D8FA1ECA343D"),
			std::string("C92C62241051F57356D7F3C90BB0E07F"),
			std::string("6DC225A071FC1B9F7C69F93B0F1E10DE"),
			std::string("E725F32494B9F914D85C0B1EB38357FF"),
			std::string("40FBBA186C5553C68AD9F592A79A4240"),
			std::string("FE80690BEE8A485D11F32965BC9D2A32"),
			std::string("B5E1DDE3BC18A5F840B52E653444D5DF"),
			std::string("ED07BA06A4A69483A7035490C5769E60"),
			std::string("C5CD9D1850C141E358649994EE701B68"),
			std::string("479AD363AC366B95A98CA5F3000B1479"),
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
		HexConverter::Decode(code, 44, m_expectedCode);
		/*lint -restore */
	}

	void AeadTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
