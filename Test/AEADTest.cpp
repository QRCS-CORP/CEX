#include "AEADTest.h"
#include "../CEX/EAX.h"
#include "../CEX/GCM.h"
#include "../CEX/GMAC.h"
#include "../CEX/OCB.h"
#include "../CEX/RHX.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Cipher::Symmetric::Block::Mode::EAX;
	using Cipher::Symmetric::Block::Mode::GCM;
	using Cipher::Symmetric::Block::Mode::OCB;
	using Cipher::Symmetric::Block::RHX;
	using Cipher::Symmetric::Block::IBlockCipher;

	const std::string AEADTest::DESCRIPTION = "Authenticate Encrypt and Associated Data (AEAD) Cipher Mode Tests.";
	const std::string AEADTest::FAILURE = "FAILURE! ";
	const std::string AEADTest::SUCCESS = "SUCCESS! AEAD tests have executed succesfully.";

	AEADTest::AEADTest()
		:
		m_associatedText(0),
		m_cipherText(0),
		m_expectedCode(0),
		m_key(0),
		m_nonce(0),
		m_plainText(0),
		m_progressEvent()
	{
	}

	AEADTest::~AEADTest()
	{
	}

	std::string AEADTest::Run()
	{
		try
		{
			Initialize();

			EAX* cipher1 = new EAX(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = 0; i < EAX_TESTSIZE; ++i)
			{
				CompareVector(cipher1, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			OnProgress(std::string("AEADTest: Passed EAX known answer comparison tests.."));

			StressTest(cipher1);
			OnProgress(std::string("AEADTest: Passed EAX stress tests.."));

			ParallelTest(cipher1);
			OnProgress(std::string("AEADTest: Passed EAX parallel tests.."));

			IncrementalCheck(cipher1);
			OnProgress(std::string("AEADTest: Passed EAX auto incrementing tests.."));

			delete cipher1;

			OCB* cipher2 = new OCB(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = EAX_TESTSIZE; i < EAX_TESTSIZE + OCB_TESTSIZE; ++i)
			{
				CompareVector(cipher2, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			OnProgress(std::string("AEADTest: Passed OCB known answer comparison tests.."));

			StressTest(cipher2);
			OnProgress(std::string("AEADTest: Passed OCB stress tests.."));

			ParallelTest(cipher2);
			OnProgress(std::string("AEADTest: Passed OCB parallel tests.."));

			IncrementalCheck(cipher2);
			OnProgress(std::string("AEADTest: Passed OCB auto incrementing tests.."));

			delete cipher2;

			GCM* cipher3 = new GCM(Enumeration::BlockCiphers::Rijndael);

			for (size_t i = EAX_TESTSIZE + OCB_TESTSIZE; i < EAX_TESTSIZE + OCB_TESTSIZE + GCM_TESTSIZE; ++i)
			{
				CompareVector(cipher3, m_key[i], m_nonce[i], m_associatedText[i], m_plainText[i], m_cipherText[i], m_expectedCode[i]);
			}
			StressTest(cipher3);
			OnProgress(std::string("AEADTest: Passed GCM stress tests.."));

			ParallelTest(cipher3);
			OnProgress(std::string("AEADTest: Passed GCM parallel tests.."));

			IncrementalCheck(cipher3);
			OnProgress(std::string("AEADTest: Passed GCM auto incrementing tests.."));

			delete cipher3;

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

	void AEADTest::CompareVector(IAeadMode* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &AssociatedText, std::vector<byte> &PlainText,
		std::vector<byte> &CipherText, std::vector<byte> &MacCode)
	{
		Key::Symmetric::SymmetricKey kp(Key, Nonce);
		Cipher->Initialize(true, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}

		// test encryption
		std::vector<byte> encData(CipherText.size());
		Cipher->Transform(PlainText, 0, encData, 0, PlainText.size());
		Cipher->Finalize(encData, PlainText.size(), 16);

		if (CipherText != encData)
		{
			throw TestException("AEADTest: Encrypted output is not equal!");
		}

		// decryption
		Cipher->Initialize(false, kp);

		if (AssociatedText.size() != 0)
		{
			Cipher->SetAssociatedData(AssociatedText, 0, AssociatedText.size());
		}
		std::vector<byte> tmpData(CipherText.size());
		const size_t dataLen = (encData.size() >= 16) ? encData.size() - Cipher->BlockSize() : 0;
		Cipher->Transform(encData, 0, tmpData, 0, dataLen);

		std::vector<byte> macCode(16);
		Cipher->Finalize(macCode, 0, 16);

		// Finalizer can be skipped if Verify called
		if (!Cipher->Verify(encData, dataLen, 16))
		{
			throw TestException("AEADTest: Tags do not match!");
		}
		std::vector<byte> decData(dataLen);
		if (dataLen != 0)
		{
			std::memcpy(&decData[0], &tmpData[0], dataLen);
		}
		if (PlainText != decData)
		{
			throw TestException("AEADTest: Decrypted output is not equal!");
		}
		if (MacCode != macCode || MacCode != Cipher->Tag())
		{
			throw TestException("AEADTest: Tags do not match!");
		}
	}

	void AEADTest::IncrementalCheck(IAeadMode* Cipher)
	{
		size_t nLen = 12;
		if (Cipher->Enumeral() == Enumeration::CipherModes::EAX)
		{
			nLen = 16;
		}
		std::vector<byte> adData1(10, (byte)16);
		std::vector<byte> nonce(nLen, (byte)17);
		std::vector<byte> key(16, (byte)5);
		std::vector<byte> decData(64, (byte)7);
		std::vector<byte> encData1(80);

		// get base value
		Key::Symmetric::SymmetricKey kp1(key, nonce);
		Cipher->Initialize(true, kp1);
		// test persisted ad
		Cipher->PreserveAD() = true;
		Cipher->SetAssociatedData(adData1, 0, adData1.size());
		Cipher->Transform(decData, 0, encData1, 0, decData.size());
		Cipher->Finalize(encData1, decData.size(), 16);

		// 10* finalize on decremented nonce
		std::vector<byte> encData2(80);
		// decrement counter by 10
		nonce[nonce.size() - 1] -= 10;
		Key::Symmetric::SymmetricKey kp2(key, nonce);
		// set to auto increment, with nonce auto-incremented post finalize, last run should equal first output
		Cipher->AutoIncrement() = true;
		Cipher->Initialize(true, kp2);

		// run 10 loops, last iteration should be equivalent to test run
		for (size_t i = 0; i < 10; ++i)
		{
			Cipher->Transform(decData, 0, encData2, 0, decData.size());
			Cipher->Finalize(encData2, decData.size(), 16);
		}
		Cipher->AutoIncrement() = false;

		// this output should be different because of decremented nonce
		if (encData1 == encData2)
		{
			throw TestException("AEADTest: Output does not match!");
		}

		// get the code after incrementing nonce
		Cipher->Transform(decData, 0, encData2, 0, decData.size());
		Cipher->Finalize(encData2, decData.size(), 16);

		if (encData1 != encData2)
		{
			throw TestException("AEADTest: Output does not match!");
		}
	}

	void AEADTest::ParallelTest(IAeadMode* Cipher)
	{
		std::vector<byte> data;
		std::vector<byte> decData1;
		std::vector<byte> decData2;
		std::vector<byte> encData1;
		std::vector<byte> encData2;
		std::vector<byte> key(32);
		std::vector<Key::Symmetric::SymmetricKeySize> keySizes = Cipher->LegalKeySizes();
		std::vector<byte> nonce(keySizes[0].NonceSize());
		std::vector<byte> assoc(16);
		Prng::SecureRandom rng;

		for (size_t i = 0; i < 100; ++i)
		{
			uint32_t dataLen = rng.NextUInt32(static_cast<uint32_t>(Cipher->ParallelProfile().ParallelMinimumSize() * 10), static_cast<uint32_t>(Cipher->ParallelProfile().ParallelMinimumSize() * 2));
			// important! if manually sizing parallel block, make it evenly divisible by parallel minimum size
			Cipher->ParallelProfile().ParallelBlockSize() = dataLen - (dataLen % Cipher->ParallelProfile().ParallelMinimumSize());

			data.resize(dataLen);
			rng.GetBytes(data);
			rng.GetBytes(nonce);
			rng.GetBytes(key);
			rng.GetBytes(assoc);
			Key::Symmetric::SymmetricKey kp(key, nonce);

			// parallel encryption mode
			encData1.resize(dataLen + Cipher->MaxTagSize());
			// note: changes to parallel processing must be made before Initialize()
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, encData1, 0, data.size());
			Cipher->Finalize(encData1, dataLen, Cipher->MaxTagSize());

			// sequential mode
			encData2.resize(dataLen + Cipher->MaxTagSize());
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, encData2, 0, data.size());
			Cipher->Finalize(encData2, dataLen, Cipher->MaxTagSize());

			if (encData1 != encData2)
			{
				throw TestException("AEADTest: Encrypted output is not equal!");
			}

			// parallel decryption mode
			decData1.resize(dataLen);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(encData1, 0, decData1, 0, encData1.size() - Cipher->MaxTagSize());
			Cipher->Finalize(encData1, dataLen, Cipher->MaxTagSize());

			// sequential decryption mode
			decData2.resize(dataLen);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(encData2, 0, decData2, 0, encData2.size() - Cipher->MaxTagSize());
			Cipher->Finalize(encData2, dataLen, Cipher->MaxTagSize());

			if (decData1 != decData2)
			{
				throw TestException("AEADTest: Decrypted output is not equal!");
			}
			if (decData1 != data)
			{
				throw TestException("AEADTest: Decrypted output is not equal!");
			}
			if (!Cipher->Verify(encData1, dataLen, Cipher->MaxTagSize()))
			{
				throw TestException("AEADTest: Tags do not match!");
			}
		}
	}

	void AEADTest::StressTest(IAeadMode* Cipher)
	{
		Key::Symmetric::SymmetricKeySize keySize = Cipher->LegalKeySizes()[0];
		std::vector<byte> data;
		std::vector<byte> decData;
		std::vector<byte> encData;
		std::vector<byte> key(32);
		std::vector<byte> nonce(keySize.NonceSize());
		std::vector<byte> assoc(16);

		Prng::SecureRandom rng;
		data.reserve(MAX_ALLOC);
		decData.reserve(MAX_ALLOC);
		encData.reserve(MAX_ALLOC);
		//815
		for (size_t i = 0; i < 100; ++i)
		{
			size_t dataLen = rng.NextUInt32(1000, 100);
			data.resize(dataLen);
			rng.GetBytes(data);
			rng.GetBytes(nonce);
			rng.GetBytes(key);
			rng.GetBytes(assoc);
			Key::Symmetric::SymmetricKey kp(key, nonce);

			encData.resize(dataLen + Cipher->MaxTagSize());
			Cipher->Initialize(true, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(data, 0, encData, 0, data.size());
			Cipher->Finalize(encData, dataLen, Cipher->MaxTagSize());

			decData.resize(dataLen);
			Cipher->Initialize(false, kp);
			Cipher->SetAssociatedData(assoc, 0, assoc.size());
			Cipher->Transform(encData, 0, decData, 0, encData.size() - Cipher->MaxTagSize());

			if (!Cipher->Verify(encData, dataLen, Cipher->MaxTagSize()))
			{
				throw TestException("AEADTest: Tags do not match!!");
			}
		}
	}

	void AEADTest::Initialize()
	{
		const char* keyEncoded[44] =
		{
			// eax
			("233952DEE4D5ED5F9B9C6D6FF80FF478"),
			("91945D3F4DCBEE0BF45EF52255F095A4"),
			("01F74AD64077F2E704C0F60ADA3DD523"),
			("D07CF6CBB7F313BDDE66B727AFD3C5E8"),
			("35B6D0580005BBC12B0587124557D2C2"),
			("BD8E6E11475E60B268784C38C62FEB22"),
			("7C77D6E813BED5AC98BAA417477A2E7D"),
			("5FFF20CAFAB119CA2FC73549E20F5B0D"),
			("A4A4782BCFFD3EC5E7EF6D8C34A56123"),
			("8395FCF1E95BEBD697BD010BC766AAC3"),
			//ocb
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			// gcm
			("00000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308"),
			("000000000000000000000000000000000000000000000000"),
			("000000000000000000000000000000000000000000000000"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
			("0000000000000000000000000000000000000000000000000000000000000000"),
			("0000000000000000000000000000000000000000000000000000000000000000"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
			("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
		};
		HexConverter::Decode(keyEncoded, 44, m_key);

		const char* nonceEncoded[44] =
		{
			// eax
			("62EC67F9C3A4A407FCB2A8C49031A8B3"),
			("BECAF043B0A23D843194BA972C66DEBD"),
			("70C3DB4F0D26368400A10ED05D2BFF5E"),
			("8408DFFF3C1A2B1292DC199E46B7D617"),
			("FDB6B06676EEDC5C61D74276E1F8E816"),
			("6EAC5C93072D8E8513F750935E46DA1B"),
			("1A8C98DCD73D38393B2BF1569DEEFC19"),
			("DDE59B97D722156D4D9AFF2BC7559826"),
			("B781FCF2F75FA5A8DE97A9CA48E522EC"),
			("22E7ADD93CFC6393C57EC0B3C17D6B44"),
			// ocb
			("BBAA99887766554433221100"),
			("BBAA99887766554433221101"),
			("BBAA99887766554433221102"),
			("BBAA99887766554433221103"),
			("BBAA99887766554433221104"),
			("BBAA99887766554433221105"),
			("BBAA99887766554433221106"),
			("BBAA99887766554433221107"),
			("BBAA99887766554433221108"),
			("BBAA99887766554433221109"),    
			("BBAA9988776655443322110A"),
			("BBAA9988776655443322110B"),
			("BBAA9988776655443322110C"),
			("BBAA9988776655443322110D"),
			("BBAA9988776655443322110E"),
			("BBAA9988776655443322110F"),
			// gcm
			("000000000000000000000000"),
			("000000000000000000000000"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbad"),
			("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"),
			("000000000000000000000000"),
			("000000000000000000000000"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbad"),
			("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"),
			("000000000000000000000000"),
			("000000000000000000000000"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbaddecaf888"),
			("cafebabefacedbad"),
			("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b")
		};
		HexConverter::Decode(nonceEncoded, 44, m_nonce);

		const char* assocEncoded[44] =
		{
			// eax
			("6BFB914FD07EAE6B"),
			("FA3BFD4806EB53FA"),
			("234A3463C1264AC6"),
			("33CCE2EABFF5A79D"),
			("AEB96EAEBE2970E9"),
			("D4482D1CA78DCE0F"),
			("65D2017990D62528"),
			("54B9F04E6A09189A"),
			("899A175897561D7E"),
			("126735FCC320D25A"),
			// ocb
			(""),
			("0001020304050607"),
			("0001020304050607"),
			(""),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F"),
			(""),
			("000102030405060708090A0B0C0D0E0F1011121314151617"),
			("000102030405060708090A0B0C0D0E0F1011121314151617"),
			(""),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			(""),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			(""),
			// gcm
			(""),
			(""),
			(""),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			(""),
			(""),
			(""),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			(""),
			(""),
			(""),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
			("feedfacedeadbeeffeedfacedeadbeefabaddad2")
		};
		HexConverter::Decode(assocEncoded, 44, m_associatedText);

		const char* plainEncoded[44] =
		{
			// eax
			(""),
			("F7FB"),
			("1A47CB4933"),
			("481C9E39B1"),
			("40D0C07DA5E4"),
			("4DE3B35C3FC039245BD1FB7D"),
			("8B0A79306C9CE7ED99DAE4F87F8DD61636"),
			("1BDA122BCE8A8DBAF1877D962B8592DD2D56"),
			("6CF36720872B8513F6EAB1A8A44438D5EF11"),
			("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7"),
			// ocb
			(""),
			("0001020304050607"),
			(""),
			("0001020304050607"),
			("000102030405060708090A0B0C0D0E0F"),
			(""),
			("000102030405060708090A0B0C0D0E0F"),
			("000102030405060708090A0B0C0D0E0F1011121314151617"),
			(""),
			("000102030405060708090A0B0C0D0E0F1011121314151617"),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			(""),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			(""),
			("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"),
			// gcm
			(""),
			("00000000000000000000000000000000"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			(""),
			("00000000000000000000000000000000"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			(""),
			("00000000000000000000000000000000"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
			("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
		};
		HexConverter::Decode(plainEncoded, 44, m_plainText);

		const char* cipherEncoded[44] =
		{
			// eax
			("E037830E8389F27B025A2D6527E79D01"),
			("19DD5C4C9331049D0BDAB0277408F67967E5"),
			("D851D5BAE03A59F238A23E39199DC9266626C40F80"),
			("632A9D131AD4C168A4225D8E1FF755939974A7BEDE"),
			("071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"),
			("835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"),
			("02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"),
			("2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"),
			("0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"),
			("CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"),
			// ocb
			("785407BFFFC8AD9EDCC5520AC9111EE6"),
			("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009"),
			("81017F8203F081277152FADE694A0A00"),
			("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9"),
			("571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"),
			("8CF761B6902EF764462AD86498CA6B97"),
			("5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"),
			("1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F"),
			("6DC225A071FC1B9F7C69F93B0F1E10DE"),
			("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF"),
			("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240"),
			("FE80690BEE8A485D11F32965BC9D2A32"),
			("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF"),
			("D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60"),
			("C5CD9D1850C141E358649994EE701B68"),
			("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479"),
			// gcm
			("58e2fccefa7e3061367f1d57a4e7455a"),
			("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
			("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"),
			("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"),
			("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f45983612d2e79e3b0785561be14aaca2fccb"),
			("8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5619cc5aefffe0bfa462af43c1699d050"),
			("cd33b28ac773f74ba00ed1f312572435"),
			("98e7247c07f0fe411c267e4384b0f6002ff58d80033927ab8ef4d4587514f0fb"),
			("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade2569924a7c8587336bfb118024db8674a14"),
			("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda27102519498e80f1478f37ba55bd6d27618c"),
			("0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f765dcc57fcf623a24094fcca40d3533f8"),
			("d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373bdcf566ff291c25bbb8568fc3d376a6d9"),
			("530f8afbc74536b9a963b4f1c4cb738b"),
			("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
			("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"),
			("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"),
			("c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f3a337dbf46a792c45e454913fe2ea8f2"),
			("5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3fa44a8266ee1c8eb0c8b5d4cf5ae9f19a")
		};
		HexConverter::Decode(cipherEncoded, 44, m_cipherText);

		const char* codeEncoded[44] =
		{
			// eax
			("E037830E8389F27B025A2D6527E79D01"),
			("5C4C9331049D0BDAB0277408F67967E5"),
			("3A59F238A23E39199DC9266626C40F80"),
			("D4C168A4225D8E1FF755939974A7BEDE"),
			("CB0677E536F73AFE6A14B74EE49844DD"),
			("ABB8644FD6CCB86947C5E10590210A4F"),
			("137327D10649B0AA6E1C181DB617D7F2"),
			("3B60450599BD02C96382902AEF7F832A"),
			("E7F6D2231618102FDB7FE55FF1991700"),
			("CFC46AFC253B4652B1AF3795B124AB6E"),
			// ocb
			("785407BFFFC8AD9EDCC5520AC9111EE6"),
			("5725BDA0D3B4EB3A257C9AF1F8F03009"),
			("81017F8203F081277152FADE694A0A00"),
			("14054CD1F35D82760B2CD00D2F99BFA9"),
			("3AD7A4FF3835B8C5701C1CCEC8FC3358"),
			("8CF761B6902EF764462AD86498CA6B97"),
			("F40E1C743F52436BDF06D8FA1ECA343D"),
			("C92C62241051F57356D7F3C90BB0E07F"),
			("6DC225A071FC1B9F7C69F93B0F1E10DE"),
			("E725F32494B9F914D85C0B1EB38357FF"),
			("40FBBA186C5553C68AD9F592A79A4240"),
			("FE80690BEE8A485D11F32965BC9D2A32"),
			("B5E1DDE3BC18A5F840B52E653444D5DF"),
			("ED07BA06A4A69483A7035490C5769E60"),
			("C5CD9D1850C141E358649994EE701B68"),
			("479AD363AC366B95A98CA5F3000B1479"),
			// gcm
			("58e2fccefa7e3061367f1d57a4e7455a"),
			("ab6e47d42cec13bdf53a67b21257bddf"),
			("4d5c2af327cd64a62cf35abd2ba6fab4"),
			("5bc94fbc3221a5db94fae95ae7121a47"),
			("3612d2e79e3b0785561be14aaca2fccb"),
			("619cc5aefffe0bfa462af43c1699d050"),
			("cd33b28ac773f74ba00ed1f312572435"),
			("2ff58d80033927ab8ef4d4587514f0fb"),
			("9924a7c8587336bfb118024db8674a14"),
			("2519498e80f1478f37ba55bd6d27618c"),
			("65dcc57fcf623a24094fcca40d3533f8"),
			("dcf566ff291c25bbb8568fc3d376a6d9"),
			("530f8afbc74536b9a963b4f1c4cb738b"),
			("d0d1c8a799996bf0265b98b5d48ab919"),
			("b094dac5d93471bdec1a502270e3cc6c"),
			("76fc6ece0f4e1768cddf8853bb2d551b"),
			("3a337dbf46a792c45e454913fe2ea8f2"),
			("a44a8266ee1c8eb0c8b5d4cf5ae9f19a")
		};
		HexConverter::Decode(codeEncoded, 44, m_expectedCode);
	}

	void AEADTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}