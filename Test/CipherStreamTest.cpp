#include "CipherStreamTest.h"
#include "../CEX/CipherStream.h"
#include "../CEX/FileStream.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/CSPPrng.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/OFB.h"
#include "../CEX/X923.h"
#include "../CEX/PKCS7.h"
#include "../CEX/TBC.h"
#include "../CEX/ISO7816.h"
#include "../CEX/ParallelUtils.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/THX.h"
#include "../CEX/ChaCha.h"
#include "../CEX/Salsa20.h"

namespace Test
{
	std::string CipherStreamTest::Run()
	{
		using namespace CEX::Cipher::Symmetric::Block::Mode;
		using namespace CEX::Cipher::Symmetric::Block::Padding;
		using namespace CEX::Enumeration;

		try
		{
			Initialize();

			CbcModeTest();
			OnProgress("Passed CBC Mode tests..");
			CfbModeTest();
			OnProgress("Passed CFB Mode tests..");
			CtrModeTest();
			OnProgress("Passed CTR Mode tests..");
			OfbModeTest();
			OnProgress("Passed OFB Mode tests..");
			StreamTest();
			OnProgress("Passed Stream Cipher tests");

			MemoryStreamTest();
			OnProgress("Passed MemoryStream self test.. ");
			OnProgress("");

			SerializeStructTest();
			OnProgress("Passed CipherDescription serialization test..");
			OnProgress("");

			OnProgress("***Testing Cipher Parameters***.. ");
			ParametersTest();
			OnProgress("Passed Cipher Parameters tests..");

			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			OnProgress("***Testing Padding Modes***..");
			StreamModesTest(new CBC(eng), new X923());
			OnProgress("Passed CBC/X923 CipherStream test..");
			StreamModesTest(new CBC(eng), new PKCS7());
			OnProgress("Passed CBC/PKCS7 CipherStream test..");
			StreamModesTest(new CBC(eng), new TBC());
			OnProgress("Passed CBC/TBC CipherStream test..");
			StreamModesTest(new CBC(eng), new ISO7816());
			OnProgress("Passed CBC/ISO7816 CipherStream test..");
			OnProgress("");

			OnProgress("***Testing Cipher Modes***..");
			StreamModesTest(new CTR(eng), new ISO7816());
			OnProgress("Passed CTR CipherStream test..");
			StreamModesTest(new CFB(eng), new ISO7816());
			OnProgress("Passed CFB CipherStream test..");
			StreamModesTest(new OFB(eng), new ISO7816());
			OnProgress("Passed OFB CipherStream test..");
			OnProgress("");
			delete eng;

			OnProgress("***Testing Stream Ciphers***..");
			StreamingTest(new CEX::Cipher::Symmetric::Stream::ChaCha());
			OnProgress("Passed ChaCha CipherStream test..");
			StreamingTest(new CEX::Cipher::Symmetric::Stream::Salsa20());
			OnProgress("Passed Salsa20 CipherStream test..");
			OnProgress("");

			OnProgress("***Testing Cipher Description Initialization***..");
			CEX::Common::CipherDescription cd(
				SymmetricEngines::RHX,		// cipher engine
				32,							// key size in bytes
				IVSizes::V128,				// cipher iv size
				CipherModes::CTR,			// cipher mode
				PaddingModes::ISO7816,		// cipher padding
				BlockSizes::B128,			// cipher block size
				RoundCounts::R14,			// number of transformation rounds
				Digests::None,				// optional key schedule engine (HX ciphers)
				0,							// optional HMAC size
				Digests::None);				// optional HMAC engine

			DescriptionTest(&cd);
			OnProgress("Passed CipherDescription stream test..");
			OnProgress("");

			OnProgress("***Testing Block Ciphers***.. ");
			CEX::Cipher::Symmetric::Block::THX* tfx = new CEX::Cipher::Symmetric::Block::THX();
			StreamModesTest(new CBC(tfx), new ISO7816());
			delete tfx;
			OnProgress("Passed THX CipherStream test..");
			CEX::Cipher::Symmetric::Block::SHX* spx = new CEX::Cipher::Symmetric::Block::SHX();
			StreamModesTest(new CBC(spx), new ISO7816());
			delete spx;
			OnProgress("Passed SHX CipherStream test..");

			m_key.resize(192);
			for (unsigned int i = 0; i < 192; i++)
				m_key[i] = (byte)i;

			// test extended ciphers
			CEX::Cipher::Symmetric::Block::RHX* rhx = new CEX::Cipher::Symmetric::Block::RHX();
			StreamModesTest(new CBC(rhx), new ISO7816());
			delete rhx;
			OnProgress("Passed RHX CipherStream test..");
			CEX::Cipher::Symmetric::Block::SHX* shx = new CEX::Cipher::Symmetric::Block::SHX();
			StreamModesTest(new CBC(shx), new ISO7816());
			delete shx;
			OnProgress("Passed SHX CipherStream test..");
			CEX::Cipher::Symmetric::Block::THX* thx = new CEX::Cipher::Symmetric::Block::THX();
			StreamModesTest(new CBC(thx), new ISO7816());
			delete thx;
			OnProgress("Passed THX CipherStream test..");
			OnProgress("");

			return SUCCESS;
		}
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	// *** Tests *** //
	void CipherStreamTest::CbcModeTest()
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::CBC cipher(eng);
		CEX::Cipher::Symmetric::Block::Mode::CBC cipher2(eng);
		CEX::Cipher::Symmetric::Block::Padding::ISO7816* padding = new CEX::Cipher::Symmetric::Block::Padding::ISO7816();
		cipher.IsParallel() = false;
		CEX::Processing::CipherStream cs(&cipher2, padding);

		for (unsigned int i = 0; i < 10; i++)
		{
			size_t sze = AllocateRandom(m_plnText, 0, cipher.BlockSize());
			size_t prlBlock = sze - (sze % (cipher.BlockSize() * m_processorCount));
			m_cmpText.resize(sze);
			m_decText.resize(sze);
			m_encText.resize(sze);

			cipher.ParallelBlockSize() = prlBlock;
			cipher2.ParallelBlockSize() = prlBlock;
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			CEX::IO::MemoryStream mRes;

			// *** Compare encryption output *** //

			// local processor
			cipher.Initialize(true, kp);
			BlockEncrypt(&cipher, padding, m_plnText, 0, m_encText, 0);

			// streamcipher linear mode
			cs.IsParallel() = false;
			// memorystream interface
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// ***compare decryption output *** //

			// local processor
			cipher.Initialize(false, kp);
			BlockDecrypt(&cipher, padding, m_encText, 0, m_decText, 0);

			if (m_plnText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt linear mode
			cs.IsParallel() = false;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt parallel mode
			cs.IsParallel() = true;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			mRes.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			m_cmpText.resize(m_encText.size());
			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
		}

		delete eng;
		delete padding;
	}

	void CipherStreamTest::CfbModeTest()
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::CFB cipher(eng);
		CEX::Cipher::Symmetric::Block::Mode::CFB cipher2(eng);
		CEX::Cipher::Symmetric::Block::Padding::ISO7816* padding = new CEX::Cipher::Symmetric::Block::Padding::ISO7816();
		cipher.IsParallel() = false;
		CEX::Processing::CipherStream cs(&cipher2, padding);

		for (unsigned int i = 0; i < 10; i++)
		{
			size_t sze = AllocateRandom(m_plnText, 0, cipher.BlockSize());
			size_t prlBlock = sze - (sze % (cipher.BlockSize() * m_processorCount));
			m_cmpText.resize(sze);
			m_decText.resize(sze);
			m_encText.resize(sze);

			cipher.ParallelBlockSize() = prlBlock;
			cipher2.ParallelBlockSize() = prlBlock;
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			CEX::IO::MemoryStream mRes;

			// *** Compare encryption output *** //

			// local processor
			cipher.Initialize(true, kp);
			BlockEncrypt(&cipher, padding, m_plnText, 0, m_encText, 0);

			// streamcipher linear mode
			cs.IsParallel() = false;
			// memorystream interface
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// ***compare decryption output *** //

			// local processor
			cipher.Initialize(false, kp);
			BlockDecrypt(&cipher, padding, m_encText, 0, m_decText, 0);

			if (m_plnText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt linear mode
			cs.IsParallel() = false;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt parallel mode
			cs.IsParallel() = true;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			mRes.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			m_cmpText.resize(m_encText.size());
			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
		}

		delete eng;
		delete padding;
	}

	void CipherStreamTest::CtrModeTest()
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
		CEX::Cipher::Symmetric::Block::Mode::CTR cipher2(eng);
		CEX::Processing::CipherStream cs(&cipher2);
		cipher.IsParallel() = false;

		// ctr test
		for (unsigned int i = 0; i < 10; i++)
		{
			size_t sze = AllocateRandom(m_plnText);
			size_t prlBlock = sze - (sze % (cipher.BlockSize() * m_processorCount));
			m_encText.resize(sze);
			m_cmpText.resize(sze);
			m_decText.resize(sze);

			cipher.ParallelBlockSize() = prlBlock;
			cipher2.ParallelBlockSize() = prlBlock;
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			CEX::IO::MemoryStream mRes;

			// *** Compare encryption output *** //

			// local processor
			cipher.Initialize(true, kp);
			BlockCTR(&cipher, m_plnText, 0, m_encText, 0);

			// streamcipher linear mode
			cs.IsParallel() = false;
			// memorystream interface
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			mIn.Seek(0, CEX::IO::SeekOrigin::Begin);
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);

			cs.IsParallel() = true;
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// ***compare decryption output *** //

			// local processor
			cipher.Initialize(false, kp);
			BlockCTR(&cipher, m_encText, 0, m_decText, 0);

			if (m_plnText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt linear mode
			cs.IsParallel() = false;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt parallel mode
			cs.IsParallel() = true;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			mRes.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
		}

		delete eng;
	}

	void CipherStreamTest::DescriptionTest(CEX::Common::CipherDescription* Description)
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);
		AllocateRandom(m_plnText);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::IO::MemoryStream mIn(m_plnText);
		CEX::IO::MemoryStream mOut;
		CEX::IO::MemoryStream mRes;

		CEX::Processing::CipherStream cs(Description);
		cs.Initialize(true, kp);
		cs.Write(&mIn, &mOut);

		mOut.Seek(0, CEX::IO::SeekOrigin::Begin);

		cs.Initialize(false, kp);
		cs.Write(&mOut, &mRes);

		if (mRes.ToArray() != m_plnText)
			throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
	}

	void CipherStreamTest::Initialize()
	{
		m_encText.reserve(MAX_ALLOC);
		m_cmpText.reserve(MAX_ALLOC);
		m_decText.reserve(MAX_ALLOC);
		m_plnText.reserve(MAX_ALLOC);
		m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	}

	void CipherStreamTest::MemoryStreamTest()
	{
		CEX::IO::MemoryStream ms;
		ms.WriteByte((byte)10);
		ms.WriteByte((byte)11);
		ms.WriteByte((byte)12);

		std::vector<byte> data(255);
		for (unsigned int i = 0; i < 255; i++)
			data[i] = (byte)i;
		ms.Write(data, 0, 255);

		ms.Seek(0, CEX::IO::SeekOrigin::Begin);

		byte x = ms.ReadByte();
		if (x != (byte)10)
			throw;
		x = ms.ReadByte();
		if (x != (byte)11)
			throw;
		x = ms.ReadByte();
		if (x != (byte)12)
			throw;

		std::vector<byte> data2(255);
		ms.Read(data2, 0, 255);
		if (data2 != data)
			throw;
	}

	void CipherStreamTest::ParametersTest()
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);
		AllocateRandom(m_plnText, 1);

		CEX::Common::KeyParams kp(m_key, m_iv);
		m_cmpText.resize(1);
		m_decText.resize(1);
		m_encText.resize(1);

		CEX::Cipher::Symmetric::Block::RHX* engine = new CEX::Cipher::Symmetric::Block::RHX();

		// 1 byte w/ byte arrays
		{
			CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
			CEX::Processing::CipherStream cs(cipher);

			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_encText, 0);

			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_decText, 0);

			if (m_decText != m_plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			delete cipher;
		}
		// 1 byte w/ stream
		{
			CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
			CEX::Processing::CipherStream cs(cipher);
			cs.Initialize(true, kp);
			AllocateRandom(m_plnText, 1);
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			cs.Write(&mIn, &mOut);

			cs.Initialize(false, kp);
			CEX::IO::MemoryStream mRes;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			delete cipher;
		}

		// partial block w/ byte arrays
		{
			CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
			CEX::Processing::CipherStream cs(cipher);
			AllocateRandom(m_plnText, 15);
			m_decText.resize(15);
			m_encText.resize(15);

			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_encText, 0);

			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_decText, 0);

			if (m_decText != m_plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			delete cipher;
		}
		// partial block w/ stream
		{
			CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
			CEX::Processing::CipherStream cs(cipher);
			AllocateRandom(m_plnText, 15);
			m_decText.resize(15);
			m_encText.resize(15);

			cs.Initialize(true, kp);
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			cs.Write(&mIn, &mOut);

			cs.Initialize(false, kp);
			CEX::IO::MemoryStream mRes;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			delete cipher;
		}

		// random block sizes w/ byte arrays
		{
			for (unsigned int i = 0; i < 100; i++)
			{
				CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);

				size_t sze = AllocateRandom(m_plnText);
				m_decText.resize(sze);
				m_encText.resize(sze);

				CEX::Processing::CipherStream cs(cipher);
				cs.Initialize(true, kp);
				cs.Write(m_plnText, 0, m_encText, 0);

				cs.Initialize(false, kp);
				cs.Write(m_encText, 0, m_decText, 0);

				if (m_decText != m_plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}
		}
		// random block sizes w/ stream
		{
			for (unsigned int i = 0; i < 100; i++)
			{
				CEX::Cipher::Symmetric::Block::Mode::CTR* cipher = new CEX::Cipher::Symmetric::Block::Mode::CTR(engine);
				size_t sze = AllocateRandom(m_plnText);
				m_decText.resize(sze);
				m_encText.resize(sze);

				CEX::Processing::CipherStream cs(cipher);
				cs.Initialize(true, kp);
				CEX::IO::MemoryStream mIn(m_plnText);
				CEX::IO::MemoryStream mOut;
				cs.Write(&mIn, &mOut);

				cs.Initialize(false, kp);
				CEX::IO::MemoryStream mRes;
				mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != m_plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}
		}

		delete engine;
	}

	void CipherStreamTest::OfbModeTest()
	{
		AllocateRandom(m_iv, 16);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::Cipher::Symmetric::Block::RHX* engine = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::OFB cipher(engine);
		CEX::Cipher::Symmetric::Block::Mode::OFB cipher2(engine);
		CEX::Cipher::Symmetric::Block::Padding::ISO7816* padding = new CEX::Cipher::Symmetric::Block::Padding::ISO7816();
		cipher.IsParallel() = false;
		CEX::Processing::CipherStream cs(&cipher2, padding);

		for (size_t i = 0; i < 10; i++)
		{
			size_t sze = AllocateRandom(m_plnText, 0, cipher.BlockSize());
			size_t prlBlock = sze - (sze % (cipher.BlockSize() * m_processorCount));
			m_cmpText.resize(sze);
			m_decText.resize(sze);
			m_encText.resize(sze);

			cipher.ParallelBlockSize() = prlBlock;
			cipher2.ParallelBlockSize() = prlBlock;
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			CEX::IO::MemoryStream mRes;

			// *** Compare encryption output *** //

			// local processor
			cipher.Initialize(true, kp);
			BlockEncrypt(&cipher, padding, m_plnText, 0, m_encText, 0);

			// streamcipher linear mode
			cs.IsParallel() = false;
			// memorystream interface
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// ***compare decryption output *** //

			// local processor
			cipher.Initialize(false, kp);
			BlockDecrypt(&cipher, padding, m_encText, 0, m_decText, 0);

			if (m_plnText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt linear mode
			cipher2.IsParallel() = false;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			m_cmpText.resize(m_encText.size());
			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
		}

		delete engine;
		delete padding;
	}

	void CipherStreamTest::SerializeStructTest()
	{
		using namespace CEX::Enumeration;

		CEX::Common::CipherDescription cd(SymmetricEngines::RHX,
			192,
			IVSizes::V128,
			CipherModes::CTR,
			PaddingModes::PKCS7,
			BlockSizes::B128,
			RoundCounts::R22,
			Digests::Skein512,
			64,
			Digests::SHA512);

		CEX::Common::CipherDescription cy(*cd.ToStream());

		if (!cy.Equals(cd))
			throw;

		cy.KeySize() = 0;
		if (cy.Equals(cd))
			throw;
	}

	void CipherStreamTest::StreamTest()
	{
		AllocateRandom(m_iv, 8);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::Cipher::Symmetric::Stream::Salsa20* cipher = new CEX::Cipher::Symmetric::Stream::Salsa20();
		CEX::Cipher::Symmetric::Stream::Salsa20* cipher2 = new CEX::Cipher::Symmetric::Stream::Salsa20();
		CEX::Processing::CipherStream cs(cipher2);
		cipher->IsParallel() = false;

		// ctr test
		for (unsigned int i = 0; i < 10; i++)
		{
			size_t sze = AllocateRandom(m_plnText);
			size_t prlBlock = sze - (sze % (cipher->BlockSize() * m_processorCount));
			m_cmpText.resize(sze);
			m_decText.resize(sze);
			m_encText.resize(sze);

			cipher->ParallelBlockSize() = prlBlock;
			cs.ParallelBlockSize() = prlBlock;
			CEX::IO::MemoryStream mIn(m_plnText);
			CEX::IO::MemoryStream mOut;
			CEX::IO::MemoryStream mRes;

			// *** Compare encryption output *** //

			// local processor
			cipher->Initialize(kp);
			ProcessStream(cipher, m_plnText, 0, m_encText, 0);

			// streamcipher linear mode
			cs.IsParallel() = false;
			// memorystream interface
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(true, kp);
			cs.Write(m_plnText, 0, m_cmpText, 0);

			if (m_cmpText != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			mIn.Seek(0, CEX::IO::SeekOrigin::Begin);
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);

			// parallel test
			cs.IsParallel() = true;
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			if (mOut.ToArray() != m_encText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// byte array interface
			//cs.Initialize(true, kp);
			//cs.Write(m_plnText, 0, m_cmpText, 0);

			//if (m_cmpText != m_encText)
			//	throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

			// ***compare decryption output *** //

			// local processor
			cipher->Initialize(kp);
			ProcessStream(cipher, m_encText, 0, m_decText, 0);

			if (m_plnText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt linear mode
			cs.IsParallel() = false;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// decrypt parallel mode
			cs.IsParallel() = true;
			mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
			mRes.Seek(0, CEX::IO::SeekOrigin::Begin);
			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

			// byte array interface
			cs.Initialize(false, kp);
			cs.Write(m_encText, 0, m_cmpText, 0);

			if (m_cmpText != m_decText)
				throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
		}

		delete cipher;
		delete cipher2;
	}

	void CipherStreamTest::StreamModesTest(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding)
	{
		if (Cipher->LegalKeySizes()[0] > 32)
			AllocateRandom(m_key, 192);
		else
			AllocateRandom(m_key, 32);

		AllocateRandom(m_iv, 16);

		// we are testing padding modes, make sure input size is random, but -not- block aligned..
		AllocateRandom(m_plnText, 0, Cipher->BlockSize());

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::IO::MemoryStream mIn(m_plnText);
		CEX::IO::MemoryStream mOut;
		CEX::IO::MemoryStream mRes;

		CEX::Processing::CipherStream cs(Cipher, Padding);
		cs.Initialize(true, kp);
		cs.Write(&mIn, &mOut);

		cs.Initialize(false, kp);
		mOut.Seek(0, CEX::IO::SeekOrigin::Begin);
		cs.Write(&mOut, &mRes);

		delete Cipher;
		delete Padding;

		if (mRes.ToArray() != m_plnText)
			throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
	}

	void CipherStreamTest::StreamingTest(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher)
	{
		AllocateRandom(m_plnText);
		AllocateRandom(m_iv, 8);
		AllocateRandom(m_key, 32);

		CEX::Common::KeyParams kp(m_key, m_iv);
		CEX::IO::MemoryStream mIn(m_plnText);
		CEX::IO::MemoryStream mOut;
		CEX::IO::MemoryStream mRes;

		CEX::Processing::CipherStream cs(Cipher);
		cs.Initialize(true, kp);
		cs.Write(&mIn, &mOut);

		mOut.Seek(0, CEX::IO::SeekOrigin::Begin);

		cs.Initialize(false, kp);
		cs.Write(&mOut, &mRes);
		delete Cipher;

		if (mRes.ToArray() != m_plnText)
			throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
	}

	// *** Helpers *** //
	size_t CipherStreamTest::AllocateRandom(std::vector<byte> &Data, size_t Size, size_t NonAlign)
	{
		CEX::Prng::CSPPrng rng;

		if (Size != 0)
		{
			Data.resize(Size);
		}
		else
		{
			unsigned int sze = 0;
			if (NonAlign != 0)
			{
				while ((sze = rng.Next(MIN_ALLOC, MAX_ALLOC)) % NonAlign == 0);
			}
			else
			{
				sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			}
			Data.resize(sze);
		}

		rng.GetBytes(Data);
		return (int)Data.size();
	}

	void CipherStreamTest::BlockCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (size_t)(Input.size() - InOffset);
		const size_t alnSize = inpSize - (size_t)(inpSize % blkSize);
		size_t count = 0;

		Cipher->IsParallel() = false;

		while (count != alnSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}

		// partial
		if (alnSize != inpSize)
		{
			size_t cnkSize = inpSize - alnSize;
			std::vector<byte> inpBuffer(blkSize);
			memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
			std::vector<byte> outBuffer(blkSize);
			Cipher->Transform(inpBuffer, 0, outBuffer, 0);
			memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		}
	}

	void CipherStreamTest::BlockDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (unsigned int)(Input.size() - InOffset);
		const size_t alnSize = inpSize - blkSize;
		size_t count = 0;

		Cipher->IsParallel() = false;

		while (count != alnSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}

		// last block
		std::vector<byte> inpBuffer(blkSize);
		memcpy(&inpBuffer[0], &Input[InOffset], blkSize);
		std::vector<byte> outBuffer(blkSize);
		Cipher->Transform(inpBuffer, 0, outBuffer, 0);
		size_t fnlSize = blkSize - Padding->GetPaddingLength(outBuffer, 0);
		memcpy(&Output[OutOffset], &outBuffer[0], fnlSize);
		OutOffset += fnlSize;

		if (Output.size() != OutOffset)
			Output.resize(OutOffset);
	}

	void CipherStreamTest::BlockEncrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (unsigned int)(Input.size() - InOffset);
		const size_t alnSize = inpSize - (inpSize % blkSize);
		size_t count = 0;

		Cipher->IsParallel() = false;

		while (count != alnSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}

		// partial
		if (alnSize != inpSize)
		{
			size_t fnlSize = inpSize - alnSize;
			std::vector<byte> inpBuffer(blkSize);
			memcpy(&inpBuffer[0], &Input[InOffset], fnlSize);
			Padding->AddPadding(inpBuffer, fnlSize);
			std::vector<byte> outBuffer(blkSize);
			Cipher->Transform(inpBuffer, 0, outBuffer, 0);
			if (Output.size() != OutOffset + blkSize)
				Output.resize(OutOffset + blkSize);
			memcpy(&Output[OutOffset], &outBuffer[0], blkSize);
		}
	}

	void CipherStreamTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void CipherStreamTest::ProcessStream(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (unsigned int)(Input.size() - InOffset);
		const size_t alnSize = (unsigned int)(inpSize / blkSize) * blkSize;
		size_t count = 0;

		Cipher->IsParallel() = false;

		while (count != alnSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}

		// partial
		if (alnSize != inpSize)
		{
			size_t cnkSize = inpSize - alnSize;
			std::vector<byte> inpBuffer(cnkSize);
			memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
			std::vector<byte> outBuffer(cnkSize);
			Cipher->Transform(inpBuffer, outBuffer);
			memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		}
	}
}