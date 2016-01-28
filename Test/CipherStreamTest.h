#ifndef _CEXTEST_STREAMCIPHERTEST_H
#define _CEXTEST_STREAMCIPHERTEST_H

#include "ITest.h"
#include "KeyParams.h"
#include "CipherStream.h"
#include "FileStream.h"
#include "MemoryStream.h"
#include "CipherDescription.h"
#include "KeyParams.h"
#include "ParallelUtils.h"
#include "CSPPrng.h"

#include "ICipherMode.h"
#include "CTR.h"
#include "CBC.h"
#include "CFB.h"
#include "OFB.h"
#include "IStreamCipher.h"
#include "Salsa20.h"
#include "ChaCha.h"

#include "IPadding.h"
#include "X923.h"
#include "PKCS7.h"
#include "TBC.h"
#include "ISO7816.h"

#include "RHX.h"
#include "SHX.h"
#include "THX.h"
#include "ChaCha.h"
#include "Salsa20.h"

namespace Test
{
	using namespace CEX::Enumeration;
	using namespace CEX::IO;
	using namespace TestFiles::TestFiles;
	using namespace CEX::Cipher::Symmetric::Block;
	using namespace CEX::Cipher::Symmetric::Block::Mode;
	using namespace CEX::Cipher::Symmetric::Block::Padding;
	using namespace CEX::Cipher::Symmetric::Stream;
	using namespace CEX::Common;
	using namespace CEX::IO;

	using CEX::Prng::CSPPrng;
	using CEX::Processing::CipherStream;

	/// <summary>
	/// Tests the CipherStream Processer
	/// </summary>
	class CipherStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CipherStream Processer Tests.";
		const std::string FAILURE = "FAILURE: ";
		const std::string SUCCESS = "SUCCESS! CipherStream tests have executed succesfully.";
		const unsigned int MIN_ALLOC = 512;
		const unsigned int MAX_ALLOC = 4096;
		const unsigned int DEF_BLOCK = 64000;

		TestEventHandler _progressEvent;
		std::vector<byte> _cmpText;
		std::vector<byte> _decText;
		std::vector<byte> _encText;
		std::vector<byte> _iv;
		std::vector<byte> _key;
		std::vector<byte> _plnText;
		unsigned int _processorCount;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		CipherStreamTest()
			:
			_encText(0),
			_cmpText(0),
			_decText(0),
			_iv(16),
			_key(32),
			_plnText(0),
			_processorCount(1)
		{
			_encText.reserve(MAX_ALLOC);
			_cmpText.reserve(MAX_ALLOC);
			_decText.reserve(MAX_ALLOC);
			_plnText.reserve(MAX_ALLOC);
			_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
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

				RHX* eng = new RHX();
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
				StreamingTest(new ChaCha());
				OnProgress("Passed ChaCha CipherStream test..");
				StreamingTest(new Salsa20());
				OnProgress("Passed Salsa20 CipherStream test..");
				OnProgress("");

				OnProgress("***Testing Cipher Description Initialization***..");
				CipherDescription cd(
					SymmetricEngines::RHX,		// cipher engine
					32,							// key size in bytes
					IVSizes::V128,				// cipher iv size
					CipherModes::CTR,			// cipher mode
					PaddingModes::ISO7816,		// cipher padding
					BlockSizes::B128,			// cipher block size
					RoundCounts::R14,			// number of transformation rounds
					Digests::Keccak512,			// optional key schedule engine (HX ciphers)
					64,							// optional HMAC size
					Digests::Keccak512);		// optional HMAC engine

				DescriptionTest(&cd);
				OnProgress("Passed CipherDescription stream test..");
				OnProgress("");

				OnProgress("***Testing Block Ciphers***.. ");
				THX* tfx = new THX();
				StreamModesTest(new CBC(tfx), new ISO7816());
				delete tfx;
				OnProgress("Passed THX CipherStream test..");
				SHX* spx = new SHX();
				StreamModesTest(new CBC(spx), new ISO7816());
				delete spx;
				OnProgress("Passed SHX CipherStream test..");

				_key.resize(192);
				for (int i = 0; i < 192; i++)
					_key[i] = (byte)i;

				// test extended ciphers
				RHX* rhx = new RHX();
				StreamModesTest(new CBC(rhx), new ISO7816());
				delete rhx;
				OnProgress("Passed RHX CipherStream test..");
				SHX* shx = new SHX();
				StreamModesTest(new CBC(shx), new ISO7816());
				delete shx;
				OnProgress("Passed SHX CipherStream test..");
				THX* thx = new THX();
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

	private:
		// *** Tests *** //
		void CbcModeTest()
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			RHX* eng = new RHX();
			CBC cipher(eng);
			CBC cipher2(eng);
			ISO7816* padding = new ISO7816();
			cipher.IsParallel() = false;
			CipherStream cs(&cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
				unsigned int sze = AllocateRandom(_plnText, 0, cipher.BlockSize());
				unsigned int prlBlock = sze - (sze % (cipher.BlockSize() * _processorCount));
				_cmpText.resize(sze);
				_decText.resize(sze);
				_encText.resize(sze);

				cipher.ParallelBlockSize() = prlBlock;
				cipher2.ParallelBlockSize() = prlBlock;
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				MemoryStream mRes;
					
				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, padding, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel() = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
				BlockDecrypt(&cipher, padding, _encText, 0, _decText, 0);

				if (_plnText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel() = false;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel() = true;
				mOut.Seek(0, SeekOrigin::Begin);
				mRes.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				_cmpText.resize(_encText.size());
				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
			delete padding;
		}

		void CfbModeTest()
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			RHX* eng = new RHX();
			CFB cipher(eng);
			CFB cipher2(eng);
			ISO7816* padding = new ISO7816();
			cipher.IsParallel() = false;
			CipherStream cs(&cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
				unsigned int sze = AllocateRandom(_plnText, 0, cipher.BlockSize());
				unsigned int prlBlock = sze - (sze % (cipher.BlockSize() * _processorCount));
				_cmpText.resize(sze);
				_decText.resize(sze);
				_encText.resize(sze);

				cipher.ParallelBlockSize() = prlBlock;
				cipher2.ParallelBlockSize() = prlBlock;
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				MemoryStream mRes;

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, padding, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel() = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
				BlockDecrypt(&cipher, padding, _encText, 0, _decText, 0);

				if (_plnText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel() = false;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel() = true;
				mOut.Seek(0, SeekOrigin::Begin);
				mRes.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				_cmpText.resize(_encText.size());
				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
			delete padding;
		}

		void CtrModeTest()
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			RHX* eng = new RHX();
			CTR cipher(eng);
			CTR cipher2(eng);
			CipherStream cs(&cipher2);
			cipher.IsParallel() = false;

			// ctr test
			for (int i = 0; i < 10; i++)
			{
				unsigned int sze = AllocateRandom(_plnText);
				unsigned int prlBlock = sze - (sze % (cipher.BlockSize() * _processorCount));
				_encText.resize(sze);
				_cmpText.resize(sze);
				_decText.resize(sze);

				cipher.ParallelBlockSize() = prlBlock;
				cipher2.ParallelBlockSize() = prlBlock;
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				MemoryStream mRes;

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
				BlockCTR(&cipher, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel() = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				mIn.Seek(0, SeekOrigin::Begin);
				mOut.Seek(0, SeekOrigin::Begin);

				cs.IsParallel() = true;
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
				BlockCTR(&cipher, _encText, 0, _decText, 0);

				if (_plnText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel() = false;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel() = true;
				mOut.Seek(0, SeekOrigin::Begin);
				mRes.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}

		void DescriptionTest(CipherDescription* Description)
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);
			AllocateRandom(_plnText);

			KeyParams kp(_key, _iv);
			MemoryStream mIn(_plnText);
			MemoryStream mOut;
			MemoryStream mRes;

			CipherStream cs(Description);
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			mOut.Seek(0, SeekOrigin::Begin);

			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);

			if (mRes.ToArray() != _plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
		}

		void FileStreamTest()
		{
			std::vector<byte> buff(255);
			FileStream fsr(mediumFileIn, FileAccess::Read, FileMode::Binary);
			fsr.Read(buff, 0, 100);
			bool exc = true;

			// test exception
			try
			{
				fsr.WriteByte((byte)1);
			}
			catch (...)
			{
				exc = false;
			}
			if (exc)
				throw;

			fsr.Close();

			std::vector<byte> buff2(255);
			for (int i = 0; i < 255; i++)
				buff2[i] = (byte)i;

			Delete(mediumFileEnc.c_str());

			FileStream fsw(mediumFileEnc, FileAccess::ReadWrite, (FileMode)(FileMode::Append | FileMode::Binary));
			long len = fsw.Length();

			fsw.Write(buff2, 0, buff2.size());
			fsw.Seek(len, SeekOrigin::Begin);
			std::vector<byte> buff3(255);
			fsw.Read(buff3, 0, 255);
			fsw.Close();

			if (buff3 != buff2)
				throw;
		}

		void MemoryStreamTest()
		{
			MemoryStream ms;
			ms.WriteByte((byte)10);
			ms.WriteByte((byte)11);
			ms.WriteByte((byte)12);

			std::vector<byte> data(255);
			for (int i = 0; i < 255; i++)
				data[i] = (byte)i;
			ms.Write(data, 0, 255);

			ms.Seek(0, SeekOrigin::Begin);

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

		void ParametersTest()
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);
			AllocateRandom(_plnText, 1);

			KeyParams kp(_key, _iv);
			_cmpText.resize(1);
			_decText.resize(1);
			_encText.resize(1);

			RHX* engine = new RHX();
			
			// 1 byte w/ byte arrays
			{
				CTR* cipher = new CTR(engine);
				CipherStream cs(cipher);

				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _encText, 0);

				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _decText, 0);

				if (_decText != _plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}
			// 1 byte w/ stream
			{
				CTR* cipher = new CTR(engine);
				CipherStream cs(cipher);
				cs.Initialize(true, kp);
				AllocateRandom(_plnText, 1);
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				cs.Write(&mIn, &mOut);

				cs.Initialize(false, kp);
				MemoryStream mRes;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}

			// partial block w/ byte arrays
			{
				CTR* cipher = new CTR(engine);
				CipherStream cs(cipher);
				AllocateRandom(_plnText, 15);
				_decText.resize(15);
				_encText.resize(15);

				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _encText, 0);

				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _decText, 0);

				if (_decText != _plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}
			// partial block w/ stream
			{
				CTR* cipher = new CTR(engine);
				CipherStream cs(cipher);
				AllocateRandom(_plnText, 15);
				_decText.resize(15);
				_encText.resize(15);

				cs.Initialize(true, kp);
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				cs.Write(&mIn, &mOut);

				cs.Initialize(false, kp);
				MemoryStream mRes;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _plnText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				delete cipher;
			}

			// random block sizes w/ byte arrays
			{
				for (int i = 0; i < 100; i++)
				{
					CTR* cipher = new CTR(engine);

					unsigned int sze = AllocateRandom(_plnText);
					_decText.resize(sze);
					_encText.resize(sze);

					CipherStream cs(cipher);
					cs.Initialize(true, kp);
					cs.Write(_plnText, 0, _encText, 0);

					cs.Initialize(false, kp);
					cs.Write(_encText, 0, _decText, 0);

					if (_decText != _plnText)
						throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

					delete cipher;
				}
			}
			// random block sizes w/ stream
			{
				for (int i = 0; i < 100; i++)
				{
					CTR* cipher = new CTR(engine);
					unsigned int sze = AllocateRandom(_plnText);
					_decText.resize(sze);
					_encText.resize(sze);

					CipherStream cs(cipher);
					cs.Initialize(true, kp);
					MemoryStream mIn(_plnText);
					MemoryStream mOut;
					cs.Write(&mIn, &mOut);

					cs.Initialize(false, kp);
					MemoryStream mRes;
					mOut.Seek(0, SeekOrigin::Begin);
					cs.Write(&mOut, &mRes);

					if (mRes.ToArray() != _plnText)
						throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

					delete cipher;
				}
			}

			delete engine;
		}

		void OfbModeTest()
		{
			AllocateRandom(_iv, 16);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			RHX* engine = new RHX();
			OFB cipher(engine);
			OFB cipher2(engine);
			ISO7816* padding = new ISO7816();
			cipher.IsParallel() = false;
			CipherStream cs(&cipher2, padding);

			for (int i = 0; i < 10; i++)
			{
				unsigned int sze = AllocateRandom(_plnText, 0, cipher.BlockSize());
				unsigned int prlBlock = sze - (sze % (cipher.BlockSize() * _processorCount));
				_cmpText.resize(sze);
				_decText.resize(sze);
				_encText.resize(sze);

				cipher.ParallelBlockSize() = prlBlock;
				cipher2.ParallelBlockSize() = prlBlock;
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				MemoryStream mRes;

				// *** Compare encryption output *** //

				// local processor
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, padding, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel() = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher.Initialize(false, kp);
				BlockDecrypt(&cipher, padding, _encText, 0, _decText, 0);

				if (_plnText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cipher2.IsParallel() = false;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				_cmpText.resize(_encText.size());
				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete engine;
			delete padding;
		}

		void SerializeStructTest()
		{
			CipherDescription cd(SymmetricEngines::RHX,
				192,
				IVSizes::V128,
				CipherModes::CTR,
				PaddingModes::PKCS7,
				BlockSizes::B128,
				RoundCounts::R22,
				Digests::Skein512,
				64,
				Digests::SHA512);

			CipherDescription cy(*cd.ToStream());

			if (!cy.Equals(cd))
				throw;

			cy.KeySize() = 0;
			if (cy.Equals(cd))
				throw;
		}

		void StreamTest()
		{
			AllocateRandom(_iv, 8);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			Salsa20* cipher = new Salsa20();
			Salsa20* cipher2 = new Salsa20();
			CipherStream cs(cipher2);
			cipher->IsParallel() = false;

			// ctr test
			for (int i = 0; i < 10; i++)
			{
				unsigned int sze = AllocateRandom(_plnText);
				unsigned int prlBlock = sze - (sze % (cipher->BlockSize() * _processorCount));
				_cmpText.resize(sze);
				_decText.resize(sze);
				_encText.resize(sze);

				cipher->ParallelBlockSize() = prlBlock;
				cs.ParallelBlockSize() = prlBlock;
				MemoryStream mIn(_plnText);
				MemoryStream mOut;
				MemoryStream mRes;

				// *** Compare encryption output *** //

				// local processor
				cipher->Initialize(kp);
				ProcessStream(cipher, _plnText, 0, _encText, 0);

				// streamcipher linear mode
				cs.IsParallel() = false;
				// memorystream interface
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				mIn.Seek(0, SeekOrigin::Begin);
				mOut.Seek(0, SeekOrigin::Begin);

				// parallel test
				cs.IsParallel() = true;
				cs.Initialize(true, kp);
				cs.Write(&mIn, &mOut);

				if (mOut.ToArray() != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(true, kp);
				cs.Write(_plnText, 0, _cmpText, 0);

				if (_cmpText != _encText)
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				// ***compare decryption output *** //

				// local processor
				cipher->Initialize(kp);
				ProcessStream(cipher, _encText, 0, _decText, 0);

				if (_plnText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt linear mode
				cs.IsParallel() = false;
				mOut.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// decrypt parallel mode
				cs.IsParallel() = true;
				mOut.Seek(0, SeekOrigin::Begin);
				mRes.Seek(0, SeekOrigin::Begin);
				cs.Initialize(false, kp);
				cs.Write(&mOut, &mRes);

				if (mRes.ToArray() != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				// byte array interface
				cs.Initialize(false, kp);
				cs.Write(_encText, 0, _cmpText, 0);

				if (_cmpText != _decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete cipher;
			delete cipher2;
		}

		void StreamModesTest(ICipherMode* Cipher, IPadding* Padding)
		{
			if (Cipher->LegalKeySizes()[0] > 32)
				AllocateRandom(_key, 192);
			else
				AllocateRandom(_key, 32);

			AllocateRandom(_iv, 16);

			// we are testing padding modes, make sure input size is random, but -not- block aligned..
			AllocateRandom(_plnText, 0, Cipher->BlockSize());

			KeyParams kp(_key, _iv);
			MemoryStream mIn(_plnText);
			MemoryStream mOut;
			MemoryStream mRes;

			CipherStream cs(Cipher, Padding);
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			cs.Initialize(false, kp);
			mOut.Seek(0, SeekOrigin::Begin);
			cs.Write(&mOut, &mRes);
			
			delete Cipher;
			delete Padding;

			if (mRes.ToArray() != _plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
		}

		void StreamingTest(IStreamCipher* Cipher)
		{
			AllocateRandom(_plnText);
			AllocateRandom(_iv, 8);
			AllocateRandom(_key, 32);

			KeyParams kp(_key, _iv);
			MemoryStream mIn(_plnText);
			MemoryStream mOut;
			MemoryStream mRes;

			CipherStream cs(Cipher);
			cs.Initialize(true, kp);
			cs.Write(&mIn, &mOut);

			mOut.Seek(0, SeekOrigin::Begin);

			cs.Initialize(false, kp);
			cs.Write(&mOut, &mRes);
			delete Cipher;

			if (mRes.ToArray() != _plnText)
				throw std::string("CipherStreamTest: Encrypted arrays are not equal!");
		}

		// *** Helpers *** //
		int AllocateRandom(std::vector<byte> &Data, unsigned int Size = 0, int NonAlign = 0)
		{
			CSPPrng rng;

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
			return Data.size();
		}

		void BlockCTR(ICipherMode* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->BlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = inpSize - (inpSize % blkSize);
			unsigned long count = 0;

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
				unsigned int cnkSize = inpSize - alnSize;
				std::vector<byte> inpBuffer(blkSize);
				memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
				std::vector<byte> outBuffer(blkSize);
				Cipher->Transform(inpBuffer, 0, outBuffer, 0);
				memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
				count += cnkSize;
			}
		}

		void BlockDecrypt(ICipherMode* Cipher, IPadding* Padding, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->BlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = inpSize - blkSize;
			unsigned long count = 0;

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
			unsigned int fnlSize = blkSize - Padding->GetPaddingLength(outBuffer, 0);
			memcpy(&Output[OutOffset], &outBuffer[0], fnlSize);
			OutOffset += fnlSize;

			if (Output.size() != OutOffset)
				Output.resize(OutOffset);
		}

		void BlockEncrypt(ICipherMode* Cipher, IPadding* Padding, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->BlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = inpSize - (inpSize % blkSize);
			unsigned long count = 0;

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
				unsigned int fnlSize = inpSize - alnSize;
				std::vector<byte> inpBuffer(blkSize);
				memcpy(&inpBuffer[0], &Input[InOffset], fnlSize);
				Padding->AddPadding(inpBuffer, fnlSize);
				std::vector<byte> outBuffer(blkSize);
				Cipher->Transform(inpBuffer, 0, outBuffer, 0);
				if (Output.size() != OutOffset + blkSize)
					Output.resize(OutOffset + blkSize);
				memcpy(&Output[OutOffset], &outBuffer[0], blkSize);
				count += blkSize;
			}
		}

		void Delete(const char* FileName)
		{
			if (FileExists(FileName))
				std::remove(FileName);
		}

		bool FileExists(const char* FileName)
		{
			try
			{
				std::ifstream infile(FileName);
				bool valid = infile.good();
				infile.close();
				return valid;
			}
			catch (...)
			{
				return false;
			}
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}

		void ParallelCTR(ICipherMode* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->ParallelBlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = (inpSize / blkSize) * blkSize;
			unsigned long count = 0;

			Cipher->IsParallel() = true;
			Cipher->ParallelBlockSize() = blkSize;

			// parallel blocks
			while (count != alnSize)
			{
				Cipher->Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				unsigned int cnkSize = inpSize - alnSize;
				std::vector<byte> inpBuffer(cnkSize);
				memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
				std::vector<byte> outBuffer(cnkSize);
				Cipher->Transform(inpBuffer, outBuffer);
				memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
				count += cnkSize;
			}
		}

		void ParallelDecrypt(ICipherMode* Cipher, IPadding* Padding, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->ParallelBlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = (inpSize / blkSize) * blkSize;
			unsigned long count = 0;

			Cipher->IsParallel() = true;
			Cipher->ParallelBlockSize() = blkSize;

			// parallel
			while (count != alnSize)
			{
				Cipher->Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				unsigned int cnkSize = inpSize - alnSize;
				BlockDecrypt(Cipher, Padding, Input, InOffset, Output, OutOffset);
			}
		}

		void ParallelStream(IStreamCipher* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->ParallelBlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = (inpSize / blkSize) * blkSize;
			unsigned long count = 0;

			Cipher->IsParallel() = true;
			Cipher->ParallelBlockSize() = blkSize;

			// parallel blocks
			while (count != alnSize)
			{
				Cipher->Transform(Input, InOffset, Output, OutOffset);
				InOffset += blkSize;
				OutOffset += blkSize;
				count += blkSize;
			}

			if (alnSize != inpSize)
			{
				unsigned int cnkSize = inpSize - alnSize;
				std::vector<byte> inpBuffer(cnkSize);
				memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
				std::vector<byte> outBuffer(cnkSize);
				Cipher->Transform(inpBuffer, outBuffer);
				memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
				count += cnkSize;
			}
		}

		void ProcessStream(IStreamCipher* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = Cipher->BlockSize();
			const unsigned long inpSize = (Input.size() - InOffset);
			const unsigned long alnSize = (inpSize / blkSize) * blkSize;
			unsigned long count = 0;

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
				unsigned int cnkSize = inpSize - alnSize;
				std::vector<byte> inpBuffer(cnkSize);
				memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
				std::vector<byte> outBuffer(cnkSize);
				Cipher->Transform(inpBuffer, outBuffer);
				memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
				count += cnkSize;
			}
		}
	};
}

#endif

