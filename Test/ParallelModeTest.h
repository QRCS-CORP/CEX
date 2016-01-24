#ifndef _CEXTEST_PARALLELMODETEST_H
#define _CEXTEST_PARALLELMODETEST_H

#include "ITest.h"
#include "KeyParams.h"
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
	using CEX::Cipher::Symmetric::Block::Mode::CBC;
	using CEX::Cipher::Symmetric::Block::Mode::CFB;
	using CEX::Cipher::Symmetric::Block::Mode::CTR;
	using CEX::Cipher::Symmetric::Block::Mode::OFB;
	using CEX::Cipher::Symmetric::Block::Padding::IPadding;
	using CEX::Cipher::Symmetric::Block::Padding::ISO7816;
	using CEX::Cipher::Symmetric::Block::Padding::PKCS7;
	using CEX::Cipher::Symmetric::Block::Padding::TBC;
	using CEX::Cipher::Symmetric::Block::Padding::X923;
	using CEX::Cipher::Symmetric::Block::IBlockCipher;
	using CEX::Cipher::Symmetric::Block::RHX;
	using CEX::Cipher::Symmetric::Stream::IStreamCipher;
	using CEX::Cipher::Symmetric::Stream::ChaCha;
	using CEX::Cipher::Symmetric::Stream::Salsa20;
	using CEX::Common::CipherDescription;
	using CEX::Common::KeyParams;
	using CEX::IO::FileStream;
	using CEX::IO::MemoryStream;
	using CEX::IO::SeekOrigin;
	using CEX::Prng::CSPPrng;

    /// <remarks>
    /// Compares the output of modes processed in parallel with their linear counterparts
    /// </remarks>
    class ParallelModeTest : public ITest
    {
	private:
		const std::string DESCRIPTION = "Compares output from parallel and linear modes for equality.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Parallel tests have executed succesfully.";
		const unsigned int MIN_ALLOC = 512;
		const unsigned int MAX_ALLOC = 4096;
		const unsigned int DEF_BLOCK = 64000;

		TestEventHandler _progressEvent;
		std::vector<byte> _cipherText;
		std::vector<byte> _decText;
		std::vector<byte> _iv;
		std::vector<byte> _key;
		std::vector<byte> _plnText;
		unsigned int _parallelBlockSize;
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

		/// <remarks>
		/// Compares Output between linear and parallel Cipher Modes
		/// </remarks>
		ParallelModeTest() 
			:
			_cipherText(0),
			_decText(0),
			_iv(16),
			_key(32),
			_parallelBlockSize(DEF_BLOCK),
			_plnText(0),
			_processorCount(1)
		{
			_cipherText.reserve(MAX_ALLOC);
			_decText.reserve(MAX_ALLOC);
			_plnText.reserve(MAX_ALLOC);

			for (int i = 0; i < 32; i++)
				_key[i] = (byte)i;
			for (int i = 15; i != 0; i--)
				_iv[i] = (byte)i;

			_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~ParallelModeTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
        {
            try
            {
				ParallelIntegrity();
				OnProgress("ParallelModeTest: Passed Parallel encryption and decryption Integrity tests..");
                CompareParallel();
				OnProgress("ParallelModeTest: Passed Parallel encryption and decryption tests..");

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

        void CompareParallel()
        {
            std::vector<byte> data;
            std::vector<byte> dec1;
            std::vector<byte> dec2;
            std::vector<byte> enc1;
            std::vector<byte> enc2;
            std::vector<byte> key;
            std::vector<byte> iv;
            int blockSize;

            GetBytes(32,key);
            GetBytes(16,iv);
			CEX::Common::KeyParams keyParam(key,iv);
            
            // CTR mode
            {
				RHX* eng = new RHX();
                CTR cipher(eng);

				// with CTR, array can be any size
                GetBytes(1036, data);
                
                // how to calculate an ideal block size:
				unsigned int plen = (data.size() / cipher.ParallelMinimumSize()) * cipher.ParallelMinimumSize();
                // you can factor it up or down or use a default
                if (plen > cipher.ParallelMaximumSize())
                    plen = 1024;
                
                // set parallel block size
                cipher.ParallelBlockSize() = plen;
                
                // encrypt //
                // parallel 1
                cipher.Initialize(true, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform1(&cipher, data, blockSize, enc1);
                
                // parallel 2
                cipher.Initialize(true, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform2(&cipher, data, blockSize, enc2);
                
				if (!Test::TestUtils::IsEqual(enc1, enc2))
					throw std::string("Parallel CTR: Encrypted output is not equal!");
                
                // linear 1
                cipher.Initialize(true, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform1(&cipher, data, blockSize, enc2);
                
                if (!Test::TestUtils::IsEqual(enc1, enc2))
                    throw std::string("Parallel CTR: Encrypted output is not equal!");
                
                // linear 2
                cipher.Initialize(true, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform2(&cipher, data, blockSize, enc2);
                
                if (!Test::TestUtils::IsEqual(enc1, enc2))
                    throw std::string("Parallel CTR: Encrypted output is not equal!");
                
                // decrypt //
                // parallel 1
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform1(&cipher, enc1, blockSize, dec1);
                
                // parallel 2
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform2(&cipher, enc2, blockSize, dec2);
                
                if (!Test::TestUtils::IsEqual(dec1, dec2))
                    throw std::string("Parallel CTR: Decrypted output is not equal!");
                
                // linear 1
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform1(&cipher, enc1, blockSize, dec2);
                
                if (!Test::TestUtils::IsEqual(dec1, dec2))
                    throw std::string("Parallel CTR: Decrypted output is not equal!");
                
                // linear 2
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform2(&cipher, enc2, blockSize, dec2);
                
                if (!Test::TestUtils::IsEqual(dec1, dec2))
                    throw std::string("Parallel CTR: Decrypted output is not equal!");

				delete eng;
            }
            
            if (data != dec1)
                throw std::string("Parallel CTR: Decrypted output is not equal!");
            if (data != dec2)
                throw std::string("Parallel CTR: Decrypted output is not equal!");
            
            std::cout << "ParallelModeTest: Passed Parallel CTR encryption and decryption tests..\n";
            
			// CBC mode
			{
				RHX* eng = new RHX();
				CBC cipher(eng);

				// must be divisible by block size, add padding if required
				GetBytes(2048, data);

				// encrypt
				cipher.ParallelBlockSize() = 1024;

				// t1: encrypt only in normal mode for cbc
				cipher.Initialize(true, keyParam);
				blockSize = cipher.BlockSize();
				Transform1(&cipher, data, blockSize, enc1);

				// t2
				cipher.Initialize(true, keyParam);
				blockSize = cipher.BlockSize();
				Transform2(&cipher, data, blockSize, enc2);

				if (!Test::TestUtils::IsEqual(enc1, enc2))
					throw std::string("Parallel CBC: Decrypted output is not equal!");

				// decrypt //
				// t1 parallel
				cipher.Initialize(false, keyParam);
				cipher.IsParallel() = true;
				blockSize = cipher.ParallelBlockSize();
				Transform1(&cipher, enc1, blockSize, dec1);

				// t1 linear
				cipher.Initialize(false, keyParam);
				cipher.IsParallel() = false;
				blockSize = cipher.BlockSize();
				Transform1(&cipher, enc2, blockSize, dec2);

				if (!Test::TestUtils::IsEqual(dec1, dec2))
					throw std::string("Parallel CBC: Decrypted output is not equal!");

				// t2 parallel
				cipher.Initialize(false, keyParam);
				cipher.IsParallel() = true;
				blockSize = cipher.ParallelBlockSize();
				Transform2(&cipher, enc2, blockSize, dec1);

				// t2 linear
				cipher.Initialize(false, keyParam);
				cipher.IsParallel() = false;
				blockSize = cipher.BlockSize();
				Transform2(&cipher, enc1, blockSize, dec2);

				if (!Test::TestUtils::IsEqual(dec1, dec2))
					throw std::string("Parallel CBC: Decrypted output is not equal!");

				delete eng;
			}

			if (dec1 != data)
				throw std::string("Parallel CBC: Decrypted output is not equal!");
			if (dec2 != data)
				throw std::string("Parallel CBC: Decrypted output is not equal!");

			std::cout << "ParallelModeTest: Passed Parallel CBC decryption tests..\n";
            
            // CFB mode
            {
				RHX* eng = new RHX();
                CFB cipher(eng);
                
                // must be divisible by block size, add padding if required
                GetBytes(2048,data);
                
                // encrypt
                cipher.ParallelBlockSize() = 1024;
                
                // t1: encrypt only in normal mode for cfb
                cipher.Initialize(true, keyParam);
                blockSize = cipher.BlockSize();
                Transform1(&cipher, data, blockSize, enc1);
                // t2
                cipher.Initialize(true, keyParam);
                blockSize = cipher.BlockSize();
                Transform2(&cipher, data, blockSize, enc2);
                
                if (!Test::TestUtils::IsEqual(enc1, enc2))
                    throw std::string("Parallel CFB: Decrypted output is not equal!");
                
                // decrypt //
                // t1 parallel
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform1(&cipher, enc1, blockSize, dec1);
                
                // t1 linear
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform1(&cipher, enc2, blockSize, dec2);
                
                if (!Test::TestUtils::IsEqual(dec1, dec2))
                    throw std::string("Parallel CFB: Decrypted output is not equal!");
                
                // t2 parallel
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = true;
                blockSize = cipher.ParallelBlockSize();
                Transform2(&cipher, enc2, blockSize, dec1);
                
                // t2 linear
                cipher.Initialize(false, keyParam);
                cipher.IsParallel() = false;
                blockSize = cipher.BlockSize();
                Transform2(&cipher, enc1, blockSize, dec2);
                
                if (!Test::TestUtils::IsEqual(dec1, dec2))
                    throw std::string("Parallel CFB: Decrypted output is not equal!");

				delete eng;
            }
            
            if (data != dec1)
                throw std::string("Parallel CFB: Decrypted output is not equal!");
            if (data != dec2)
                throw std::string("Parallel CFB: Decrypted output is not equal!");
            
            std::cout << "ParallelModeTest: Passed Parallel CFB decryption tests..\n";
        }        

        void GetBytes(int Size, std::vector<byte> &Output)
        {
			Output.resize(Size,0);
			CSPRsg rng;
            rng.GetBytes(Output);
        }

		void ParallelCTR(ICipherMode* Cipher, const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset)
		{
			const unsigned int blkSize = _parallelBlockSize;
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
			const unsigned int blkSize = _parallelBlockSize;
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

		void ParallelIntegrity()
		{
			CSPPrng rng;
			_iv.resize(16);
			_key.resize(32);
			rng.GetBytes(_iv);
			rng.GetBytes(_key);
			KeyParams kp(_key, _iv);

			std::vector<byte> cp2Text(0);
			cp2Text.reserve(MAX_ALLOC);

			// compare ctr output
			OnProgress("***Testing Block Cipher Modes***..");

			{
				RHX* eng = new RHX();
				CTR cipher(eng);

				for (int i = 0; i < 10; i++)
				{
					unsigned int sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
					_cipherText.resize(sze);
					cp2Text.resize(sze);
					_decText.resize(sze);
					_plnText.resize(sze);
					rng.GetBytes(_plnText);

					cipher.Initialize(true, kp);
					BlockCTR(&cipher, _plnText, 0, _cipherText, 0);

					cipher.Initialize(true, kp);
					ParallelCTR(&cipher, _plnText, 0, cp2Text, 0);

					if (_cipherText != cp2Text)
						throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

					cipher.Initialize(false, kp);
					BlockCTR(&cipher, _cipherText, 0, _decText, 0);

					if (_decText != _plnText)
						throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

					cipher.Initialize(false, kp);
					ParallelCTR(&cipher, cp2Text, 0, _decText, 0);

					if (_decText != _plnText)
						throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
				}

				delete eng;
			}
			OnProgress("Passed CTR Mode tests..");

			// test cbc
			{
				RHX* eng = new RHX();
				CBC cipher(eng);
				cipher.IsParallel() = false;
				ISO7816 pad;

				for (int i = 0; i < 10; i++)
				{
					unsigned int sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
					_cipherText.resize(sze);
					_decText.resize(sze);
					_plnText.resize(sze);
					rng.GetBytes(_plnText);

					// encrypt the array locally
					cipher.Initialize(true, kp);
					BlockEncrypt(&cipher, &pad, _plnText, 0, _cipherText, 0);
					// decrypt
					cipher.Initialize(false, kp);
					ParallelDecrypt(&cipher, &pad, _cipherText, 0, _decText, 0);

					if (_plnText != _decText)
						throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
				}

				delete eng;
			}
			OnProgress("Passed CBC Mode tests..");

			// cfb
			{
				RHX* eng = new RHX();
				CFB cipher(eng);
				cipher.IsParallel() = false;
				ISO7816 pad;

				for (int i = 0; i < 10; i++)
				{
					unsigned int sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
					_cipherText.resize(sze);
					_decText.resize(sze);
					_plnText.resize(sze);
					rng.GetBytes(_plnText);

					// encrypt the array locally
					cipher.Initialize(true, kp);
					BlockEncrypt(&cipher, &pad, _plnText, 0, _cipherText, 0);
					// decrypt
					cipher.Initialize(false, kp);
					ParallelDecrypt(&cipher, &pad, _cipherText, 0, _decText, 0);

					if (_plnText != _decText)
						throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
				}

				delete eng;
			}
			OnProgress("Passed CFB Mode tests..");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}

        void Transform1(ICipherMode *Cipher, std::vector<byte> &Input, int BlockSize, std::vector<byte> &Output)
        {
			Output.resize(Input.size(), 0);

			// best way, use the offsets
			unsigned int blocks = Input.size() / BlockSize;

			for (unsigned int i = 0; i < blocks; i++)
				Cipher->Transform(Input, i * BlockSize, Output, i * BlockSize);
            
			if (blocks * BlockSize < Input.size())
			{
				std::string name = Cipher->Name();
				if (name == "CTR")
				{
					unsigned int sze = Input.size() - (blocks * BlockSize);
					std::vector<byte> inpBuffer(sze);
					unsigned int oft = Input.size() - sze;
					memcpy(&inpBuffer[0], &Input[oft], sze);
					std::vector<byte> outBuffer(sze);
					Cipher->Transform(inpBuffer, outBuffer);
					memcpy(&Output[oft], &outBuffer[0], sze);
				}
				else
				{
					// last partial
					Cipher->Transform(Input, blocks * BlockSize, Output, blocks * BlockSize);
				}
			}
        }

        void Transform2(ICipherMode *Cipher, std::vector<byte> &Input, int BlockSize, std::vector<byte> &Output)
        {
			Output.resize(Input.size(), 0);
            
            // slower, mem copy can be expensive on large data..
			unsigned int blocks = Input.size() / BlockSize;
            std::vector<byte> inBlock(BlockSize, 0);
            std::vector<byte> outBlock(BlockSize, 0);

            std::string name = Cipher->Name();
            if (name == "CTR")
            {
                Cipher->Transform(Input, Output);
            }
            else
            {
                for (unsigned int i = 0; i < blocks; i++)
                {
					memcpy(&inBlock[0], &Input[i * BlockSize], BlockSize);
                    Cipher->Transform(inBlock, outBlock);
					memcpy(&Output[i * BlockSize], &outBlock[0], BlockSize);
                }

                if (blocks * BlockSize < Input.size())
                    Cipher->Transform(Input, blocks * BlockSize, Output, blocks * BlockSize);
            }
        }
    };
}

#endif

