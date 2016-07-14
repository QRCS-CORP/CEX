#include "ParallelModeTest.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/CTR.h"
#include "../CEX/CSPPrng.h"
#include "../CEX/ISO7816.h"
#include "../CEX/ParallelUtils.h"
#include "../CEX/RHX.h"

#if defined(HAS_MINSSE)
#	include "../CEX/AHX.h"
#	include "../CEX/SHX.h"
#	include "../CEX/THX.h"
#endif

#define STAT_INP

namespace Test
{
	std::string ParallelModeTest::Run()
	{
		try
		{
			Initialize();

#if defined(HAS_MINSSE)

			AHXCompare();
			OnProgress("ParallelModeTest: AHX Passed AES-NI/Rijndael CTR/CBC comparison tests..");
			CEX::Cipher::Symmetric::Block::AHX* eng1 = new CEX::Cipher::Symmetric::Block::AHX();
			TestIntrinsics(eng1);
			OnProgress("ParallelModeTest: AHX Passed Rijndael Intrinsics Integrity tests..");
			CEX::Cipher::Symmetric::Block::SHX* eng2 = new CEX::Cipher::Symmetric::Block::SHX();
			TestIntrinsics(eng2);
			OnProgress("ParallelModeTest: SHX Passed Serpent Intrinsics Integrity tests..");
			CEX::Cipher::Symmetric::Block::THX* eng3 = new CEX::Cipher::Symmetric::Block::THX();
			TestIntrinsics(eng3);
			OnProgress("ParallelModeTest: THX Passed Twofish Intrinsics Integrity tests..");
			OnProgress("");

#endif
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

	void ParallelModeTest::AHXCompare()
	{
#if defined(HAS_MINSSE)
		std::vector<byte> data;
		std::vector<byte> dec;
		std::vector<byte> enc1;
		std::vector<byte> enc2;
		std::vector<byte> key(32);
		std::vector<byte> iv(16);
		size_t blockSize;
		CEX::Prng::CSPPrng rng;
		data.reserve(MAX_ALLOC);
		enc1.reserve(MAX_ALLOC);
		enc2.reserve(MAX_ALLOC);
		CEX::Cipher::Symmetric::Block::AHX* eng1 = new CEX::Cipher::Symmetric::Block::AHX();
		CEX::Cipher::Symmetric::Block::RHX* eng2 = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Cipher::Symmetric::Block::Mode::CTR cpr1(eng1);
		CEX::Cipher::Symmetric::Block::Mode::CTR cpr2(eng2);

		// compare rhx/ahx parallel ctr
		for (size_t i = 0; i < 100; ++i)
		{
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);
			rng.GetBytes(data);
			GetBytes(32, key);
			GetBytes(16, iv);

			CEX::Common::KeyParams keyParam(key, iv);

			cpr1.ParallelBlockSize(cpr1.ParallelMinimumSize() * cpr1.ProcessorCount());
			cpr1.Initialize(true, keyParam);
			cpr1.IsParallel() = true;
			blockSize = cpr1.ParallelBlockSize();
			Transform1(&cpr1, data, blockSize, enc1);

			cpr2.ParallelBlockSize(cpr2.ParallelMinimumSize() * cpr2.ProcessorCount());
			cpr2.Initialize(true, keyParam);
			cpr2.IsParallel() = true;
			blockSize = cpr2.ParallelBlockSize();
			Transform1(&cpr2, data, blockSize, enc2);

			if (enc1 != enc2)
				throw std::string("Parallel CTR: Encrypted output is not equal!");
		}

		CEX::Cipher::Symmetric::Block::Mode::CBC cpr3(eng1);
		CEX::Cipher::Symmetric::Block::Mode::CBC cpr4(eng2);
		CEX::Cipher::Symmetric::Block::Padding::ISO7816 pad;

		// compare rhx/ahx cbc
		for (size_t i = 0; i < 100; ++i)
		{
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);
			rng.GetBytes(data);
			GetBytes(32, key);
			GetBytes(16, iv);

			CEX::Common::KeyParams keyParam(key, iv);

			cpr3.Initialize(true, keyParam);
			cpr3.IsParallel() = false;
			blockSize = cpr3.BlockSize();
			BlockEncrypt(&cpr3, &pad, data, 0, enc1, 0);

			cpr4.Initialize(true, keyParam);
			cpr4.IsParallel() = false;
			blockSize = cpr4.BlockSize();
			BlockEncrypt(&cpr4, &pad, data, 0, enc2, 0);

			if (enc1 != enc2)
				throw std::string("CBC: Encrypted output is not equal!");

			cpr3.Initialize(false, keyParam);
			BlockDecrypt(&cpr3, &pad, enc1, 0, dec, 0);

			if (dec != data)
				throw std::string("CBC: Decrypted output is not equal!");

			cpr4.Initialize(false, keyParam);
			BlockDecrypt(&cpr4, &pad, enc2, 0, dec, 0);

			if (dec != data)
				throw std::string("CBC: Decrypted output is not equal!");
		}

		delete eng1;
		delete eng2;
#endif
	}


	void ParallelModeTest::TestIntrinsics(CEX::Cipher::Symmetric::Block::IBlockCipher* Engine)
	{
#if defined(HAS_MINSSE)
		std::vector<byte> data;
		std::vector<byte> dec;
		std::vector<byte> enc1;
		std::vector<byte> enc2;
		std::vector<byte> key(32);
		std::vector<byte> iv(16);
		size_t blockSize;
		CEX::Prng::CSPPrng rng;
		data.reserve(MAX_ALLOC);
		enc1.reserve(MAX_ALLOC);
		enc2.reserve(MAX_ALLOC);

#if defined STAT_INP
		for (size_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (size_t i = 0; i < iv.size(); ++i)
			iv[i] = i;
#endif

		for (size_t i = 0; i < 100; ++i)
		{
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);

#if !defined STAT_INP
			rng.GetBytes(data);
			GetBytes(32, key);
			GetBytes(16, iv);
#endif
			CEX::Common::KeyParams keyParam(key, iv);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(Engine);
			cipher.ParallelBlockSize(cipher.ParallelMinimumSize() * cipher.ProcessorCount());
			// parallel w/ intrinsics (if available)
			cipher.Initialize(true, keyParam);
			cipher.IsParallel() = true;
			blockSize = cipher.ParallelBlockSize();
			Transform1(&cipher, data, blockSize, enc1);

			// sequential
			cipher.Initialize(true, keyParam);
			cipher.IsParallel() = false;
			blockSize = cipher.BlockSize();
			Transform1(&cipher, data, blockSize, enc2);

			if (enc1 != enc2)
				throw std::string("Parallel CTR: Encrypted output is not equal!");

			// decrypt
			cipher.Initialize(false, keyParam);
			cipher.IsParallel() = true;
			blockSize = cipher.ParallelBlockSize();
			Transform1(&cipher, enc1, blockSize, dec);

			if (dec != data)
				throw std::string("Parallel CTR: Decrypted output is not equal!");
		}
		delete Engine;
#endif
	}

	void ParallelModeTest::BlockCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (Input.size() - InOffset);
		const size_t alnSize = (inpSize - (inpSize % blkSize));
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

	void ParallelModeTest::BlockDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (size_t)(Input.size() - InOffset);
		const size_t alnSize = (size_t)(inpSize - blkSize);
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
		size_t fnlSize = blkSize - (size_t)Padding->GetPaddingLength(outBuffer, 0);
		memcpy(&Output[OutOffset], &outBuffer[0], fnlSize);
		OutOffset += fnlSize;

		if (Output.size() != OutOffset)
			Output.resize(OutOffset);
	}

	void ParallelModeTest::BlockEncrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = (size_t)(Input.size() - InOffset);
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

	void ParallelModeTest::CompareParallel()
	{
		std::vector<byte> data;
		std::vector<byte> dec1;
		std::vector<byte> dec2;
		std::vector<byte> enc1;
		std::vector<byte> enc2;
		std::vector<byte> key;
		std::vector<byte> iv;
		size_t blockSize;

		GetBytes(32, key);
		GetBytes(16, iv);
		CEX::Common::KeyParams keyParam(key, iv);

		// CTR mode
		{
			CEX::Cipher::Symmetric::Block::AHX* eng = new CEX::Cipher::Symmetric::Block::AHX();
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);

			// with CTR, array can be any size
			size_t smpSze = 0;
			GetBytes(2, data);
			memcpy(&smpSze, &data[0], 2);
			smpSze += 800;
			GetBytes(smpSze, data);

			// how to calculate an ideal block size:
			size_t plen = (size_t)((data.size() / cipher.ParallelMinimumSize()) * cipher.ParallelMinimumSize());
			// you can factor it up or down or use a default
			if (plen > cipher.ParallelMaximumSize())
				plen = 1024;

			// set parallel block size
			cipher.ParallelBlockSize(plen);

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
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CEX::Cipher::Symmetric::Block::Mode::CBC cipher(eng);

			// must be divisible by block size, add padding if required
			GetBytes(2048, data);

			// encrypt
			cipher.ParallelBlockSize(1024);

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
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CEX::Cipher::Symmetric::Block::Mode::CFB cipher(eng);

			// must be divisible by block size, add padding if required
			GetBytes(2048, data);

			// encrypt
			cipher.ParallelBlockSize(1024);

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

	void ParallelModeTest::GetBytes(size_t Size, std::vector<byte> &Output)
	{
		Output.resize(Size, 0);
		CEX::Seed::CSPRsg rng;
		rng.GetBytes(Output);
	}

	void ParallelModeTest::Initialize()
	{
		m_cipherText.reserve(MAX_ALLOC);
		m_decText.reserve(MAX_ALLOC);
		m_plnText.reserve(MAX_ALLOC);

		for (size_t i = 0; i < 32; i++)
			m_key[i] = (byte)i;
		for (int i = 15; i != 0; i--)
			m_iv[i] = (byte)i;

		m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
	}

	void ParallelModeTest::ParallelCTR(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->ParallelMinimumSize();
		const size_t inpSize = (Input.size() - InOffset);
		const size_t alnSize = ((inpSize / blkSize) * blkSize);
		size_t count = 0;

		Cipher->IsParallel() = true;
		Cipher->ParallelBlockSize(blkSize);

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
			size_t cnkSize = inpSize - alnSize;
			std::vector<byte> inpBuffer(cnkSize);
			memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
			std::vector<byte> outBuffer(cnkSize);
			Cipher->Transform(inpBuffer, outBuffer);
			memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		}
	}

	void ParallelModeTest::ParallelDecrypt(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = m_parallelBlockSize;
		const size_t inpSize = (Input.size() - InOffset);
		const size_t alnSize = ((inpSize / blkSize) * blkSize);
		size_t count = 0;

		Cipher->IsParallel() = true;
		Cipher->ParallelBlockSize(blkSize);

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
			BlockDecrypt(Cipher, Padding, Input, InOffset, Output, OutOffset);
		}
	}

	void ParallelModeTest::ParallelIntegrity()
	{
		CEX::Prng::CSPPrng rng;
		m_iv.resize(16);
		m_key.resize(32);
		rng.GetBytes(m_iv);
		rng.GetBytes(m_key);
		CEX::Common::KeyParams kp(m_key, m_iv);

		std::vector<byte> cp2Text(0);
		cp2Text.reserve(MAX_ALLOC);

		// compare ctr output
		OnProgress("***Testing Block Cipher Modes***..");

		{
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);

			for (size_t i = 0; i < 10; i++)
			{
				size_t sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				m_cipherText.resize(sze);
				cp2Text.resize(sze);
				m_decText.resize(sze);
				m_plnText.resize(sze);
				rng.GetBytes(m_plnText);

				cipher.Initialize(true, kp);
				BlockCTR(&cipher, m_plnText, 0, m_cipherText, 0);

				cipher.Initialize(true, kp);
				ParallelCTR(&cipher, m_plnText, 0, cp2Text, 0);

				if (m_cipherText[i] != cp2Text[i])
					throw std::string("CipherStreamTest: Encrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				BlockCTR(&cipher, m_cipherText, 0, m_decText, 0);

				if (m_decText != m_plnText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				ParallelCTR(&cipher, cp2Text, 0, m_decText, 0);

				if (m_decText != m_plnText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CTR Mode tests..");

		// test cbc
		{
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CEX::Cipher::Symmetric::Block::Mode::CBC cipher(eng);
			cipher.IsParallel() = false;
			CEX::Cipher::Symmetric::Block::Padding::ISO7816 pad;

			for (size_t i = 0; i < 10; i++)
			{
				size_t sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				m_cipherText.resize(sze);
				m_decText.resize(sze);
				m_plnText.resize(sze);
				rng.GetBytes(m_plnText);

				// encrypt the array locally
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, &pad, m_plnText, 0, m_cipherText, 0);
				// decrypt
				cipher.Initialize(false, kp);
				ParallelDecrypt(&cipher, &pad, m_cipherText, 0, m_decText, 0);

				if (m_plnText != m_decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CBC Mode tests..");

		// cfb
		{
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
			CEX::Cipher::Symmetric::Block::Mode::CFB cipher(eng);
			cipher.IsParallel() = false;
			CEX::Cipher::Symmetric::Block::Padding::ISO7816 pad;

			for (size_t i = 0; i < 10; i++)
			{
				size_t sze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				m_cipherText.resize(sze);
				m_decText.resize(sze);
				m_plnText.resize(sze);
				rng.GetBytes(m_plnText);

				// encrypt the array locally
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, &pad, m_plnText, 0, m_cipherText, 0);
				// decrypt
				cipher.Initialize(false, kp);
				ParallelDecrypt(&cipher, &pad, m_cipherText, 0, m_decText, 0);

				if (m_plnText != m_decText)
					throw std::string("CipherStreamTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CFB Mode tests..");
	}

	void ParallelModeTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void ParallelModeTest::Transform1(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output)
	{
		Output.resize(Input.size(), 0);

		// best way, use the offsets
		size_t blocks = Input.size() / BlockSize;

		for (size_t i = 0; i < blocks; i++)
			Cipher->Transform(Input, i * BlockSize, Output, i * BlockSize);

		if (blocks * BlockSize < Input.size())
		{
			std::string name = Cipher->Name();
			if (name == "CTR")
			{
				size_t sze = Input.size() - (blocks * BlockSize);
				std::vector<byte> inpBuffer(sze);
				size_t oft = Input.size() - sze;
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

	void ParallelModeTest::Transform2(CEX::Cipher::Symmetric::Block::Mode::ICipherMode *Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output)
	{
		Output.resize(Input.size(), 0);

		// slower, mem copy can be expensive on large data..
		size_t blocks = Input.size() / BlockSize;
		std::vector<byte> inBlock(BlockSize, 0);
		std::vector<byte> outBlock(BlockSize, 0);

		for (size_t i = 0; i < blocks; i++)
		{
			memcpy(&inBlock[0], &Input[i * BlockSize], BlockSize);
			Cipher->Transform(inBlock, outBlock);
			memcpy(&Output[i * BlockSize], &outBlock[0], BlockSize);
		}

		if (blocks * BlockSize < Input.size())
			Cipher->Transform(Input, blocks * BlockSize, Output, blocks * BlockSize);
	}
}