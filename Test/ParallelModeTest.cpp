#include "ParallelModeTest.h"
#include "TestUtils.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/CTR.h"
#include "../CEX/ICM.h"
#include "../CEX/CSPPrng.h"
#include "../CEX/ParallelUtils.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/THX.h"
#include "../CEX/ChaCha.h"
#include "../CEX/Salsa20.h"

//#define STAT_INP // internal testing

namespace Test
{
	using namespace CEX::Cipher::Symmetric::Block;
	using namespace CEX::Cipher::Symmetric::Stream;

	std::string ParallelModeTest::Run()
	{
		try
		{
			Initialize();

			if (m_hasSSE)
			{
				if (m_hasAESNI)
				{
					CompareAhxSimd();
					OnProgress("ParallelModeTest: AHX Passed AES-NI/Rijndael CTR/CBC comparison tests..");

					AHX* eng1 = new AHX();
					CompareBcrSimd(eng1);
					OnProgress("ParallelModeTest: AHX Passed Rijndael Parallel Intrinsics Integrity tests..");
					CompareBcrKat(eng1, m_katExpected[0]);
					OnProgress("ParallelModeTest: AHX Passed Rijndael Monte Carlo KAT test..");

					AHX* eng1b = new AHX();
					CompareCbcDecrypt(eng1, eng1b);
					delete eng1;
					delete eng1b;
					OnProgress("ParallelModeTest: AHX Passed Parallel CBC Decrypt SIMD-128 Integrity tests..");
				}

				SHX* eng2 = new SHX();
				CompareBcrSimd(eng2);
				OnProgress("ParallelModeTest: SHX Passed Serpent Parallel Intrinsics Integrity tests..");
				CompareBcrKat(eng2, m_katExpected[1]);
				OnProgress("ParallelModeTest: SHX Passed Serpent Monte Carlo KAT test..");
				CompareCbcWide(eng2);
				OnProgress("ParallelModeTest: SHX Passed CBC-WBV Wide Block Vector integrity and parallel tests..");

				SHX* eng2b = new SHX();
				CompareCbcDecrypt(eng2, eng2b);
				OnProgress("ParallelModeTest: SHX Passed Parallel CBC Decrypt SIMD-256 Integrity tests..");
				delete eng2;
				delete eng2b;

				THX* eng3 = new THX();
				CompareBcrSimd(eng3);
				OnProgress("ParallelModeTest: THX Passed Serpent Monte Carlo KAT test..");
				CompareBcrKat(eng3, m_katExpected[2]);
				delete eng3;
				OnProgress("ParallelModeTest: THX Passed Twofish Parallel Intrinsics Integrity tests..");

				ChaCha* stm1 = new ChaCha();
				CompareStmSimd(stm1);
				OnProgress("ParallelModeTest: ChaCha Passed Parallel Intrinsics Integrity tests..");
				CompareStmKat(stm1, m_katExpected[3]);
				OnProgress("ParallelModeTest: ChaCha Passed Monte Carlo KAT test..");
				delete stm1;

				Salsa20* stm2 = new Salsa20();
				CompareStmSimd(stm2);
				OnProgress("ParallelModeTest: Salsa Passed Parallel Intrinsics Integrity tests..");
				CompareStmKat(stm2, m_katExpected[4]);
				OnProgress("ParallelModeTest: Salsa Passed Monte Carlo KAT test..");
				delete stm2;

				OnProgress("");
			}

			CompareParallelLoop();
			OnProgress("ParallelModeTest: Passed CBC/CFB/CTR/ICM Parallel encryption and decryption looping Integrity tests..");
			CompareParallelOutput();
			OnProgress("ParallelModeTest: Passed CBC/CFB/CTR/ICM Parallel output encryption and decryption tests..");

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

	void ParallelModeTest::CompareAhxSimd()
	{
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
		AHX* eng1 = new AHX();
		RHX* eng2 = new RHX();
		Mode::CTR cpr1(eng1);
		Mode::CTR cpr2(eng2);

		// compare rhx/ahx parallel ctr
		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			smpSze -= (smpSze % cpr1.BlockSize());
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);
			rng.GetBytes(data);
			GetBytes(32, key);
			GetBytes(16, iv);
			CEX::Common::KeyParams keyParam(key, iv);

			cpr1.ParallelBlockSize() = cpr1.ParallelMinimumSize() * cpr1.ProcessorCount();
			cpr1.Initialize(true, keyParam);
			cpr1.IsParallel() = true;
			blockSize = cpr1.ParallelBlockSize();
			Transform1(&cpr1, data, blockSize, enc1);

			cpr2.ParallelBlockSize() = cpr2.ParallelMinimumSize() * cpr2.ProcessorCount();
			cpr2.Initialize(true, keyParam);
			cpr2.IsParallel() = true;
			blockSize = cpr2.ParallelBlockSize();
			Transform1(&cpr2, data, blockSize, enc2);

			if (enc1 != enc2)
				throw std::string("Parallel CTR: Encrypted output is not equal!");
		}

		Mode::CBC cpr3(eng1);
		Mode::CBC cpr4(eng2);

		// compare rhx/ahx cbc
		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			smpSze -= (smpSze % cpr1.BlockSize());
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
			BlockEncrypt(&cpr3, data, 0, enc1, 0);

			cpr4.Initialize(true, keyParam);
			cpr4.IsParallel() = false;
			blockSize = cpr4.BlockSize();
			BlockEncrypt(&cpr4, data, 0, enc2, 0);

			if (enc1 != enc2)
				throw std::string("CBC: Encrypted output is not equal!");

			cpr3.Initialize(false, keyParam);
			BlockDecrypt(&cpr3, enc1, 0, dec, 0);

			if (dec != data)
				throw std::string("CBC: Decrypted output is not equal!");

			cpr4.Initialize(false, keyParam);
			BlockDecrypt(&cpr4, enc2, 0, dec, 0);

			if (dec != data)
				throw std::string("CBC: Decrypted output is not equal!");
		}

		delete eng1;
		delete eng2;
	}

	void ParallelModeTest::CompareBcrKat(IBlockCipher* Engine, std::vector<byte> Expected)
	{
		size_t blkSize = 1024;
		std::vector<byte> data(blkSize);
		std::vector<byte> enc(blkSize);
		std::vector<byte> key(32);
		std::vector<byte> iv(16);

		data[0] = 128;
		for (uint8_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (uint8_t i = 0; i < iv.size(); ++i)
			iv[i] = i;

		CEX::Common::KeyParams keyParam(key, iv);
		Mode::CTR cipher(Engine);
		cipher.ParallelBlockSize() = blkSize;
		// parallel w/ intrinsics (if available)
		cipher.Initialize(true, keyParam);
		cipher.IsParallel() = true;
		cipher.ParallelBlockSize() = blkSize;
		Transform1(&cipher, data, data.size(), enc);

		while (enc.size() > 32)
			enc = TestUtils::Reduce(enc);

		if (enc != Expected)
			throw std::string("ParallelModeTest: Failed Kat comparison test!");
	}

	void ParallelModeTest::CompareBcrSimd(IBlockCipher* Engine)
	{
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
			Mode::CTR cipher(Engine);
			cipher.ParallelBlockSize() = cipher.ParallelMinimumSize() * cipher.ProcessorCount();
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
	}

	void ParallelModeTest::CompareCbcDecrypt(IBlockCipher* Engine1, IBlockCipher* Engine2)
	{
		std::vector<byte> data;
		std::vector<byte> dec1;
		std::vector<byte> dec2;
		std::vector<byte> key(32);
		std::vector<byte> iv(16);
		CEX::Prng::CSPPrng rng;

#if defined(STAT_INP)
		size_t blkSize = 4096;
		data.resize(blkSize);
		dec1.resize(blkSize);
		dec2.resize(blkSize);
		data[0] = 128;
		for (uint8_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (uint8_t i = 0; i < iv.size(); ++i)
			iv[i] = i;
		CEX::Common::KeyParams keyParam(key, iv);
#else
		data.reserve(MAX_ALLOC);
		dec1.reserve(MAX_ALLOC);
		dec2.reserve(MAX_ALLOC);
		GetBytes(32, key);
		GetBytes(16, iv);
		CEX::Common::KeyParams keyParam(key, iv);
#endif

		Mode::CBC cipher1(Engine1);
		Mode::CBC cipher2(Engine2);

		// compare to sequential decryption output
		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher1.ParallelMinimumSize(), (uint)cipher1.ParallelBlockSize());
			smpSze -= (smpSze % cipher1.BlockSize());
			//smpSze = 38176;
			data.resize(smpSze);
			dec1.resize(smpSze);
			dec2.resize(smpSze);
			rng.GetBytes(data);

			// standard mode
			cipher1.Initialize(false, keyParam);
			cipher1.IsParallel() = false;
			Transform1(&cipher1, data, cipher1.BlockSize(), dec1);

			// parallel + intrinsics
			cipher2.ParallelBlockSize() = cipher2.ParallelMinimumSize();
			cipher2.Initialize(false, keyParam);
			cipher2.IsParallel() = true;
			Transform1(&cipher2, data, cipher2.ParallelBlockSize(), dec2);

			if (dec1 != dec2)
				throw std::string("ParallelModeTest: Failed CBC decryption test!");
		}

		// decryption output integrity
		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher1.ParallelMinimumSize(), (uint)cipher1.ParallelBlockSize());
			smpSze -= (smpSze % cipher1.ParallelMinimumSize());
			data.resize(smpSze);
			dec1.resize(smpSze);
			dec2.resize(smpSze);
			rng.GetBytes(data);

			// standard mode encrypt
			cipher1.Initialize(true, keyParam);
			cipher1.IsParallel() = false;
			Transform1(&cipher1, data, cipher1.BlockSize(), dec1);

			// parallel decrypt
			cipher2.ParallelBlockSize() = smpSze;
			cipher2.Initialize(false, keyParam);
			cipher2.IsParallel() = true;
			Transform1(&cipher2, dec1, smpSze, dec2);

			if (data != dec2)
				throw std::string("ParallelModeTest: Failed CBC decryption test!");
		}
	}

	void ParallelModeTest::CompareCbcWide(IBlockCipher* Engine)
	{
		const size_t BLK64 = 64;
		const size_t BLK128 = 128;

		std::vector<byte> data;
		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> key(32);
		std::vector<byte> iv64(BLK64);
		std::vector<byte> iv128(BLK128);
		CEX::Prng::CSPPrng rng;

#if defined(STAT_INP)
		size_t blkSize = 4096;
		data.resize(blkSize);
		enc.resize(blkSize);
		dec.resize(blkSize);
		data[0] = 128;
		for (uint8_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (uint8_t i = 0; i < iv128.size(); ++i)
			iv128[i] = i;
		CEX::Common::KeyParams keyParam(key, iv128);
#else
		data.reserve(MAX_ALLOC);
		enc.reserve(MAX_ALLOC);
		dec.reserve(MAX_ALLOC);
		rng.GetBytes(key);
		rng.GetBytes(iv128);
		CEX::Common::KeyParams keyParam(key, iv128);
#endif

		Mode::CBC cipher(Engine);

		// test sequential 128 wide block
		cipher.IsParallel() = false;

		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher.ParallelMinimumSize(), (uint)cipher.ParallelBlockSize());
			smpSze -= (smpSze % BLK128);
			data.resize(smpSze);
			enc.resize(smpSze);
			dec.resize(smpSze);
			rng.GetBytes(data);
			const size_t BLKCNT = smpSze / BLK128;

			// encrypt
			cipher.Initialize(true, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform128(data, j * BLK128, enc, j * BLK128);

			// decrypt
			cipher.Initialize(false, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform128(enc, j * BLK128, dec, j * BLK128);

			if (data != dec)
				throw std::string("ParallelModeTest: Failed CBC-WBV integrity test!");
		}


		// test 128 wide with parallel decrypt
		rng.GetBytes(iv128);
		keyParam.IV() = iv128;

		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher.ParallelMinimumSize(), (uint)cipher.ParallelBlockSize());
			smpSze -= (smpSze % BLK128);
			data.resize(smpSze);
			enc.resize(smpSze);
			dec.resize(smpSze);
			rng.GetBytes(data);
			const size_t BLKCNT = smpSze / BLK128;

			// encrypt
			cipher.Initialize(true, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform128(data, j * BLK128, enc, j * BLK128);

			// decrypt
			const size_t PRLMIN = cipher.ParallelMinimumSize();
			cipher.ParallelBlockSize() = PRLMIN;
			cipher.IsParallel() = true;
			cipher.Initialize(false, keyParam);
			size_t offset = 0;

			while (offset != smpSze)
			{
				cipher.Transform128(enc, offset, dec, offset);
				if (smpSze - offset >= PRLMIN)
					offset += PRLMIN;
				else
					offset = smpSze;
			}

			if (data != dec)
				throw std::string("ParallelModeTest: Failed CBC-WBV parallel decryption test!");
		}


		// test sequential 64 wide block
		rng.GetBytes(iv64);
		keyParam.IV() = iv64;
		cipher.IsParallel() = false;

		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher.ParallelMinimumSize(), (uint)cipher.ParallelBlockSize());
			smpSze -= (smpSze % BLK64);
			data.resize(smpSze);
			enc.resize(smpSze);
			dec.resize(smpSze);
			rng.GetBytes(data);
			const size_t BLKCNT = smpSze / BLK64;

			// encrypt
			cipher.Initialize(true, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform64(data, j * BLK64, enc, j * BLK64);

			// decrypt
			cipher.Initialize(false, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform64(enc, j * BLK64, dec, j * BLK64);

			if (data != dec)
				throw std::string("ParallelModeTest: Failed CBC-WBV integrity test!");
		}


		// test 64 wide with parallel decrypt
		rng.GetBytes(iv64);
		keyParam.IV() = iv64;
		cipher.IsParallel() = false;

		for (size_t i = 0; i < TEST_LOOPS; ++i)
		{
			size_t smpSze = (size_t)rng.Next((uint)cipher.ParallelMinimumSize(), (uint)cipher.ParallelBlockSize());
			smpSze -= (smpSze % BLK64);
			data.resize(smpSze);
			enc.resize(smpSze);
			dec.resize(smpSze);
			rng.GetBytes(data);
			const size_t BLKCNT = smpSze / BLK64;

			// encrypt
			cipher.Initialize(true, keyParam);
			for (size_t j = 0; j < BLKCNT; ++j)
				cipher.Transform64(data, j * BLK64, enc, j * BLK64);

			// decrypt
			const size_t PRLMIN = cipher.ParallelMinimumSize();
			cipher.ParallelBlockSize() = PRLMIN;
			cipher.IsParallel() = true;
			cipher.Initialize(false, keyParam);

			size_t offset = 0;
			while (offset != smpSze)
			{
				cipher.Transform64(enc, offset, dec, offset);
				if (smpSze - offset >= PRLMIN)
					offset += PRLMIN;
				else
					offset = smpSze;
			}

			if (data != dec)
				throw std::string("ParallelModeTest: Failed CBC-WBV parallel decryption test!");
		}
	}

	void ParallelModeTest::CompareParallelLoop()
	{
		CEX::Prng::CSPPrng rng;
		std::vector<byte> data(0);
		std::vector<byte> dec1(0);
		std::vector<byte> enc1(0);
		std::vector<byte> enc2(0);
		std::vector<byte> key(32);
		std::vector<byte> iv(16);

		rng.GetBytes(iv);
		rng.GetBytes(key);
		CEX::Common::KeyParams kp(key, iv);

		// CTR
		OnProgress("***Testing Block Cipher Modes***..");

		{
			RHX* eng = new RHX();
			Mode::CTR cipher(eng);

			for (size_t i = 0; i < TEST_LOOPS; i++)
			{
				size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				enc1.resize(smpSze);
				enc2.resize(smpSze);
				dec1.resize(smpSze);
				data.resize(smpSze);
				rng.GetBytes(data);

				cipher.Initialize(true, kp);
				BlockCTR(&cipher, data, 0, enc1, 0);

				cipher.Initialize(true, kp);
				ParallelCTR(&cipher, data, 0, enc2, 0);

				if (enc1[i] != enc2[i])
					throw std::string("ParallelModeTest: Encrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				BlockCTR(&cipher, enc1, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				ParallelCTR(&cipher, enc2, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CTR Mode tests..");

		{
			RHX* eng = new RHX();
			Mode::ICM cipher(eng);

			for (size_t i = 0; i < TEST_LOOPS; i++)
			{
				size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				enc1.resize(smpSze);
				enc2.resize(smpSze);
				dec1.resize(smpSze);
				data.resize(smpSze);
				rng.GetBytes(data);

				cipher.Initialize(true, kp);
				BlockCTR(&cipher, data, 0, enc1, 0);

				cipher.Initialize(true, kp);
				ParallelCTR(&cipher, data, 0, enc2, 0);

				if (enc1[i] != enc2[i])
					throw std::string("ParallelModeTest: Encrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				BlockCTR(&cipher, enc1, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");

				cipher.Initialize(false, kp);
				ParallelCTR(&cipher, enc2, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed ICM Mode tests..");

		// CBC
		{
			RHX* eng = new RHX();
			Mode::CBC cipher(eng);
			cipher.IsParallel() = false;

			for (size_t i = 0; i < TEST_LOOPS; i++)
			{
				size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				smpSze -= (smpSze % cipher.BlockSize());
				enc1.resize(smpSze);
				dec1.resize(smpSze);
				data.resize(smpSze);
				rng.GetBytes(data);

				// encrypt the array locally
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, data, 0, enc1, 0);
				// decrypt
				cipher.Initialize(false, kp);
				ParallelDecrypt(&cipher, enc1, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CBC Mode tests..");

		// CFB
		{
			RHX* eng = new RHX();
			Mode::CFB cipher(eng);
			cipher.IsParallel() = false;

			for (size_t i = 0; i < TEST_LOOPS; i++)
			{
				size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
				smpSze -= (smpSze % cipher.BlockSize());
				enc1.resize(smpSze);
				dec1.resize(smpSze);
				data.resize(smpSze);
				rng.GetBytes(data);

				// encrypt the array locally
				cipher.Initialize(true, kp);
				BlockEncrypt(&cipher, data, 0, enc1, 0);
				// decrypt
				cipher.Initialize(false, kp);
				ParallelDecrypt(&cipher, enc1, 0, dec1, 0);

				if (dec1 != data)
					throw std::string("ParallelModeTest: Decrypted arrays are not equal!");
			}

			delete eng;
		}
		OnProgress("Passed CFB Mode tests..");
	}

	void ParallelModeTest::CompareParallelOutput()
	{
		// compares sequential and parallel output
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

		// CTR
		{
			AHX* eng = new AHX();
			Mode::CTR cipher(eng);

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

		OnProgress("ParallelModeTest: Passed Parallel CTR encryption and decryption tests");

		// ICM
		{
			AHX* eng = new AHX();
			Mode::ICM cipher(eng);

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
				throw std::string("Parallel ICM: Encrypted output is not equal!");

			// linear 1
			cipher.Initialize(true, keyParam);
			cipher.IsParallel() = false;
			blockSize = cipher.BlockSize();
			Transform1(&cipher, data, blockSize, enc2);

			if (!Test::TestUtils::IsEqual(enc1, enc2))
				throw std::string("Parallel ICM: Encrypted output is not equal!");

			// linear 2
			cipher.Initialize(true, keyParam);
			cipher.IsParallel() = false;
			blockSize = cipher.BlockSize();
			Transform2(&cipher, data, blockSize, enc2);

			if (!Test::TestUtils::IsEqual(enc1, enc2))
				throw std::string("Parallel ICM: Encrypted output is not equal!");

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
				throw std::string("Parallel ICM: Decrypted output is not equal!");

			// linear 1
			cipher.Initialize(false, keyParam);
			cipher.IsParallel() = false;
			blockSize = cipher.BlockSize();
			Transform1(&cipher, enc1, blockSize, dec2);

			if (!Test::TestUtils::IsEqual(dec1, dec2))
				throw std::string("Parallel ICM: Decrypted output is not equal!");

			// linear 2
			cipher.Initialize(false, keyParam);
			cipher.IsParallel() = false;
			blockSize = cipher.BlockSize();
			Transform2(&cipher, enc2, blockSize, dec2);

			if (!Test::TestUtils::IsEqual(dec1, dec2))
				throw std::string("Parallel ICM: Decrypted output is not equal!");

			delete eng;
		}

		if (data != dec1)
			throw std::string("Parallel ICM: Decrypted output is not equal!");
		if (data != dec2)
			throw std::string("Parallel ICM: Decrypted output is not equal!");

		OnProgress("ParallelModeTest: Passed Parallel ICM encryption and decryption tests");

		// CBC
		{
			RHX* eng = new RHX();
			Mode::CBC cipher(eng);

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

		OnProgress("ParallelModeTest: Passed Parallel CBC decryption tests");

		// CFB
		{
			RHX* eng = new RHX();
			Mode::CFB cipher(eng);

			// must be divisible by block size, add padding if required
			GetBytes(2048, data);

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

		OnProgress("ParallelModeTest: Passed Parallel CFB decryption tests");
	}

	void ParallelModeTest::CompareStmKat(IStreamCipher* Engine, std::vector<byte> Expected)
	{
		size_t blkSize = 4096;
		std::vector<byte> data(blkSize);
		std::vector<byte> enc(blkSize);
		std::vector<byte> key(32);
		std::vector<byte> iv(8);
		data[0] = 128;

		for (uint8_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (uint8_t i = 0; i < iv.size(); ++i)
			iv[i] = i;
		CEX::Common::KeyParams keyParam(key, iv);

		// parallel with intrinsics (if available)
		Engine->Initialize(keyParam);
		Engine->IsParallel() = true;
		Engine->ParallelBlockSize() = blkSize;
		Engine->Transform(data, enc);

		while (enc.size() > 32)
			enc = TestUtils::Reduce(enc);

		if (enc != Expected)
			throw std::string("ParallelModeTest: Failed Stream Cipher Kat comparison test!");
	}

	void ParallelModeTest::CompareStmSimd(IStreamCipher* Engine)
	{
		std::vector<byte> data;
		std::vector<byte> dec;
		std::vector<byte> enc1;
		std::vector<byte> enc2;
		std::vector<byte> key(32);
		std::vector<byte> iv(8);
		CEX::Prng::CSPPrng rng;

		data.reserve(MAX_ALLOC);
		enc1.reserve(MAX_ALLOC);
		enc2.reserve(MAX_ALLOC);

#if defined(STAT_INP)
		for (size_t i = 0; i < key.size(); ++i)
			key[i] = i;
		for (size_t i = 0; i < iv.size(); ++i)
			iv[i] = i;
#endif

		for (size_t i = 0; i < 100; ++i)
		{
#if !defined(STAT_INP)
			size_t smpSze = rng.Next(MIN_ALLOC, MAX_ALLOC);
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);
			rng.GetBytes(data);
			GetBytes(32, key);
			GetBytes(8, iv);
#else
			size_t smpSze = MIN_ALLOC * 8;
			data.resize(smpSze);
			dec.resize(smpSze);
			enc1.resize(smpSze);
			enc2.resize(smpSze);
#endif
			CEX::Common::KeyParams keyParam(key, iv);
			Engine->ParallelBlockSize() = Engine->ParallelMinimumSize() * Engine->ProcessorCount();

			// sequential
			Engine->Initialize(keyParam);
			Engine->IsParallel() = false;
			Engine->Transform(data, enc2);

			// parallel with intrinsics (if available)
			Engine->Initialize(keyParam);
			Engine->IsParallel() = true;
			Engine->Transform(data, enc1);

			if (enc1 != enc2)
				throw std::string("Parallel Stream: Encrypted output is not equal!");

			// decrypt
			Engine->Initialize(keyParam);
			Engine->IsParallel() = true;
			Engine->Transform(enc1, dec);

			if (dec != data)
				throw std::string("Parallel Stream: Decrypted output is not equal!");
		}
	}

	//~~~Helpers~~~//

	void ParallelModeTest::BlockCTR(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
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

	void ParallelModeTest::BlockDecrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = Input.size() - InOffset;
		size_t count = 0;
		Cipher->IsParallel() = false;

		while (count != inpSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}
	}

	void ParallelModeTest::BlockEncrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->BlockSize();
		const size_t inpSize = Input.size() - InOffset;
		size_t count = 0;
		Cipher->IsParallel() = false;

		while (count != inpSize)
		{
			Cipher->Transform(Input, InOffset, Output, OutOffset);
			InOffset += blkSize;
			OutOffset += blkSize;
			count += blkSize;
		}
	}

	void ParallelModeTest::GetBytes(size_t Size, std::vector<byte> &Output)
	{
		Output.resize(Size, 0);
		CEX::Seed::CSPRsg rng;
		rng.GetBytes(Output);
	}

	void ParallelModeTest::Initialize()
	{
		// vectors derived from sequential reduction loop, compared to intrinsic output
		const char* expected[5] =
		{
			("c07d97f791abc487129f47a6d29f66992d5994fbb3b8b11f3f0e8f479aa353de"), //rijndael
			("c3d46cf0bfebf80589bb65fef3fab9fc8993f352500a9d71483d4382aab695a6"), //serpent
			("94e6761273d83ce4f775d21eb37e88fb848b77f16791fa805a64e5750c0684b9"), //twofish
			("4036af67c0a150992cc6ff649a3204e1e0d5ed3baa822d7b284ce4f7bd0302a5"), //chacha
			("37287bc9b4706c9450c943cf99ae3d685878f5e906546f36b53adab35f8e91cb")  //salsa
		};
		HexConverter::Decode(expected, 5, m_katExpected);

		m_processorCount = CEX::Utility::ParallelUtils::ProcessorCount();
		try
		{
			CEX::Common::CpuDetect detect;
			m_hasAESNI = detect.HasAES();
			m_hasSSE = detect.HasMinIntrinsics();
		}
		catch (...)
		{
			m_hasAESNI = false;
			m_hasSSE = false;
		}
	}

	void ParallelModeTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void ParallelModeTest::ParallelCTR(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->ParallelMinimumSize();
		const size_t inpSize = (Input.size() - InOffset);
		const size_t alnSize = ((inpSize / blkSize) * blkSize);
		size_t count = 0;

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
			size_t cnkSize = inpSize - alnSize;
			std::vector<byte> inpBuffer(cnkSize);
			memcpy(&inpBuffer[0], &Input[InOffset], cnkSize);
			std::vector<byte> outBuffer(cnkSize);
			Cipher->Transform(inpBuffer, outBuffer);
			memcpy(&Output[OutOffset], &outBuffer[0], cnkSize);
		}
	}

	void ParallelModeTest::ParallelDecrypt(Mode::ICipherMode* Cipher, const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset)
	{
		const size_t blkSize = Cipher->ParallelMinimumSize();
		const size_t inpSize = (Input.size() - InOffset);
		const size_t alnSize = ((inpSize / blkSize) * blkSize);
		size_t count = 0;

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
			BlockDecrypt(Cipher, Input, InOffset, Output, OutOffset);
	}

	void ParallelModeTest::Transform1(Mode::ICipherMode* Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output)
	{
		Output.resize(Input.size(), 0);

		// use the offset methods
		size_t blocks = Input.size() / BlockSize;

		for (size_t i = 0; i < blocks; ++i)
			Cipher->Transform(Input, i * BlockSize, Output, i * BlockSize);

		if (blocks * BlockSize < Input.size())
		{
			std::string name = Cipher->Name();
			if (Cipher->Enumeral() == Mode::CipherModes::CTR)
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
				Cipher->Transform(Input, blocks * BlockSize, Output, blocks * BlockSize);
			}
		}
	}

	void ParallelModeTest::Transform2(Mode::ICipherMode* Cipher, std::vector<byte> &Input, size_t BlockSize, std::vector<byte> &Output)
	{
		Output.resize(Input.size(), 0);

		// buffered, slower
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