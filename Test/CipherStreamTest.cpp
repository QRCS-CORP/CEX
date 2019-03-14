#include "CipherStreamTest.h"
#include "../CEX/BlockCipherExtensions.h"
#include "../CEX/CTR.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/FileStream.h"
#include "../CEX/ICM.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/OFB.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace Cipher::Block::Mode;
	using Utility::IntegerTools;
	using IO::MemoryStream;
	using Enumeration::PaddingModes;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey; 

	const std::string CipherStreamTest::CLASSNAME = "CipherStreamTest";
	const std::string CipherStreamTest::DESCRIPTION = "CipherStream Processer Tests.";
	const std::string CipherStreamTest::SUCCESS = "SUCCESS! CipherStream tests have executed succesfully.";

	CipherStreamTest::CipherStreamTest()
		:
		m_processorCount(1),
		m_progressEvent()
	{
	}

	CipherStreamTest::~CipherStreamTest()
	{
	}

	const std::string CipherStreamTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CipherStreamTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CipherStreamTest::Run()
	{
		try
		{
			// Not tested: used for internal testing
			//FileStreamTest();

			CipherStream* cfbm = new CipherStream(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::CFB, PaddingModes::ESP);
			CipherStream* cbcm = new CipherStream(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::ESP);
			CipherStream* ctrm = new CipherStream(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::CTR, PaddingModes::None);
			CipherStream* icmm = new CipherStream(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::ICM, PaddingModes::None);
			CipherStream* ofbm = new CipherStream(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::OFB, PaddingModes::ESP);

			Memory();
			OnProgress(std::string("Passed MemoryStream self test.. "));

			Parallel(cfbm);
			OnProgress(std::string("Passed CFB Parallel tests.."));

			Parallel(cbcm);
			OnProgress(std::string("Passed CBC Parallel tests.."));

			Parallel(ctrm);
			OnProgress(std::string("Passed CTR Parallel tests.."));

			Parallel(icmm);
			OnProgress(std::string("Passed ICM Parallel tests.."));

			Parallel(ofbm);
			OnProgress(std::string("Passed OFB Parallel tests.."));

			Parameters();
			OnProgress(std::string("Passed Cipher Parameters tests.."));

			Stress(cfbm);
			OnProgress(std::string("Passed CFB stress tests.."));

			Stress(cbcm);
			OnProgress(std::string("Passed CBC stress tests.."));

			Stress(ctrm);
			OnProgress(std::string("Passed CTR stress tests.."));

			Stress(icmm);
			OnProgress(std::string("Passed ICM stress tests.."));

			Stress(ofbm);
			OnProgress(std::string("Passed OFB stress tests.."));

			delete cfbm;
			delete cbcm;
			delete ctrm;
			delete icmm;
			delete ofbm;

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

	void CipherStreamTest::File()
	{
		using namespace CEX::IO;

		const std::string INPFILE = "C:\\Users\\John\\Documents\\Tests\\test1.txt"; // input
		const std::string ENCFILE = "C:\\Users\\John\\Documents\\Tests\\test2.txt"; // empty
		const std::string DECFILE = "C:\\Users\\John\\Documents\\Tests\\test3.txt"; // empty
		std::vector<byte> key(32, 1);
		std::vector<byte> iv(16, 2);
		std::vector<byte> data(1025, 3);

		// initialize the cipher and key container
		CipherStream cs(BlockCiphers::AES, BlockCipherExtensions::None, CipherModes::CBC, PaddingModes::ESP);
		SymmetricKey kp(key, iv);

		// encrypt the file in-place
		FileStream fIn1(INPFILE, FileStream::FileAccess::Read);
		FileStream fOut1(INPFILE, FileStream::FileAccess::ReadWrite);
		cs.Initialize(true, kp);
		cs.Write(&fIn1, &fOut1);
		fIn1.Close();
		fOut1.Close();

		// decrypt the file in-place
		FileStream fIn2(INPFILE, FileStream::FileAccess::Read);
		FileStream fOut2(INPFILE, FileStream::FileAccess::ReadWrite);
		cs.Initialize(false, kp);
		cs.Write(&fIn2, &fOut2);
		fIn2.Close();
		fOut2.Close();

		// encrypt and copy to a new file
		FileStream fIn3(INPFILE, FileStream::FileAccess::Read);
		FileStream fOut3(ENCFILE, FileStream::FileAccess::ReadWrite);
		cs.Initialize(true, kp);
		cs.Write(&fIn3, &fOut3);
		fIn3.Close();
		fOut3.Close();

		// decrypt and copy to a new file
		FileStream fIn4(ENCFILE, FileStream::FileAccess::Read);
		FileStream fOut4(DECFILE, FileStream::FileAccess::ReadWrite);
		cs.Initialize(false, kp);
		cs.Write(&fIn4, &fOut4);
		fIn4.Close();
		fOut4.Close();
	}

	void CipherStreamTest::Parallel(CipherStream* Cipher)
	{
		std::vector<byte> iv(16);
		std::vector<byte> key(32);
		std::vector<byte> dec(0);
		std::vector<byte> enc(0);
		std::vector<byte> pln(0);
		SecureRandom rng;

		rng.Generate(iv);
		rng.Generate(key);
		SymmetricKey kp(key, iv);

		for (size_t i = 0; i < TEST_CYCLES; i++)
		{
			const uint SMPLEN = rng.NextUInt32(static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4), static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize()));
			dec.clear();
			enc.clear();
			pln.clear();
			dec.resize(SMPLEN);
			enc.resize(SMPLEN);
			pln.resize(SMPLEN);
			rng.Generate(pln);

			MemoryStream mpln(pln);
			MemoryStream menc;
			MemoryStream mdec;

			// compare encryption output

			// stream linear mode
			Cipher->ParallelProfile().IsParallel() = false;
			// memorystream interface
			Cipher->Initialize(true, kp);
			Cipher->Write(&mpln, &menc);

			// byte-array interface
			Cipher->Initialize(true, kp);
			Cipher->Write(pln, 0, enc, 0);

			if (menc.ToArray() != enc)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Decrypted arrays are not equal! -CM1"));
			}

			// decrypt in parallel

			// stream interface, parallel mode
			Cipher->ParallelProfile().IsParallel() = true;
			menc.Seek(0, IO::SeekOrigin::Begin);
			Cipher->Initialize(false, kp);
			Cipher->Write(&menc, &mdec);

			if (mdec.ToArray() != pln)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Decrypted arrays are not equal! -CM2"));
			}

			// byte array interface
			dec.resize(enc.size());
			Cipher->Initialize(false, kp);
			Cipher->Write(enc, 0, dec, 0);

			if (dec != pln)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Decrypted arrays are not equal! -CM3"));
			}
		}
	}

	void CipherStreamTest::Memory()
	{
		std::vector<byte> data(255);
		std::vector<byte> data2(255);
		MemoryStream ms;
		size_t i;
		byte x;

		ms.WriteByte(0xA);
		ms.WriteByte(0xB);
		ms.WriteByte(0xC);

		for (i = 0; i < 255; i++)
		{
			data[i] = static_cast<byte>(i);
		}
		ms.Write(data, 0, 255);

		ms.Seek(0, IO::SeekOrigin::Begin);

		x = ms.ReadByte();
		if (x != 0xA)
		{
			throw;
		}

		x = ms.ReadByte();
		if (x != 0xB)
		{
			throw;
		}

		x = ms.ReadByte();
		if (x != 0xC)
		{
			throw;
		}

		ms.Read(data2, 0, 255);
		if (data2 != data)
		{
			throw;
		}
	}

	void CipherStreamTest::Parameters()
	{
		std::vector<byte> iv(16);
		std::vector<byte> key(32);
		std::vector<byte> dec(1);
		std::vector<byte> enc(1);
		std::vector<byte> pln(1);
		MemoryStream mdec;
		MemoryStream mpln;
		MemoryStream menc;
		CipherStream cs;

		SecureRandom rng;
		rng.Generate(iv);
		rng.Generate(key);
		rng.Generate(pln);
		SymmetricKey kp(key, iv);

		// 1 byte test
		cs.Initialize(true, kp);
		cs.Write(pln, 0, enc, 0);
	
		cs.Initialize(false, kp);
		cs.Write(enc, 0, dec, 0);

		if (dec != pln)
		{
			throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP1"));
		}

		// 1 byte with stream
		cs.Initialize(true, kp);
		rng.Generate(pln);
		mpln.Write(pln, 0, pln.size());
		mpln.Seek(0, IO::SeekOrigin::Begin);

		cs.Write(&mpln, &menc);

		cs.Initialize(false, kp);
		menc.Seek(0, IO::SeekOrigin::Begin);
		cs.Write(&menc, &mdec);

		if (mdec.ToArray() != pln)
		{
			throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP2"));
		}

		// partial block test
		dec.clear();
		enc.clear();
		pln.clear();
		dec.resize(15);
		enc.resize(15);
		pln.resize(15);

		rng.Generate(pln);

		cs.Initialize(true, kp);
		cs.Write(pln, 0, enc, 0);

		cs.Initialize(false, kp);
		cs.Write(enc, 0, dec, 0);

		if (dec != pln)
		{
			throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP3"));
		}

		// partial block with stream
		dec.resize(15);
		enc.resize(15);

		cs.Initialize(true, kp);
		mpln.Reset(); 
		mpln.Write(pln, 0, pln.size());
		mpln.Seek(0, IO::SeekOrigin::Begin);
		menc.Reset();

		cs.Write(&mpln, &menc);

		cs.Initialize(false, kp);
		mdec.Reset();
		menc.Seek(0, IO::SeekOrigin::Begin);
		cs.Write(&menc, &mdec);

		if (mdec.ToArray() != pln)
		{
			throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP4"));
		}

		// random block sizes with byte arrays
		for (size_t i = 0; i < 10; i++)
		{
			const uint SMPLEN = rng.NextUInt32(static_cast<uint>(cs.ParallelProfile().ParallelBlockSize() * 4), static_cast<uint>(cs.ParallelProfile().ParallelBlockSize()));

			dec.clear();
			enc.clear();
			pln.clear();
			dec.resize(SMPLEN);
			enc.resize(SMPLEN);
			pln.resize(SMPLEN);

			rng.Generate(pln);

			cs.Initialize(true, kp);
			cs.Write(pln, 0, enc, 0);

			cs.Initialize(false, kp);
			cs.Write(enc, 0, dec, 0);

			if (dec != pln)
			{
				throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP5"));
			}
		}

		// random block sizes with stream
		for (size_t i = 0; i < 10; i++)
		{
			const uint SMPLEN = rng.NextUInt32(static_cast<uint>(cs.ParallelProfile().ParallelBlockSize() * 4), static_cast<uint>(cs.ParallelProfile().ParallelBlockSize()));
			dec.clear();
			enc.clear();
			pln.clear();
			dec.resize(SMPLEN);
			enc.resize(SMPLEN);
			pln.resize(SMPLEN);

			rng.Generate(pln);

			cs.Initialize(true, kp);
			mpln.Reset();
			mpln.Write(pln, 0, pln.size());
			mpln.Seek(0, IO::SeekOrigin::Begin);
			menc.Reset();
			cs.Write(&mpln, &menc);

			cs.Initialize(false, kp);
			mdec.Reset();
			menc.Seek(0, IO::SeekOrigin::Begin);
			cs.Write(&menc, &mdec);

			if (mdec.ToArray() != pln)
			{
				throw TestException(std::string("Parameters"), cs.Name(), std::string("Encrypted arrays are not equal! -CP6"));
			}
		}
	}

	void CipherStreamTest::Stress(CipherStream* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXM_ALLOC);
		inp.reserve(MAXM_ALLOC);
		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			const size_t ALNLEN = MSGLEN - (MSGLEN % 16);

			cpt.resize(ALNLEN);
			inp.resize(ALNLEN);
			otp.resize(ALNLEN);

			IntegerTools::Fill(inp, 0, ALNLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Write(inp, 0, cpt, 0);

			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Write(cpt, 0, otp, 0);

			if (!IntegerTools::Compare(inp, 0, otp, 0, otp.size()))
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -TS1"));
			}
		}
	}

	//~~~Helpers~~~//

	void CipherStreamTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
