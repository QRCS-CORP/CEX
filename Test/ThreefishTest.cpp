#include "ThreefishTest.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/Threefish.h"
#include "../CEX/Threefish256.h"
#include "../CEX/Threefish512.h"
#include "../CEX/Threefish1024.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntUtils;
	using Utility::MemUtils;
	using Prng::SecureRandom;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;
	using Cipher::Symmetric::Stream::Threefish;
	using Cipher::Symmetric::Stream::Threefish256;
	using Cipher::Symmetric::Stream::Threefish512;
	using Cipher::Symmetric::Stream::Threefish1024;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ThreefishTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ThreeFish stream cipher.";
	const std::string ThreefishTest::FAILURE = "ThreefishTest: Test Failure!";
	const std::string ThreefishTest::SUCCESS = "SUCCESS! All Threefish tests have executed succesfully.";

	//~~~Constructor~~~//

	ThreefishTest::ThreefishTest()
		:
		m_code(0),
		m_expected(0),
		m_key(0),
		m_message(0),
		m_monte(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	ThreefishTest::~ThreefishTest()
	{
		IntUtils::ClearVector(m_code);
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_message);
		IntUtils::ClearVector(m_monte);
		IntUtils::ClearVector(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string ThreefishTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ThreefishTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string ThreefishTest::Run()
	{
		try
		{
			// threefish256 standard and authenticated variants

			Threefish256* tsx256h256 = new Threefish256(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish256* tsx256h512 = new Threefish256(Enumeration::StreamAuthenticators::HMACSHA512);
			Threefish256* tsx256k256 = new Threefish256(Enumeration::StreamAuthenticators::KMAC256);
			Threefish256* tsx256k512 = new Threefish256(Enumeration::StreamAuthenticators::KMAC512);
			Threefish256* tsx256s = new Threefish256();

			Authentication(tsx256h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 MAC authentication tests.."));

			CompareP256();
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 permutation variants equivalence test.."));

			Exception(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 exception handling tests.."));
			
			Finalization(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[12]);
			Finalization(tsx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1], m_code[13]);
			Finalization(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2], m_code[14]);
			Finalization(tsx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[3], m_code[15]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer finalization tests."));

			// check each variant for identical cipher-text output
			Kat(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			// non-authenticated threefish256
			Kat(tsx256s, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer cipher tests.."));

			// check each variant for identical cipher-text output
			MonteCarlo(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(tsx256h512, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(tsx256k512, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			// non-authenticated threefish256
			MonteCarlo(tsx256s, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 monte carlo tests.."));

			Parallel(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 parallel to sequential equivalence test.."));

			Stress(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 stress tests.."));

			// original mac vectors
			Verification(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(tsx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1]);
			Verification(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2]);
			Verification(tsx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer authentication tests.."));

			delete tsx256h256;
			delete tsx256h512;
			delete tsx256k256;
			delete tsx256k512;
			delete tsx256s;

			// threefish512 standard and authenticated variants

			Threefish512* tsx512h256 = new Threefish512(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish512* tsx512h512 = new Threefish512(Enumeration::StreamAuthenticators::HMACSHA512);
			Threefish512* tsx512k256 = new Threefish512(Enumeration::StreamAuthenticators::KMAC256);
			Threefish512* tsx512k512 = new Threefish512(Enumeration::StreamAuthenticators::KMAC512);
			Threefish512* tsx512s = new Threefish512();

			Authentication(tsx512h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 permutation variants equivalence test.."));

			Exception(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 exception handling tests.."));

			// check each variant for identical cipher-text output
			Kat(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			// non-authenticated threefish512
			Kat(tsx512s, m_message[1], m_key[1], m_nonce[1], m_expected[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer cipher tests.."));

			Finalization(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[4], m_code[16]);
			Finalization(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[5], m_code[17]);
			Finalization(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[6], m_code[18]);
			Finalization(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[7], m_code[19]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer finalization tests."));


			// check each variant for identical cipher-text output
			MonteCarlo(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			// non-authenticated threefish512
			MonteCarlo(tsx512s, m_message[1], m_key[1], m_nonce[1], m_monte[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 monte carlo tests.."));

			Parallel(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 parallel to sequential equivalence test.."));

			Stress(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 stress tests.."));

			// original mac vectors
			Verification(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[4]);
			Verification(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[5]);
			Verification(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[6]);
			Verification(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[7]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer authentication tests.."));

			delete tsx512h256;
			delete tsx512h512;
			delete tsx512k256;
			delete tsx512k512;
			delete tsx512s;

			// threefish1024 standard and authenticated variants

			Threefish1024* tsx1024h256 = new Threefish1024(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish1024* tsx1024h512 = new Threefish1024(Enumeration::StreamAuthenticators::HMACSHA512);
			Threefish1024* tsx1024k256 = new Threefish1024(Enumeration::StreamAuthenticators::KMAC256);
			Threefish1024* tsx1024k512 = new Threefish1024(Enumeration::StreamAuthenticators::KMAC512);
			Threefish1024* tsx1024s = new Threefish1024();

			Authentication(tsx1024h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 permutation variants equivalence test.."));

			Exception(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 exception handling tests.."));

			Finalization(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[8], m_code[20]);
			Finalization(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[9], m_code[21]);
			Finalization(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[10], m_code[22]);
			Finalization(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[11], m_code[23]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			// check each variant for identical cipher-text output
			Kat(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			// non-authenticated threefish1024
			Kat(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_expected[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer cipher tests.."));

			// check each variant for identical cipher-text output
			MonteCarlo(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			// non-authenticated threefish1024
			MonteCarlo(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_monte[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 monte carlo tests.."));

			Parallel(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 parallel to sequential equivalence test.."));

			Stress(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 stress tests.."));

			// original mac vectors
			Verification(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[8]);
			Verification(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[9]);
			Verification(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[10]);
			Verification(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[11]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			delete tsx1024h256;
			delete tsx1024h512;
			delete tsx1024k256;
			delete tsx1024k512;
			delete tsx1024s;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + ex.Origin(), ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" Unknown Error")));
		}
	}

	void ThreefishTest::Authentication(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t TAGLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> code(TAGLEN);
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;
		size_t j;

		cpt.reserve(MAXSMP + TAGLEN);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		// test-1: compare large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(MSGLEN + TAGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			SymmetricKey kp(key);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// write mac to output stream
			Cipher->Finalize(cpt, MSGLEN, TAGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
			// write mac to temp array
			Cipher->Finalize(code, 0, TAGLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(code, 0, cpt, MSGLEN, TAGLEN))
			{
				throw TestException(std::string("Authentication: MAC output is not equal! -TA2"));
			}

			for (j = 0; j < MSGLEN; ++j)
			{
				if (inp[j] != otp[j])
				{
					throw TestException(std::string("Authentication: Cipher output is not equal! -TA3"));
				}
			}
		}
	}

	void ThreefishTest::CompareP256()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 4> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 4> state1;
		std::array<ulong, 4> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 4, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 4 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 4 * sizeof(ulong));

		Threefish::PemuteP256C(key, counter, tweak, state1, 72);
		Threefish::PemuteR72P256U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("Permutation256: Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 16> state3;

		MemUtils::Clear(state3, 0, 16 * sizeof(ulong));

		Threefish::PemuteP4x256H(key, counter8, tweak, state3, 72);

		for (size_t i = 0; i < 16; i += 4)
		{
			for (size_t j = 0; j < 4; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation256: Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 32> state4;

		MemUtils::Clear(state4, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter16, tweak, state4, 72);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation256: Permutation output is not equal! -TP3"));
				}
			}
		}

#endif
	}

	void ThreefishTest::CompareP512()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 8> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 8> state1;
		std::array<ulong, 8> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 8, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 8 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 8 * sizeof(ulong));

		Threefish::PemuteP512C(key, counter, tweak, state1, 96);
		Threefish::PemuteR96P512U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("Permutation512: Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 32> state3;

		MemUtils::Clear(state3, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter8, tweak, state3, 96);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation512: Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 64> state4;

		MemUtils::Clear(state4, 0, 64 * sizeof(ulong));

		Threefish::PemuteP8x512H(key, counter16, tweak, state4, 96);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation512: Permutation output is not equal! -TP3"));
				}
			}
		}

#endif

	}

	void ThreefishTest::CompareP1024()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 16> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 16> state1;
		std::array<ulong, 16> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 16, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 16 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 16 * sizeof(ulong));

		Threefish::PemuteR120P1024U(key, counter, tweak, state2);
		Threefish::PemuteP1024C(key, counter, tweak, state1, 120);

		if (state1 != state2)
		{
			throw TestException(std::string("Permutation1024: Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)
		
		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 64> state3;

		MemUtils::Clear(state3, 0, 64 * sizeof(ulong));

		Threefish::PemuteP4x1024H(key, counter8, tweak, state3, 120);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation1024: Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 128> state4;

		MemUtils::Clear(state4, 0, 128 * sizeof(ulong));

		Threefish::PemuteP8x1024H(key, counter16, tweak, state4, 120);

		for (size_t i = 0; i < 128; ++i)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException(std::string("Permutation1024: Permutation output is not equal! -TP3"));
				}
			}
		}

#endif

	}

	void ThreefishTest::Exception(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Threefish"), std::string("Exception: Exception handling failure! -TE1"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(1);
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Threefish"), std::string("Exception: Exception handling failure! -TE2"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			std::vector<byte> info(ks.InfoSize() + 1);
			SymmetricKey kp(key, nonce, info);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Threefish"), std::string("Exception: Exception handling failure! -TE3"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid finalizer call
		try
		{
			// not initialized
			std::vector<byte> code(16);

			Cipher->Finalize(code, 0, 16);

			throw TestException(std::string("Threefish"), std::string("Exception: Exception handling failure! -TE4"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid parallel options
		try
		{
			std::vector<byte> key(ks.KeySize());
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);
			Cipher->ParallelMaxDegree(9999);

			throw TestException(std::string("Threefish"), std::string("Exception: Exception handling failure! -TE5"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ThreefishTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> code1(TAGLEN);
		std::vector<byte> code2(TAGLEN);
		std::vector<byte> cpt((MSGLEN + TAGLEN) * 2);
		std::vector<byte> otp(MSGLEN * 2);
		SymmetricKey kp(Key, Nonce);

		// encrypt msg 1
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);
		Cipher->Finalize(cpt, MSGLEN, TAGLEN);

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);
		Cipher->Finalize(cpt, (MSGLEN * 2) + TAGLEN, TAGLEN);

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
		Cipher->Finalize(code1, 0, TAGLEN);

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code1, 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF1"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);
		Cipher->Finalize(code2, 0, TAGLEN);

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code2, 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF2"));
		}

		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -TF3"));
		}

		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -TF4"));
		}
	}

	void ThreefishTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(MSGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat: Decrypted output does not match the input! -TV1"));
		}
		if (cpt != Expected)
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -TV2"));
		}
	}

	void ThreefishTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Key::Symmetric::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo: Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo: Decrypted output does not match the input! -TM2"));
		}
	}

	void ThreefishTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		Prng::SecureRandom rnd;
		size_t prlSize = Cipher->ParallelProfile().ParallelBlockSize();

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.resize(MSGLEN);
			cpt2.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			SymmetricKey kp(key);

			Cipher->ParallelProfile().ParallelBlockSize() = Cipher->ParallelProfile().ParallelMinimumSize();

			// sequential
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, MSGLEN);

			// parallel
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, MSGLEN);

			if (cpt1 != cpt2)
			{
				throw TestException(std::string("Parallel: Cipher output is not equal! -TP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel: Cipher output is not equal! -TP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ThreefishTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());

		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXM_ALLOC);
		inp.reserve(MAXM_ALLOC);
		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			cpt.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			SymmetricKey kp(key);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress: Transformation output is not equal! -TS1"));
			}
		}
	}

	void ThreefishTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> code(TAGLEN);
		std::vector<byte> cpt(MSGLEN + TAGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);
		Cipher->Finalize(cpt, MSGLEN, TAGLEN);

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
		Cipher->Finalize(code, 0, TAGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat: Decrypted output does not match the input! -TV1"));
		}

		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -TV2"));
		}

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code, 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Authentication: MAC output is not equal! -TV3"));
		}
	}

	//~~~Private Functions~~~//

	void ThreefishTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// tsx256 - verification
			std::string("509BF34198A8DCE342DF1ABF2644393EDEAB7C5A66FCC05C44DFBAD45C0C33F3"),																	// tsx256h256
			std::string("DF36D613ACB8AEE9767AE8D76A7555B50CEAED49972FBC98BF6BFF44672A7ECBDB6557B96A8B3FECEBBF89C5CE67040F9AB62FB526970B9D01A17EC6CBA5D281"),	// tsx256h512
			std::string("D06026F800C9BD6AB49B0C2714D5CEC1A73EAAA22D0E862B58771F70FB5BDE3D"),																	// tsx256k256
			std::string("58493C980A99827A2B0B683CA43A636BA9B5F2748D9393050756071BD5C4B17EC7EFFE478E3558BB6F82E6CD9D773051AD19A61D761FE3DF8119C0AF6AB6C80F"),	// tsx256k512
			// tsx512 - verification
			std::string("157AC462D45D68552AEE015B195FEFAAF3173EC3062356EEE01D80CB8194E5D5"),																	// tsx512h256
			std::string("68AA4B5FB2C95A6450D16975EEA6A74FC229EAAD7228EDAD160A7D64B97557100435924A3219C9B631F0E8CB2234C0748D9FBE09C77E5A7F5A25BAA98E3867AE"),	// tsx512h512
			std::string("A39DC64FFD17165903ECBF07027A2EA6E5983E0949FE038CC98BE29BD2E164B2"),																	// tsx512k256
			std::string("BC147C47B92CA40CF9397AF5D060DE7A20C0580F66FBB782C2CEEB1B106895060CB99032C33F52D82E7827461F490D3CB229C26D542BA1277C179DF17BC35345"),	// tsx512k512
			// tsx1024- verification
			std::string("E35D61794B5F3DFDAC1D383DE9B62AD4E3E456FE30A19739936364BBE11252E1"),																	// tsx1024h256
			std::string("5D709CB41B285C07EA91538E06C651592945BFA66391E20FFD727585904C0EF16DF8A4848A8DCD637B7D2459079772AAAA141F3BCF8E35ACA95E8BDBF7C5EC3E"),	// tsx1024h512
			std::string("0E53E321F5E7567DECB4EDAA117F251E3A378C78DCB648AC8CD71CE167499F50"),																	// tsx1024k256
			std::string("7919F16C23478B9B482349E2E09808CA817851D165C5AF5030001C9208F2C25D1F7B4051B2434779DB2C7067E6997FE57631B85D5F68E1B1AD8FCC6F5D65CFAF"),	// tsx1024k512
			// tsx256 finalization tests: mac-2
			std::string("655CC3F418B2FF64E1C0AED6FF1B9E6CB0ACCDB6C32ABD74A495D7CA649591BD"),																	// tsx256h256
			std::string("35ED24F6D0A9E7E0973A550EEB87187EE206E2B8760A0D25C6B3B18E2318FABBEC6B2CEA5B438D56E1B3CF6CFDA72567428A7AC19425CD8A17434DCF39DE8733"),	// tsx256h512
			std::string("FBC80E8766E5014992C0D727F19CA532DC4EAF9A3AAEB65582E67C1794E82330"),																	// tsx256k256
			std::string("6A4AA6697AF55897F81C8212344213BA306350D577A31836FFEA9D6473ED2A019D0C2F50CAC8CBBFBC15BDD9A39A854CBE9070FBA27EB799C9E5148473FB3A78"),	// tsx256k512
			// tsx512 finalization tests: mac-2
			std::string("806C72BE87D599F0FAEAC9534A952D6DF9F0DD649E41ED0B4354522142AE2080"),																	// tsx512h256
			std::string("EC19467DBA0A74F7971959CF77D126D9FF7C1F54628650CC26687435AD4B9759733E79A92FD77C66F133DBB1A05DE67022CF7FECFF93DB2F2C3B89A5E9BB539D"),	// tsx512h512
			std::string("0242990182F81C4A9EE985EFED0F7DDF82976993462DBC10E70FD4B32FF224A9"),																	// tsx512k256
			std::string("FFA831222934ACAAEC1A1FCBAF75AC06473EB0EE1FAB37E22339451A487C93C2BE7B02E9B63F95F033337F2CBE453EF4D91DEE0CB654ECAA31F6FD0F6D643DBB"),	// tsx512k512
			// tsx1024 finalization tests: mac-2
			std::string("F92FE6BD68B4DC03D6CC7DB51899FC978A50E2083C33071B672DF8213E5B2D7D"),																	// tsx1024h256
			std::string("FD9C1C77819F44C1BAE429C521290F27249142FC1D329311237C1786FA5FE6462202D7479DB969823D913FDB340FC8A4F3BADB43CA269A335C7D5291605F9CA3"),	// tsx1024h512
			std::string("289FA609EFF62AD871B13710BAB4FE780B283D6E0B9F7937FA9B3090385C62E4"),																	// tsx1024k256
			std::string("3AFC8C20054DC911B3C47DB3C61EB59E695070B1D7761A51C5A7FB59C0593D2EBF1A8BA0888D7331905D8493EBDEC388F5AF57A812713BD15A1622E0D18B0AEE")		// tsx1024k512
		};
		HexConverter::Decode(code, 24, m_code);

		const std::vector<std::string> expected =
		{
			std::string("22051C2C7115F2E1343D848ABA02C749C474E7EFB0CE6AA72F2573A3089EF780"),
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),
			std::string("00D4DB25D39129E24955F3EC2BE0B89F4C571F23401FE0B73D9D12DF4AB7DA9A9DB08E48529BBA253FE995075D85273692E5206BE38114AE4BD087DABE782BBB"),
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),
			std::string("E82D7F08695BD89E1BDD58334A342A8D43F5F23CB95D562EE070C52D2419BDB5C376A894FA5D5C3413D46F34D67F824C12D7E6BBB6F47928518D19607A907D9E00BDA5C72F734D88CFBD0D008794839073975394552FAC34AD58B21355AB4D2106F86EBEA1371591DB8C60DB3A3B4538582B05CB541C1E2D86DD44B9E1EF5AC9"),
			std::string("B3F7134A5977D657479377A1224CA0ACF29C79B4AF0C8A23B269850F6DAEEDB37F8EFCD7F0B65BA7B4F5264E255B459E96AC4D1DD13D7957B6581DB116C7F5848BCD73FA5B588D28B0EE942F8E5F01C85E4E85B743B7CB0EC885B77533D733ABD811B6AB5D2AA25DFADA55138EEB5E3FF150BE937F1AB241DC374DB1F1BA6D09")
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180")
		};
		HexConverter::Decode(message, 3, m_message);

		const std::vector<std::string> monte =
		{
			std::string("2f962d1bbd97223a5a0379b1a4d7af7c86227bffed5362551433155a106207c1"),
			std::string("963a9eab3ebefcaaf8bd27f68755d00db8269c1ebadd4bd3be75a36a39a31f9f"),
			std::string("a549d91645d693b797efb25e900ed04c75ea42dbc570ddcd3541986e5fcaa2645db98ad8c9545ddcee81bd93b5376bb835b03d194a089b5cb4551e6d609c64c9"),
			std::string("39ab0176f64ed6a121d85c78def78d7a548118a89fc5e4c00508f3d5ded5dabc34d0544262ff32bbad7f2bdf2963f10ee796fb7a1a70be4bdc2546a95788849d"),
			std::string("b5747f5be85b6ac8ac2d97a32cc6a3e961195e81d0017ed2308f658ff9c937b0bef28249407234f7bc5baf0336351bddf1f4edfabd325e4ddbdc64ba6ccbccf2ae3aacb10829cf4bf1c2ceeb6b2929a270addb00ea947cc74abcf3ae905b5cddbda4b46df0b6295ca8cb11d28d5d30ad8ae337130f86652e11c6ab32b71ebefa"),
			std::string("4fe91078f7c2be5a8aa30d5f53c71c77a421d1a836ea0f08d6aa543415a792cdd9b05bd4a0725501b14e87bf1a13f57a5efe4a50c8d69571401ca74659c06c0dcc8f7b905bfd5e67e7a8ffaf122daeb6e209a6c0c57e6a45380eb24acef0d5e2a0e6a4580043aa1e5a172fd54ca80cfaa87b82adba96ad909034f44daccc5474")
		};
		HexConverter::Decode(monte, 6, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0"),
			std::string("EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0")
		};
		HexConverter::Decode(nonce, 3, m_nonce);

		/*lint -restore */
	}

	void ThreefishTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
