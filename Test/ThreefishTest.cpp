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
	using Enumeration::StreamAuthenticators;
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
			Threefish256* tsx256h256 = new Threefish256(StreamAuthenticators::HMACSHA256);
			Threefish256* tsx256k256 = new Threefish256(StreamAuthenticators::KMAC256);
			Threefish256* tsx256s = new Threefish256(StreamAuthenticators::None);

			// stress test authentication and verification using random input and keys
			Authentication(tsx256h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 MAC authentication tests.."));

			// compare parallel to sequential otput for equality
			CompareP256();
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 permutation variants equivalence test.."));

			// test all exception handlers for correct operation
			Exception(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 exception handling tests.."));
			
			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[10]);
			Finalization(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1], m_code[11]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256s, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer cipher tests.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(tsx256s, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer authentication tests.."));

			delete tsx256h256;
			delete tsx256k256;
			delete tsx256s;

			// threefish512 standard and authenticated variants
			Threefish512* tsx512h256 = new Threefish512(StreamAuthenticators::HMACSHA256);
			Threefish512* tsx512h512 = new Threefish512(StreamAuthenticators::HMACSHA512);
			Threefish512* tsx512k256 = new Threefish512(StreamAuthenticators::KMAC256);
			Threefish512* tsx512k512 = new Threefish512(StreamAuthenticators::KMAC512);
			Threefish512* tsx512s = new Threefish512(StreamAuthenticators::None);

			Authentication(tsx512h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 permutation variants equivalence test.."));

			Exception(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 exception handling tests.."));

			Kat(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512s, m_message[1], m_key[1], m_nonce[1], m_expected[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer cipher tests.."));

			Finalization(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[2], m_code[12]);
			Finalization(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[3], m_code[13]);
			Finalization(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[4], m_code[14]);
			Finalization(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[5], m_code[15]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer finalization tests."));

			MonteCarlo(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_monte[2]);
			MonteCarlo(tsx512s, m_message[1], m_key[1], m_nonce[1], m_monte[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 monte carlo tests.."));

			Parallel(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 parallel to sequential equivalence test.."));

			Stress(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 stress tests.."));

			Verification(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[2]);
			Verification(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[3]);
			Verification(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[4]);
			Verification(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer authentication tests.."));

			delete tsx512h256;
			delete tsx512h512;
			delete tsx512k256;
			delete tsx512k512;
			delete tsx512s;

			// threefish1024 standard and authenticated variants
			Threefish1024* tsx1024h256 = new Threefish1024(StreamAuthenticators::HMACSHA256);
			Threefish1024* tsx1024h512 = new Threefish1024(StreamAuthenticators::HMACSHA512);
			Threefish1024* tsx1024k256 = new Threefish1024(StreamAuthenticators::KMAC256);
			Threefish1024* tsx1024k512 = new Threefish1024(StreamAuthenticators::KMAC512);
			Threefish1024* tsx1024k1024 = new Threefish1024(StreamAuthenticators::KMAC1024);
			Threefish1024* tsx1024s = new Threefish1024(StreamAuthenticators::None);

			Authentication(tsx1024h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 permutation variants equivalence test.."));

			Exception(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 exception handling tests.."));

			Finalization(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[6], m_code[16]);
			Finalization(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[7], m_code[17]);
			Finalization(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[8], m_code[18]);
			Finalization(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[9], m_code[19]);
			Finalization(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[20], m_code[21]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			Kat(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_expected[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer cipher tests.."));

			MonteCarlo(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_monte[4]);
			MonteCarlo(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_monte[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 monte carlo tests.."));

			Parallel(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 parallel to sequential equivalence test.."));

			Stress(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 stress tests.."));

			Verification(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[6]);
			Verification(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[7]);
			Verification(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[8]);
			Verification(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[9]);
			Verification(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[20]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			delete tsx1024h256;
			delete tsx1024h512;
			delete tsx1024k256;
			delete tsx1024k512;
			delete tsx1024k1024;
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
		std::vector<byte> code(TAGLEN);
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

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

			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

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
				throw TestException(std::string("Authentication: MAC output is not equal! -TA1"));
			}
			if (!IntUtils::Compare(inp, 0, otp, 0, MSGLEN))
			{
				throw TestException(std::string("Authentication: ciphertext output output is not equal! -TA2"));
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
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

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
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

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

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);
		Cipher->Finalize(code2, 0, TAGLEN);

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code1, 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF1"));
		}
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
		std::vector<byte> nonce(ks.NonceSize());
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

			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);

			SymmetricKey kp(key, nonce);

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
		std::vector<byte> nonce(ks.NonceSize());
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

			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

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
			throw TestException(std::string("Verification: Decrypted output does not match the input! -TV1"));
		}
		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -TV2"));
		}
		if (!IntUtils::Compare(code, 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -TV3"));
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
			std::string("D06026F800C9BD6AB49B0C2714D5CEC1A73EAAA22D0E862B58771F70FB5BDE3D"),																	// tsx256k256
			// tsx512 - verification
			std::string("5CDB3447F0DEF7149DDADAF4F6CF9B41BE3A527728DCED03216DE8A2FD154052"),																	// tsx512h256
			std::string("F23A482F6BE7AF228D18E8FFB574813E8E63C854F171D25B876EB02540741498EBE13799E61AC8DE432B702027EC3FB3D6B28BCC61E17464DE5FA0BE0B86E4D9"),	// tsx512h512
			std::string("B7BD6DE81164A62AFD79E7CBA2FB546C53E57BF4D5D42D3CB692C3A17FDB25FC"),																	// tsx512k256
			std::string("4B0063C921F4D313FFBCA8FED0DABDC935485B3C6DF8B99FCB19C5C5A1A09CEB12184146BE94EBDA84C4DF8F4F6F72E564CC518DBBB30B68AB52EFED72911FBF"),	// tsx512k512
			// tsx1024- verification
			std::string("FD6667AECF310FE107E48A9922F8FE0DB4C67ABE6A1D386898DCB23FD322C9BD"),																	// tsx1024h256
			std::string("CB0976CBE2063C1A9A406AB5605D1E05E7C93E341FCB9D6CB54AA101DD5B3BD1F112D88ACE0B5C9E030249ECFF73C6F6610EE9CA17BC041AB4416C0FB1288CDD"),	// tsx1024h512
			std::string("CC83F9E82D61B2205BA1975BFBF34CDEE834B0CD6834443540FCD0BAE2AD1726"),																	// tsx1024k256
			std::string("0517A96B115F371DCE9A39358AACB7385558A73C43C635E024DD4B7029639514258EE69C2B4FEDDACC59A855D73D2153A252CB7053299DFD93548FD285A97AF8"),	// tsx1024k512
			// tsx256 finalization tests: mac-2
			std::string("655CC3F418B2FF64E1C0AED6FF1B9E6CB0ACCDB6C32ABD74A495D7CA649591BD"),																	// tsx256h256
			std::string("FBC80E8766E5014992C0D727F19CA532DC4EAF9A3AAEB65582E67C1794E82330"),																	// tsx256k256
			// tsx512 finalization tests: mac-2
			std::string("A47C29D31BCA48AE506A87CE1B366E8A15CC33EE175CC7ACFECC68DD5E804EF3"),																	// tsx512h256
			std::string("2DF95CB2D9359CD268907DD7EC21845E9300176FB90D0BB5EDA31C8F57B0E6065094368798AF8DFDF11C1AB21EB6DBEB8D0BB0859B92D3FDD9B33D8F5C68A016"),	// tsx512h512
			std::string("B7395656981B7510DB8C676A54DD2C4E5C58B8394E8278A091C51090AD34D419"),																	// tsx512k256
			std::string("A1C0BEF51B48000D29F73EDC7681B8F47835F6901B73C109EBFDA862C719A2557065D50D832EC094F482954E4534B331F05194C0FAFE4A83125B249F25AEAA47"),	// tsx512k512
			// tsx1024 finalization tests: mac-2
			std::string("754D322FE78B891B03418F02BF787D36FABEC98F896339764445BF0BEA31E5DE"),																	// tsx1024h256
			std::string("E4FC6CE59E10E954E0365402FA97D628A490FEC9C2EC221EE614155FDD64995E0096B62CB43A5C980D1DA550C94CF8EA15C8D8DD7F781C6C3E38C9EA508ED254"),	// tsx1024h512
			std::string("D4D92BC5FB814D82FC0F3B7099933F7F91301DDC5E4142BDB048A0F2DCA5E2D9"),																	// tsx1024k256
			std::string("BCCEFCFA1C40BAA808AD9ACF969CB6ED5791333B4006A740F85781BA6544FE613FAAB660404E45EC7C380B78B3FEEF60DCFE126FEA6F846E30BBFFBC4AD2D4BB"),	// tsx1024k512
			// tsx1024k1024 finalization tests: mac-2
			std::string("D0C49650DBEC26DA7439C20D792FB31033FC480FAC3D4F36D58A26566FCCAF13F0570B69A7205B741F451559A7A591ACF9A4F8F30C63C5C9638DDAC40D1CCAEEAB6F17A733135C272FDBFBB7D96291B0D1FE1B2E15056CDE22AD3236DF1ED6A63C28C1C21A9B70415ECF46EE8FF1D32ACA1CF027C02B9FB9FD64F1CDF9B1564C"),																	// tsx1024k1024
			std::string("3ECAF7371E2623FA4E5A1E9DC96B725A1E45E00ED40FA5411F473AE71C7390E249B76C224EF30A154043A71F7937C519093279B9383DB452803C41A3FDB34EEAFCC9E8F29BD51EFD5B184738A331AAA0482B607E0FED45B905A0EAA5726663A7B5522C6A90637FF4F46F121383A01AF023A3DDA336665E0F54A06982D54EFFA0")		// tsx1024k1024
		};
		HexConverter::Decode(code, 22, m_code);

		const std::vector<std::string> expected =
		{
			std::string("22051C2C7115F2E1343D848ABA02C749C474E7EFB0CE6AA72F2573A3089EF780"),
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),
			std::string("85D1B134B67A1DE07439DEF590208088F60210BE24E510669964ECE5A8C09F175F709679E19789742F339EF6E49A7E3EEED658F0FC8043537E7E5105E5EE20AF"),
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),
			std::string("9E2E81ACB541F45E239D14D4BEDC29FBE03F6554086EF684BFF81587D063037B8B8BBAAADB2930F636EBE55716FDC4EE55232C94463A928F5F2885FF595E80EC6183E9F02A9B822BF8418FB64FCE35553D4BB3D0027DA947F3BFBEBB27B620D15B2DE678AAB759C7CA540515E726EBC711BCDBF6E1C5CEE8B4B145FFCD560522"),
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
			std::string("2F962D1BBD97223A5A0379B1A4D7AF7C86227BFFED5362551433155A106207C1"),
			std::string("963A9EAB3EBEFCAAF8BD27F68755D00DB8269C1EBADD4BD3BE75A36A39A31F9F"),
			std::string("0C6C0ECA8EA33C62DDF79B8C547640EA25E157DC863C155690B3A5C461AB4102F62729B44FD04FD9EE829763EADAC944CC63BF69980FFC15669CA5D5C51C6830"),
			std::string("39AB0176F64ED6A121D85C78DEF78D7A548118A89FC5E4C00508F3D5DED5DABC34D0544262FF32BBAD7F2BDF2963F10EE796FB7A1A70BE4BDC2546A95788849D"),
			std::string("C836E5E5CD57CB3690F0485E97357BCD029A79C102A23C8B5140BF00E7DE296C3C3791E901A52B283005F1BBBBDB71B083AD8F60435DBDFCFB1DD9376762EA5849339CB2D10C7FFE6793418F2D289884B760277DBFAD70092957B671E5148CF52672A6C0B74737FC40FBFFA94AA44FC77C98E370D97A8CA3421DA8002AA7CA22"),
			std::string("4FE91078F7C2BE5A8AA30D5F53C71C77A421D1A836EA0F08D6AA543415A792CDD9B05BD4A0725501B14E87BF1A13F57A5EFE4A50C8D69571401CA74659C06C0DCC8F7B905BFD5E67E7A8FFAF122DAEB6E209A6C0C57E6A45380EB24ACEF0D5E2A0E6A4580043AA1E5A172FD54CA80CFAA87B82ADBA96AD909034F44DACCC5474")
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
