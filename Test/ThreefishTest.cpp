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
			Finalization(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[1], m_code[11]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(tsx256s, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer cipher tests.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(tsx256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[1]);
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

			Finalization(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[3], m_code[2], m_code[12]);
			Finalization(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[4], m_code[3], m_code[13]);
			Finalization(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5], m_code[4], m_code[14]);
			Finalization(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[6], m_code[5], m_code[15]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer finalization tests."));

			Kat(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[3]);
			Kat(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[4]);
			Kat(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5]);
			Kat(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[6]);
			Kat(tsx512s, m_message[1], m_key[1], m_nonce[1], m_expected[7]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer cipher tests.."));

			MonteCarlo(tsx512s, m_message[1], m_key[1], m_nonce[1], m_monte[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 monte carlo tests.."));

			Parallel(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 parallel to sequential equivalence test.."));

			Stress(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 stress tests.."));

			Verification(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[3], m_code[2]);
			Verification(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[4], m_code[3]);
			Verification(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5], m_code[4]);
			Verification(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[6], m_code[5]);
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

			Finalization(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[8], m_code[6], m_code[16]);
			Finalization(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[9], m_code[7], m_code[17]);
			Finalization(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10], m_code[8], m_code[18]);
			Finalization(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[11], m_code[9], m_code[19]);
			Finalization(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[12], m_code[20], m_code[21]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			Kat(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[8]);
			Kat(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[9]);
			Kat(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10]);
			Kat(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[11]);
			Kat(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[12]);
			Kat(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_expected[13]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer cipher tests.."));

			MonteCarlo(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_monte[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 monte carlo tests.."));

			Parallel(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 parallel to sequential equivalence test.."));

			Stress(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 stress tests.."));

			Verification(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[8], m_code[6]);
			Verification(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[9], m_code[7]);
			Verification(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10], m_code[8]);
			Verification(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[11], m_code[9]);
			Verification(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[12], m_code[20]);
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

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN))
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
		const size_t CPTLEN = Message.size() + Cipher->TagSize();
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> cpt(CPTLEN * 2);
		std::vector<byte> otp(MSGLEN * 2);
		SymmetricKey kp(Key, Nonce);

		// encrypt msg 1
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF4"));
		}

		// use constant time IntUtils::Compare to verify
		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -TF5"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -TF6"));
		}
	}

	void ThreefishTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(CPTLEN);
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
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -TV2"));
		}
	}

	void ThreefishTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(CPTLEN);
		std::vector<byte> dec(MSGLEN);
		Key::Symmetric::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, MSGLEN);
			msg = enc;
		}

		if (!IntUtils::Compare(enc, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("MonteCarlo: Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, MSGLEN);
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
			const size_t CPTLEN = Cipher->IsAuthenticator() ? MSGLEN + Cipher->TagSize() : MSGLEN;

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
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> cpt(CPTLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -TV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Verification: Decrypted output does not match the input! -TV2"));
		}
		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -TV3"));
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
			std::string("60C417AC4EE5F43382ACEBE4453C3F119CFAD78EA1E2CCA3517D3BBEF1859B09"),																	// tsx256h256
			std::string("49EE5D3C88A42CDF054FCA6E93BA16BA00AAE4734147C7F5441A9FC2054344E1"),																	// tsx256k256
			// tsx512 - verification
			std::string("C19FDC2F9160C77ED7078886E4884461A5AA6EDB131311B8BAFA4071C2E6B5CA"),																	// tsx512h256
			std::string("EB4D53A06D6F474CDEFB54E71BD53F4FA50A6A33D93EA4F76ADA74EC2588EE2D8C0E98B62176F5FF72259640F506F2787ACF6E4A0D0AAA095BFA51571533BE1B"),	// tsx512h512
			std::string("1FFD4B4EED720F5489DF0F2EDE377F5DE3312DFE03F8A8A36A7957ED678C4D46"),																	// tsx512k256
			std::string("786586E4C05DAFF30810C0DB6EA268F06BF8C7A20D43138C8E3A2753CDF5677B8588A66AA08AB6239830EFF64C589F6EEAC814D2CEEEB43449700A1E30AE2950"),	// tsx512k512
			// tsx1024- verification
			std::string("8AEB70D8BF1A83DA1F8936CF7A1E9098F44D220FD6682B66D732E4EBF07E02D0"),																	// tsx1024h256
			std::string("5E394834A36C9DB632D5C572FE4319A0E6CA25DFC369717B77ADF3A2A2EF86063DC6EB8B8B5D4D46003533426F5395AF05A061224453229A2A3BB5F7382C77F1"),	// tsx1024h512
			std::string("67E23840956DFA021BC89CFF6D5774E8BC52F7E8BC87F83D9DF5C2BE89D96DA2"),																	// tsx1024k256
			std::string("640A0452CECB50F06D4867280D61030460ACB5713DA96E9A4EDF8858489CC6EF5D6A04B0FFA6FD70DD5CBBADB038AE8F19D22D5F026645F54E263506DDC4023C"),	// tsx1024k512
			// tsx256 finalization tests: mac-2
			std::string("8591E3435A33BEB456452FB788580A8B77B128FEF8F668DD8311E3A48C9B1FBF"),																	// tsx256h256
			std::string("C9E940254B4794766C7F19A6B12C7A7677B5D37C84FCCD300B6AC98E7571A304"),																	// tsx256k256
			// tsx512 finalization tests: mac-2
			std::string("03D7B2CEACB7D2274206A11C12FA8A126519745FF3784B351235E8F156D77C0F"),																	// tsx512h256
			std::string("E7C6DCCDE38CC0B9480A49E52BBE52460CA5905C4ECBD1649DE48676756EDFC2C0ACC96609089EECFA5DE9F1ACCB29F6A020A11524091A4D5A2D48C0B8CCD760"),	// tsx512h512
			std::string("5AB6A2591B936E908FC59A2833CB19D2744E061659DEC05293DA651048EFEDE3"),																	// tsx512k256
			std::string("B7170DB2D7FEB5FB24C95E4BC0816FA750DED08E66A802F6B33101C38CBA78C0317B967411838D65217E2BECCE1BE5C760A95EAC9CFEAC21E9E669DD2BE85892"),	// tsx512k512
			// tsx1024 finalization tests: mac-2
			std::string("1A5D0F20CB31E7E087B14FF9B742142D741192BFFA2D56CBAAE747AB2D4F5979"),																	// tsx1024h256
			std::string("AB67B5A2787B925BBABB39DC3570D529EADAC572C5D98E7C9001B8756C704EBDC7EFC751015E1E732C6C62EE7F679B0A2BD43680869B05D5A356F11648CB7BB9"),	// tsx1024h512
			std::string("BE1EC2CCC3B75A5B50E5B2D89A9B3A856346B470DB4215D9FB7CF3143B8824F4"),																	// tsx1024k256
			std::string("F4285FC54F012244631A9AA3C64BDDA234227CF5B592E17DCA0D70F1D7AC05CD9B7CCB35F71DDF90473DA25B07567078F08559D6A9D91E5CF72E98DCB045B242"),	// tsx1024k512
			// tsx1024k1024 finalization tests: mac-2
			std::string("102274AF7633951F752FDAC4A496EC86C490F9D16DE4B7C41E44140434D1FDC5916DE3B8C0CCBD618740379AA9796DA4EB5F4708C8A4052449ACAEA44DF4C3669446F8CE3008C31E20A8535E438F81BA06305BE4970EB36813BC7CC36C1DF610360EF6FC00EE091EE903A821EC09F90F2316D27049253CBA9F87EE0DA77BE583"),																	// tsx1024k1024
			std::string("88E543D605F865AF30E4A17848A131BFF571003E817D0270B34F7D58C9FF2C93D2E8ED19E770A5D2CAAA827704697743FA57F69A1DBE8C0498BC889D2B1EE4262FDC9BC03BBC209B8BD92F92DA622AA01AA5CFAF326964CECC2BE6EB93AC52D668DAAEC235FAAF8A5F05A28026E4B4BA09DAAE1087B4BC68AB8C47A8187F17F4")		// tsx1024k1024
		};
		HexConverter::Decode(code, 22, m_code);

		const std::vector<std::string> expected =
		{
			std::string("4ED77F3F983C6F35C9A5ADEFD7447004EBBE098FB488EBEB6B80514667444D0E"),
			std::string("366CE9D507F31F5272AE5DA4EA483DB0CBC10329425CB43AD259294FCA3A0BCE"),
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),
			std::string("DE1C8FF89D760ABD368FCF972B0ABF753E210C99B3E170EDB5DDF01F437BDAC7E4BFE0594BA3257E88E1C8DD1044D6C6A3606FAB6CF939E0CA9DDCFD7C2F8BAD"),
			std::string("102C4AA042C38CB138ADA0FAE4B8D1C53A5260BFDFE46990D82700A09FFFA2F173865E820D34EE13CB36CE4139DAF4B0B7362F9E8DD7E13254D90CE75749655A"),
			std::string("BE3AB71F968A420165EEBD2E0E8CCF50916C809D26009B9781124DEC59FE67288198DD5247489F449A4F1B94513809899A63F537CF71EBA43A1DB6C57245E378"),
			std::string("4F433077556E7DB5A8708CDA9849AB3619E5BABD430319191C33557B6956C0D12EE84AB5C2BBF55128DA23F685C9914AE677C4EAF72B505073AF7E5390E0324E"),
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),
			std::string("0CB8DF1ABA7BA22DA7ABDBD2C368A04D532F50389BC47BEFAEFD3A4464036A8BC2D10D2F3EEDDDA9AD869F3947964342704C8D01CC9117028D2B99DAFB973D355908B5616E0335CE5788EB0237C3FB99A32622E5069467E98978E772E97AF0DAC26622F1FFE7FB250B0D10602659F683393494BDE555F3D340B6256623174808"),
			std::string("561632B2C28CEC073E0CE98E701405D996FEF747D1B87004377D9440A0CAD6BA034527BB5F93ECB8FED21848E21BBA3D880F5488675E86FB0AA58F11E5B29FB42845202889C1D9D928ACF70A6C34D60D0BB92CA3746F00DD017F387E7EA1F295339B271A163434E27A53553EB75BC077A18A7B7E4B14866C3FF50439C61A37B4"),
			std::string("AB3305096376897E6A8921A759964B07DCE61C8B9DC22EC0EB33D09EA7392CC40BB28960023BBA88288FC2772067839B6D893B1408AB80747C3E318610A0183C477802705996E0DFD4F5120192F5983AC8C1BCA73DC7E023240EBEF83DD544CEEEF7FF7638AB8B3F8EE449FAA51C875A5B162FA84998DA7B9A2E82870E569B1C"),
			std::string("F05D3655A6B260FA489F20D13F795CD9C3157594594A3A09565EB2529A091733EE483E704ABBBBDA85EC9808397F7B0DFBF6A332227595FE1C51A9E1C8F9D2C7CA80C775BF2900369E90DBAC0F4A91CCEB720D8A7B4D27806BC8D4A5D6E6D7F63431645F6EEAC4BF633D76099FD0C53F8AF8E36DC0F8BF68C3FF46F958E453B7"),
			std::string("24977F741863E8472C47AD0F782F9772AF938882EC69269C93F741509B68032EA820545E3BB32363285E2ED8C3F3F9B6D86F3FF524011F547D9EC873AAC336FD9B5E46A536B643579F2EB5543D99EB35FF7C18BE4B984EAB8D7E5CB2FD438A39501A1AF0ABA868B915B39A5F77DD56813A5B9ACF31545B0E9ACFF1A226C82BD6"),
			std::string("B3F7134A5977D657479377A1224CA0ACF29C79B4AF0C8A23B269850F6DAEEDB37F8EFCD7F0B65BA7B4F5264E255B459E96AC4D1DD13D7957B6581DB116C7F5848BCD73FA5B588D28B0EE942F8E5F01C85E4E85B743B7CB0EC885B77533D733ABD811B6AB5D2AA25DFADA55138EEB5E3FF150BE937F1AB241DC374DB1F1BA6D09")
		};
		HexConverter::Decode(expected, 14, m_expected);

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
			std::string("963A9EAB3EBEFCAAF8BD27F68755D00DB8269C1EBADD4BD3BE75A36A39A31F9F"),
			std::string("39AB0176F64ED6A121D85C78DEF78D7A548118A89FC5E4C00508F3D5DED5DABC34D0544262FF32BBAD7F2BDF2963F10EE796FB7A1A70BE4BDC2546A95788849D"),
			std::string("4FE91078F7C2BE5A8AA30D5F53C71C77A421D1A836EA0F08D6AA543415A792CDD9B05BD4A0725501B14E87BF1A13F57A5EFE4A50C8D69571401CA74659C06C0DCC8F7B905BFD5E67E7A8FFAF122DAEB6E209A6C0C57E6A45380EB24ACEF0D5E2A0E6A4580043AA1E5A172FD54CA80CFAA87B82ADBA96AD909034F44DACCC5474")
		};
		HexConverter::Decode(monte, 3, m_monte);

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
