#include "ThreefishTest.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
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
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;
	using Cipher::Stream::Threefish;
	using Cipher::Stream::Threefish256;
	using Cipher::Stream::Threefish512;
	using Cipher::Stream::Threefish1024;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ThreefishTest::CLASSNAME = "ThreefishTest";
	const std::string ThreefishTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ThreeFish stream cipher.";
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
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
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
			Kat(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[12]);/**/
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
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void ThreefishTest::Authentication(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
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

			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntegerTools::Compare to verify mac
			if (!IntegerTools::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN))
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -TA1"));
			}
			if (!IntegerTools::Compare(inp, 0, otp, 0, MSGLEN))
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("ciphertext output output is not equal! -TA2"));
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

		IntegerTools::Fill(key, 0, 4, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 4 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 4 * sizeof(ulong));

		Threefish::PemuteP256C(key, counter, tweak, state1, 72);
		Threefish::PemuteR72P256U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP256"), std::string("PemuteP256"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 16> state3;

		MemoryTools::Clear(state3, 0, 16 * sizeof(ulong));

		Threefish::PemuteP4x256H(key, counter8, tweak, state3, 72);

		for (size_t i = 0; i < 16; i += 4)
		{
			for (size_t j = 0; j < 4; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP256"), std::string("PemuteP4x256H"), std::string("Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 32> state4;

		MemoryTools::Clear(state4, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter16, tweak, state4, 72);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP256"), std::string("PemuteP4x512H"), std::string("Permutation output is not equal! -TP3"));
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

		IntegerTools::Fill(key, 0, 8, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 8 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 8 * sizeof(ulong));

		Threefish::PemuteP512C(key, counter, tweak, state1, 96);
		Threefish::PemuteR96P512U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP512"), std::string("PemuteP512"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 32> state3;

		MemoryTools::Clear(state3, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter8, tweak, state3, 96);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PemuteP4x512H"), std::string("Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 64> state4;

		MemoryTools::Clear(state4, 0, 64 * sizeof(ulong));

		Threefish::PemuteP8x512H(key, counter16, tweak, state4, 96);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PemuteP8x512H"), std::string("Permutation output is not equal! -TP3"));
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

		IntegerTools::Fill(key, 0, 16, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 16 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 16 * sizeof(ulong));

		Threefish::PemuteR120P1024U(key, counter, tweak, state2);
		Threefish::PemuteP1024C(key, counter, tweak, state1, 120);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP1024"), std::string("PemuteP1024"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX2__)
		
		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 64> state3;

		MemoryTools::Clear(state3, 0, 64 * sizeof(ulong));

		Threefish::PemuteP4x1024H(key, counter8, tweak, state3, 120);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP1024"), std::string("PemuteP4x1024H"), std::string("Permutation output is not equal! -TP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 128> state4;

		MemoryTools::Clear(state4, 0, 128 * sizeof(ulong));

		Threefish::PemuteP8x1024H(key, counter16, tweak, state4, 120);

		for (size_t i = 0; i < 128; ++i)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP1024"), std::string("PemuteP8x1024H"), std::string("Permutation output is not equal! -TP3"));
				}
			}
		}

#endif

	}

	void ThreefishTest::Exception(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE1"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Threefish"), std::string("Exception handling failure! -TE2"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Threefish"), std::string("Exception handling failure! -TE3"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Threefish"), std::string("Exception handling failure! -TE5"));
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

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF4"));
		}

		// use constant time IntegerTools::Compare to verify
		if (!IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) || !IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -TF5"));
		}
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Output does not match the known answer! -TF6"));
		}
	}

	void ThreefishTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
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
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV1"));
		}
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -TV2"));
		}
	}

	void ThreefishTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(CPTLEN);
		std::vector<byte> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, MSGLEN);
			msg = enc;
		}

		if (!IntegerTools::Compare(enc, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, MSGLEN);
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Decrypted output does not match the input! -TM2"));
		}
	}

	void ThreefishTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
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

			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);

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
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -TP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -TP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ThreefishTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());

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
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			const size_t CPTLEN = Cipher->IsAuthenticator() ? MSGLEN + Cipher->TagSize() : MSGLEN;

			cpt.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -TS1"));
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

		if (!IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -TV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV2"));
		}
		// use constant time IntegerTools::Compare to verify mac
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Output does not match the known answer! -TV3"));
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
			std::string("19C1FECDBAA3EDE407FD34E1A1374C9025CEB24401707327B83E0A33EFE9CE8E"),																	// tsx256h256
			std::string("564160439CA3B9205C5C0EA5302E48F0557A8A6203063B879FC71DF1F2397AEB"),																	// tsx256k256
			// tsx512 - verification
			std::string("77BC9C62971E4D51BF154DAB034866A19A7B77261F4B12032FF0A15B1D40298E"),																	// tsx512h256
			std::string("FF2049736E255DF33E62C4A24C2D69087EE7CE8E2EF0B5D42B98FCC5AAD1092833327747CE8057E474B78D0B6883DEA171109633AF7A0D043E138E87586D799A"),	// tsx512h512
			std::string("CA0A4433D71466920F623F8B1391861DEC761B8C10386B10BB939E7713739C55"),																	// tsx512k256
			std::string("102FAD79EB23333DA44355D9C1F5D9DE6FD561BAF596CEF0791577FD37D159BC9E8AD0024EA4ADA33B166C1D9EDAAAF21694D1BA6992AFC7C3E432BE9C59DA63"),	// tsx512k512
			// tsx1024- verification
			std::string("A304345AA9BFFB281EC8E41221369D9AC412F9694EF9DADE5531386FA008483B"),																	// tsx1024h256
			std::string("36F1346035412CD4F242B4B4E09D52F1C71671BD4E3E1E75F1AF1298A20E30254E6A357A8E4417C50BE940D1ADFD05D9C7407D89F25D7017FC564AB5D96BFD4F"),	// tsx1024h512
			std::string("E48904554FD8D2690B1500227BCFEAF6DD6DBFA1DABC8C83E5C3FEF32D13D641"),																	// tsx1024k256
			std::string("74F36AC150066C95D642A730D837C97BDFE6C2530D1D5E361E886022851B9B4BD158502A2388C99242DDC47885457DBD02C0F3CAC25C5DFE12F7EEE133B01E9B"),	// tsx1024k512
			// tsx256 finalization tests: mac-2
			std::string("0ED247370CE660A3601793AB2193DFE666EF2BBCE8A23C31A0CBB6AFD4FBA5F2"),																	// tsx256h256
			std::string("C94C8B6329B1F61139802C3F821E3148DE26E4392E20B4FFE461FCFD42A1D0D5"),																	// tsx256k256
			// tsx512 finalization tests: mac-2
			std::string("5D8D237FDF23A3CF60E8A90FC7417DDA08F96F0E001025EB7E0D6EFD50B112F5"),																	// tsx512h256
			std::string("246DA51381473C44238EACE109E35B046EDCD272DB647D66C07BF64BD2AFFA4327F6745280F16208E3B813B18253E18329CA55A9C927E8D293C5D4E090FE3CE8"),	// tsx512h512
			std::string("85C62F691478A8388DADDE9E653AD2325B3E7F7B2CE4315658A1928571982C5E"),																	// tsx512k256
			std::string("A84CCDE44D4FFAB561A3A0B5CCA58D68249858A93FAE45E1CB9E9B3D2C7EED773B3B5F618EDC496930B17BE3BACECFD12B48096F4032DAF51FEA2EAAB36EE074"),	// tsx512k512
			// tsx1024 finalization tests: mac-2
			std::string("2E901A32C399AB794C42168E6E3D55E330755E7164364953653CEEA2C821B985"),																	// tsx1024h256
			std::string("E8A236593C1D419C4B364E13CE42498E7AB45379473A68362A22038B87DAA2D268EF830201DA15E50D9CBB7733AA7EC69EA5C96D76BB5DB31789B4D1E2FAC8E7"),	// tsx1024h512
			std::string("06995A0D9A045580445883B90B6D9EE5C0A5A270E4FE0CE3AED74FD94AEAC73E"),																	// tsx1024k256
			std::string("4F3ACB81B9DA781A8B50FAB63BEC35189E70AC9EBBC06DBE1F6BFE481BC861CA933B2AA91FD337B31559B5B325D2DE34FE68E40D48FBAA543E53EA07E45D594B"),	// tsx1024k512
			// tsx1024k1024 finalization tests: mac-2
			std::string("49AE83DD0FB195592874D40797A5AD311E0D0F330F6E79F086ECDC68F5CF82CFCF373B1149E50493DADBBB409F9F2A88F9D201FFB6A3E885B6135031A55B73B8338D571859BC75FC504D039AB40E98E2666C2B340C43608F1C7BACA9219067AB441FE5B6C809DBF3640695C58D67D7B1EB98FB153A81CC5F376102ECADC592B2"),
			std::string("7B5130FEF965CEE84C3D5B4C951D30A8227A756ACF6DDE95568A03075932905863F58C033C3E612FB7C262529DD5D622C45F8472D373CE8ED69895A3EF5E4DBD23C2DA6E9211A46C4933AC1C9343441A4F1F0573F30679B70DDD220F3D2597BAED2B123F7C77957A0E3A7B0DBCD01EDE10D952E12FFC40FE6FA548D3E36CB34A")
		};
		HexConverter::Decode(code, 22, m_code);

		const std::vector<std::string> expected =
		{
			std::string("69508BF4F87BD7FF8D107FEFA24718DDB71553E6C3E9662B513FE8DD0E9B71DE"),
			std::string("2DACC4507EE764A80C7F7B56FF8A4CEC558A8AD3D3C065B25536FEBBF8000AA5"),
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),
			std::string("1CDE50369EEC72E2D3FBA429E47E92DA4B51956000266E1275A7AAF7CFE33D1B029B563FCBA0BCDDBBEAC741A80EC3B3B28F193EB380B4567CEBF112FA09501C"),
			std::string("BE9ECA021AB35992B96106870E8C65D0806B1619A8EC291182AAA42BB68AD8D95622C422537658815C0E2389A4B7FFCE3E524E353326F9C2E1FB3D77AA1EFE9E"),
			std::string("FEF1B7D63D7806EA4D4485CC9460F24D08E3DA53DBF2B456E2CD0D25EA144BF7BC5B42F0448C1EAFD989BC1E0C552925CAE47FF4A46F9B7A1E2D0DA818A051D8"),
			std::string("EA93FE7FC81BE4431E4D29844852CAD8A49A3A0B1BE5532581FC0E4171BD65490C97DAB54570DF73232F02613DB83C82396A056053E2ADBE3089854772636C36"),
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),
			std::string("18B665A4D622C684A37B707D785A344114FF8E5E6DF34B8600549140AFA98C4643131D736E3D2ED563385647283FD10613A345EE537CCE9AC954240003D5DC163D3B63FAA4A491270298B403D063305DA24442BB1FE4802230F4826599D1558251E9105CA7C0F52E14C897783C1F497608F1636CF5358D242564A458856106A6"),
			std::string("2AFE6FC82BB73DC44547E977D8A0975C257E3A76206D876EE524FC34DCAB66CBC889FEEFBD1C88261CFCC8A5DAE4F11776334524DB8F2CF4B6CC454877C1E756408407DF0717F251D4D750B7B43C697FECDD1AB152F20E275D2C47CE5E120306D8A730961F49BD85FE4DC79B5AFE8465A13546B41DCF41CC7870709219CB8C7B"),
			std::string("FE0D577CC6B21863E161A0C43ED77CB6A56ABB71277BAA64DB1DE66FACD82817D5509DB05E26D1363034781D730A6DC063351D90B862F476C3A315B91DDD9441F95BD2CCDEE4875720817B92DC2FF0461693DDD90D73BA07EAD6131B29CFABC4F9C05FEA664E092F8AD0D0E7D210D110D6BF58717EE281CC1533EE0E0AC3A898"),
			std::string("55A42C7CBC0C7E1FFDB149C06C94A1208F03DFE6E81E461AE2F956DE855352E094692763EA2C3C77EAC081641A78BDBB4DE50BD2E60D844BD063726306F7ED789C3FAD8120F2B5EB81CC00B393D55D3B2CCEA262707FA1F230BF69462D0E69A5570CC13848666FF4E6C24FC235ED5216732188B73C6105D2ABD27E32EB117B45"),
			std::string("E7B308C86B23D465FEA27C3A8F3190B88726716E118EC792C9DED19FDAE0157F9B93772445993DC4A2F6F6E2809D269D3DA90D85083641BC65499BD99B7883BF6E53CC1993E725AC292F095B321A93EDDE69A8BE2DCD2C363F83E0024BCC1449556B0DBA41E69420D75ABD658E1747D1E252A6A9797C17C05240D1772B2DF0F8"),
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

	void ThreefishTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
