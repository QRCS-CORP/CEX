#include "ThreefishTest.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/Threefish.h"
#include "../CEX/TSX256.h"
#include "../CEX/TSX512.h"
#include "../CEX/TSX1024.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Exception::CryptoSymmetricException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;
	using Cipher::Stream::Threefish;
	using Cipher::Stream::TSX256;
	using Cipher::Stream::TSX512;
	using Cipher::Stream::TSX1024;

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
			TSX256* tsx256h256 = new TSX256(StreamAuthenticators::HMACSHA256);
			TSX256* tsx256k256 = new TSX256(StreamAuthenticators::KMAC256);
			TSX256* tsx256p256 = new TSX256(StreamAuthenticators::Poly1305);
			TSX256* tsx256s = new TSX256(StreamAuthenticators::None);

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
			Finalization(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[1]);
			Finalization(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[2], m_code[3]);
			Finalization(tsx256p256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[4], m_code[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(tsx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(tsx256p256, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(tsx256s, m_message[0], m_key[0], m_nonce[0], m_expected[3]);
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
			Verification(tsx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer authentication tests.."));

			delete tsx256h256;
			delete tsx256k256;
			delete tsx256s;

			// threefish512 standard and authenticated variants
			TSX512* tsx512h256 = new TSX512(StreamAuthenticators::HMACSHA256);
			TSX512* tsx512h512 = new TSX512(StreamAuthenticators::HMACSHA512);
			TSX512* tsx512k256 = new TSX512(StreamAuthenticators::KMAC256);
			TSX512* tsx512k512 = new TSX512(StreamAuthenticators::KMAC512);
			TSX512* tsx512s = new TSX512(StreamAuthenticators::None);

			Authentication(tsx512h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 permutation variants equivalence test.."));

			Exception(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 exception handling tests.."));

			Finalization(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[4], m_code[6], m_code[7]);
			Finalization(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5], m_code[8], m_code[9]);
			Finalization(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[6], m_code[10], m_code[11]);
			Finalization(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[7], m_code[12], m_code[13]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer finalization tests."));

			Kat(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[4]);
			Kat(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5]);
			Kat(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[6]);
			Kat(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[7]);
			Kat(tsx512s, m_message[1], m_key[1], m_nonce[1], m_expected[8]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer cipher tests.."));

			MonteCarlo(tsx512s, m_message[1], m_key[1], m_nonce[1], m_monte[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 monte carlo tests.."));

			Parallel(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 parallel to sequential equivalence test.."));

			Stress(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 stress tests.."));

			Verification(tsx512h256, m_message[1], m_key[1], m_nonce[1], m_expected[4], m_code[6]);
			Verification(tsx512k256, m_message[1], m_key[1], m_nonce[1], m_expected[5], m_code[8]);
			Verification(tsx512h512, m_message[1], m_key[1], m_nonce[1], m_expected[6], m_code[10]);
			Verification(tsx512k512, m_message[1], m_key[1], m_nonce[1], m_expected[7], m_code[12]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer authentication tests.."));

			delete tsx512h256;
			delete tsx512h512;
			delete tsx512k256;
			delete tsx512k512;
			delete tsx512s;

			// threefish1024 standard and authenticated variants
			TSX1024* tsx1024h256 = new TSX1024(StreamAuthenticators::HMACSHA256);
			TSX1024* tsx1024h512 = new TSX1024(StreamAuthenticators::HMACSHA512);
			TSX1024* tsx1024k256 = new TSX1024(StreamAuthenticators::KMAC256);
			TSX1024* tsx1024k512 = new TSX1024(StreamAuthenticators::KMAC512);
			TSX1024* tsx1024k1024 = new TSX1024(StreamAuthenticators::KMAC1024);
			TSX1024* tsx1024s = new TSX1024(StreamAuthenticators::None);

			Authentication(tsx1024h256);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 permutation variants equivalence test.."));

			Exception(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 exception handling tests.."));

			Finalization(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[9], m_code[14], m_code[15]);
			Finalization(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10], m_code[16], m_code[17]);
			Finalization(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[11], m_code[18], m_code[19]);
			Finalization(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[12], m_code[20], m_code[21]);
			Finalization(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[13], m_code[22], m_code[23]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			Kat(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[9]);
			Kat(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10]);
			Kat(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[11]);
			Kat(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[12]);
			Kat(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[13]);
			Kat(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_expected[14]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer cipher tests.."));

			MonteCarlo(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_monte[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 monte carlo tests.."));

			Parallel(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 parallel to sequential equivalence test.."));

			Stress(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 stress tests.."));

			Verification(tsx1024h256, m_message[2], m_key[2], m_nonce[2], m_expected[9], m_code[14]);
			Verification(tsx1024k256, m_message[2], m_key[2], m_nonce[2], m_expected[10], m_code[16]);
			Verification(tsx1024h512, m_message[2], m_key[2], m_nonce[2], m_expected[11], m_code[18]);
			Verification(tsx1024k512, m_message[2], m_key[2], m_nonce[2], m_expected[12], m_code[20]);
			Verification(tsx1024k1024, m_message[2], m_key[2], m_nonce[2], m_expected[13], m_code[22]);
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
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
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
		catch (CryptoSymmetricException const &)
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
		catch (CryptoSymmetricException const &)
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
		catch (CryptoSymmetricException const &)
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
		catch (CryptoSymmetricException const &)
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
		const size_t MINSMP = Cipher->ParallelBlockSize();
		const size_t MAXSMP = Cipher->ParallelBlockSize() * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		Prng::SecureRandom rnd;

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
	}

	void ThreefishTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

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
			std::string("F8D20CDCF99AE9F9C35629BE2A8DABB655C2F7DAC3383D4F8BAC1C925A84C80B"),																	// tsx256h256
			std::string("6D52E20BEE8B040F861FC98CF08C223816E462A1F56BC02B743F1E6828D21850"),
			std::string("75D7687989B945236E86DA7E4024C675BF31A685DC48C4AD9094803DCF5F0A0F"),																	// tsx256k256
			std::string("363F58E6DE31C5C2ABC0545B1A5ABD2650F9309B0180340A59761FFD8197D1A7"),
			std::string("18ACA3431FFBEF3CF0567FADE3512014"),																									// tsx256p256
			std::string("73E0F3B7150D0529423F115F779D6375"),
			// tsx512 mac256
			std::string("B623AA62A56655F9C43BCF8CC887F2D53F676AA07AE9D85678EBD72D2D183C02"),																	// tsx512h256
			std::string("91080FED4981AA6BE98794E6AAD015F17F358203DE72E5AFB90F72173506DFE8"),
			std::string("A14AA21191C0A13A86748F5883EDD36B695AC67228B12E6ABEC17EEDEFB84328"),																	// tsx512k256
			std::string("136A974A408ACFF09E368908BE96C75000AF3D06EEAC63E02176591FF1136F44"),
			// tsx512 mac512
			std::string("4C7A90F7130F2E110610A0D5DD1CD11D41F022034F6EFCE0C9C24034F8A7105F075BFE46F83C36D03BB5230D345C4C8D8B1A48B28F797B5342CE6B8C7CDC258F"),	// tsx512h512
			std::string("15D18F6E8B5C33BF8F884E8289F90CA658FB7909F9DFDC3C66FDB64AD15B1173F16B988D45A98EC9F82D128AE3512C3FFEBE9774EAE8DACD7D55D436EFECEC19"),
			std::string("00F917206A098405E3368BB059A29FD5933B39F902FA54818F8C88D4F4BF40A4F5DA63839B6524C5BE818B0F5EC7AD2F63CFDDD624B7B670688306D943660F1C"),	// tsx512k512
			std::string("998D0947CA9007E078B3200B7116B781FCA932AAF37DB8889605C67A24D736BE991E985EFC1CAA7BD66970D3E8218AAA67F2CBFDB912807C11E3987E1B2DCA98"),
			// tsx1024 mac256
			std::string("3BC942F466D7B2128E9910227D39E5BD38A08477FD70EFA0D5E0731338E4F887"),																	// tsx1024h256
			std::string("C14E9F879D42D03C98A69A8990BA964BE5CE816FD37B6DCB11AAE99ABD225BE2"),
			std::string("50315C8F3B3AAF5A3F2DA4AFDE20CBABDA95A34ADB0E3189F9D333781A9898BB"),																	// tsx1024k256
			std::string("A79275123E002286E3046CAD2C89FBED4AA7275941052B708E8C96AAAC1478C3"),
			// tsx1024 mac512
			std::string("F10E1BD5AE87B0048E4165BE843B943CC0B87327EB2A32F2C22A4F3B4D5893B7675A5572C96C106CE097360E9C681AE03226544762FBD9432E7333054A6226B7"),	// tsx1024h512
			std::string("50D0D95ACFA4F647451FA40ED082C4A287C1CCA005C2ABD5FF386E29464DE4633719ADEF621B529682EFB024E74A616FBE9625B2093DE27A166E91454226706D"),
			std::string("3B5E309ACB6F0B02C29CE80919C3C6B6AF3ACAC0B1364CDFFD3D58B6ADFAA4F2DFA584A2A5ECCE7C7775B573C6B649B78AF69ED368B0651D6C1899C42C2D1390"),	// tsx1024k512
			std::string("28514E2803824618DF06FDADED26A5420ABD04DAB5B78BBC9FFAD4C3EBD17ABE3AEF8014108417134D3710271795997B9D290A8B6058F27F563A25BF808843B9"),
			// tsx1024 mac1024
			std::string("B7B233507851787A141F104A4EB383D7CCD855B3CA706CDFE2BC58791C59535933DB56187F3415C1EB34377FD06F0D7B26FBB5F5718F876644C1171852C446C4"		// tsx1024k1024
				"CA37871AE3D179CD701C652B82EB007731D594448FC17C75D07262FE3F3DD6A73C7BE6DA693CDF8CBA203EEA87D224F888A84DA716FBC8875FCA7349F7357AFA"),
			std::string("10CE0FB50F3F2A0BA714417F47E562367034F1AA617C87D162841696207079090E670194960CC7E5109ACF373050991D55D77091915A3B48FDACDE0E6CE1614C"
				"E1D9964CBB1215745ECE32C1582F02F7437678AB1AE798834D9834C884E9DAEA83B211C60A51839A3BBA15DEC5CD10A42EF92B359A3B1C2751391779D7A700E7")
		};
		HexConverter::Decode(code, 24, m_code);

		const std::vector<std::string> expected =
		{
			// tsx256
			std::string("602602D74C6D54FF406572F502148C44CC40222DEE05D2CFB696986753362F6F"),																	// tsx256h256
			std::string("F483F8DAB670B5CEA16E1246683D87D567090519531908A433BFFDE65313F1CA"),																	// tsx256k256
			std::string("B23E2A97A52F75EE8C2207302BE54744BA8535CFA23935AC13EB58449A9844BE"),																	// tsx256p256
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),																	// tsx256s
			// tsx512
			std::string("4B94550861F4FBF0BC3C33CFBE912F65C26BAFFE15E19B05E71362EF2610CC7701AD6A6BD4F3FF03B9F9897821E584E05791BBA03B55E86F44394C222CEC87E3"),	// tsx512h256
			std::string("0488FF8CB0BACEBB0E577C5088033D67515F64F748668D90A685AE982FE4BA4976ED805D243163BAECCF8B7CF102EFCB82BA73382917F9B20B46264823DA9717"),	// tsx512k256
			std::string("F4E1C66FBB58953FD2B824377F70B35035092107C11D5A956235B8481B53EF560D919DC3D54B200F57485A05068397B63276D9F02F3753FEA3B4FDD58EACC409"),	// tsx512h512
			std::string("C59B94E79547F1167CA534438421FECBC73705D8D23E7EBDC0D573EE8C63D15E50DC6A5DBCDE0C2F02C36288242EBF7E313FA1B05405218A4624EDE79C81ED25"),	// tsx512k512
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),	// tsx512s
			// tsx1024
			std::string("C486F59614780B7C4ECE76D1AAADC297A4172C60FFF9D774ADD8041F6458FC77AFFB5742A1278341CA69BB331AC3419A42623015EB4C96C502C83A0023E4CFBD"		// tsx1024h256
				"1A03980B9673AE17F9C907E8598E9826B63AA094ACABE6803BECD75F10286F71188D7B27817C9C4EE81CA0BD432EE436014172C1F9EB6EF8A27FFF7BD32FF7EE"),
			std::string("999AF047E0EA529DF27EB2E982A06CC315D89D6B177B27F850994E3125F3322DC5360D0AC08354965717B7197EDF2E3C9649B991BCE3B2E66548EAE7127BD11A"		// tsx1024k256
				"BAF0956BFDEE3737B56397576A0F2A752584692C874CFD59F03FA5231340E0F2A37B1C4CB6A0662F9134FEC4EEEAA62F01FA8112300C9C85417A7850AC98CAAF"),
			std::string("20888D6A742053EC089207EAC73BE706EA29B81E14F6563D8A29680421BC1BD46F623A66C05C691A15574539AE5491AD18C52F46F94D53E040E191B57D8C1F2D"		// tsx1024h512
				"27514B1EFE98CB99C7C65121D007A57DA847E58EE32BDD86BD5A6AF8995DEAB33E8DC322EF259F2401760A7EC50FD3530185B4B412ACA391745E83BFB99EAB62"),
			std::string("808A6DF034185573A11F05417DCA72456D1515D441070BD3C15E1E23553E7AE1ED42143DA8FC53B8108F1A998182EDFCFEDD3ABDD9E827FA7711DB99676305EC"		// tsx1024k512
				"AFDBC49F341518A291CDEB9FA59F06E9899931C9CF237B76A0AAB0D823023B6E8DD7CE034C94CBFFF72938675674DDB258C710B3A79C55D0661CCA88E16ACFD8"),
			std::string("620EA1A99D97C38B8B8D4F1EC5F5102D8E863D39A90A28B9187D8372C9651A488740D3F64CE3A35160A9E9F9B020F211B8595E0C9D735C712D711E808B447B7B"		// tsx1024k1024
				"BE91B467D3255661CA9ADD426B770FEDC3A89C8E34FF91FE9D7FD2F53E41F3359874A77736EA234956C645AC34F8284C28F3956807CB175E86C5434866333F29"),
			std::string("B3F7134A5977D657479377A1224CA0ACF29C79B4AF0C8A23B269850F6DAEEDB37F8EFCD7F0B65BA7B4F5264E255B459E96AC4D1DD13D7957B6581DB116C7F584"		// tsx1024s
				"8BCD73FA5B588D28B0EE942F8E5F01C85E4E85B743B7CB0EC885B77533D733ABD811B6AB5D2AA25DFADA55138EEB5E3FF150BE937F1AB241DC374DB1F1BA6D09")
		};
		HexConverter::Decode(expected, 15, m_expected);

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
