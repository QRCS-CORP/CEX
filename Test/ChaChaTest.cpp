#include "ChaChaTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/ChaCha256.h"
#include "../CEX/ChaCha512.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Cipher::Symmetric::Stream::ChaCha;
	using Cipher::Symmetric::Stream::ChaCha256;
	using Cipher::Symmetric::Stream::ChaCha512;
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntUtils;
	using Utility::MemUtils;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ChaChaTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the ChaCha stream cipher.";
	const std::string ChaChaTest::FAILURE = "ChaChaTest: Test Failure!";
	const std::string ChaChaTest::SUCCESS = "SUCCESS! All ChaCha tests have executed succesfully.";

	//~~~Constructor~~~//

	ChaChaTest::ChaChaTest()
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

	ChaChaTest::~ChaChaTest()
	{
		IntUtils::ClearVector(m_code);
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_message);
		IntUtils::ClearVector(m_monte);
		IntUtils::ClearVector(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string ChaChaTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ChaChaTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string ChaChaTest::Run()
	{
		try
		{
			// Standard ChaChaPoly20 + authenticator
			ChaCha256* csx256h256 = new ChaCha256(StreamAuthenticators::HMACSHA256);
			ChaCha256* csx256h512 = new ChaCha256(StreamAuthenticators::HMACSHA512);
			ChaCha256* csx256k256 = new ChaCha256(StreamAuthenticators::KMAC256);
			ChaCha256* csx256k512 = new ChaCha256(StreamAuthenticators::KMAC512);
			ChaCha256* csx256s = new ChaCha256(StreamAuthenticators::None);

			// stress test authentication and verification using random input and keys
			Authentication(csx256h256);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 MAC authentication tests.."));

			// compare parallel to sequential otput for equality
			CompareP256();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 permutation variants equivalence test.."));

			// test all exception handlers for correct operation
			Exception(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[4]);
			Finalization(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[1], m_code[5]);
			Finalization(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2], m_code[6]);
			Finalization(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[3], m_code[7]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256h256, m_message[0], m_key[1], m_nonce[1], m_expected[2]);
			Kat(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(csx256h512, m_message[0], m_key[1], m_nonce[1], m_expected[3]);
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[2]);
			Kat(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(csx256k512, m_message[0], m_key[1], m_nonce[1], m_expected[3]);
			// default: chachapoly20-kmac256
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[2]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[4], m_expected[4]);
			Kat(csx256k256, m_message[0], m_key[5], m_nonce[4], m_expected[5]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[5], m_expected[6]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[6], m_expected[7]);
			// IETF vectors: non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[4], m_nonce[4], m_expected[14]);
			Kat(csx256s, m_message[0], m_key[5], m_nonce[4], m_expected[15]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[5], m_expected[16]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[6], m_expected[17]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer cipher tests.."));
			
			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(csx256h256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(csx256h512, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			MonteCarlo(csx256k256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(csx256k512, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			MonteCarlo(csx256s, m_message[0], m_key[0], m_nonce[0], m_monte[2]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[1]);
			Verification(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2]);
			Verification(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[3]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer authentication tests.."));

			delete csx256h256;
			delete csx256h512;
			delete csx256k256;
			delete csx256k512;
			delete csx256s;

			// ChaChaPoly80 is the default if CEX_CHACHA512_STRONG is defined in CexConfig, or ChaChaPoly40 as alternate
			ChaCha512* csx512h256 = new ChaCha512(StreamAuthenticators::HMACSHA256);
			ChaCha512* csx512h512 = new ChaCha512(StreamAuthenticators::HMACSHA512);
			ChaCha512* csx512k256 = new ChaCha512(StreamAuthenticators::KMAC256);
			ChaCha512* csx512k512 = new ChaCha512(StreamAuthenticators::KMAC512);
			ChaCha512* csx512s = new ChaCha512(StreamAuthenticators::None);

			Authentication(csx512h256);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 permutation variants equivalence test.."));

			Exception(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 exception handling tests.."));

			Finalization(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[8], m_code[8], m_code[12]);
			Finalization(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[9], m_code[9], m_code[13]);
			Finalization(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[8], m_code[10], m_code[14]);
			Finalization(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[9], m_code[11], m_code[15]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer finalization tests."));

			Kat(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[8]);
			Kat(csx512h256, m_message[0], m_key[3], m_nonce[3], m_expected[10]);
			Kat(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[9]);
			Kat(csx512h512, m_message[0], m_key[3], m_nonce[3], m_expected[11]);
			Kat(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[8]);
			Kat(csx512k256, m_message[0], m_key[3], m_nonce[3], m_expected[10]);
			Kat(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[9]);
			Kat(csx512k512, m_message[0], m_key[3], m_nonce[3], m_expected[11]);
			Kat(csx512s, m_message[0], m_key[2], m_nonce[2], m_expected[12]);
			Kat(csx512s, m_message[0], m_key[3], m_nonce[3], m_expected[13]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer cipher tests.."));

			MonteCarlo(csx512h256, m_message[0], m_key[3], m_nonce[3], m_monte[3]);
			MonteCarlo(csx512h512, m_message[0], m_key[3], m_nonce[3], m_monte[4]);
			MonteCarlo(csx512k256, m_message[0], m_key[3], m_nonce[3], m_monte[3]);
			MonteCarlo(csx512k512, m_message[0], m_key[3], m_nonce[3], m_monte[4]);
			MonteCarlo(csx512s, m_message[0], m_key[3], m_nonce[3], m_monte[5]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 stress tests.."));
			
			Verification(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[8], m_code[8]);
			Verification(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[9], m_code[9]);
			Verification(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[8], m_code[10]);
			Verification(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[9], m_code[11]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer authentication tests.."));

			delete csx512h256;
			delete csx512h512;
			delete csx512k256;
			delete csx512k512;
			delete csx512s;

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

	void ChaChaTest::Authentication(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t TAGLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> code(TAGLEN);
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;
		size_t j;

		cpt.reserve(MAXSMP + TAGLEN);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		// test large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(MSGLEN + TAGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(key, 0, key.size(), rnd);
			if (nonce.size() > 0)
			{
				IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			}
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
				throw TestException(std::string("Authentication: MAC output is not equal! -CA1"));
			}

			for (j = 0; j < MSGLEN; ++j)
			{
				if (inp[j] != otp[j])
				{
					throw TestException(std::string("Authentication: MAC output is not equal! -CA2"));
				}
			}
		}
	}

	void ChaChaTest::CompareP256()
	{
		const size_t ROUNDS = 20;
		std::array<uint, 2> counter{ 128, 1 };
		std::vector<byte> output1(64);
		std::vector<byte> output2(64);
		std::array<uint, 14> state;

		MemUtils::Clear(state, 0, state.size() * sizeof(uint));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);
		ChaCha::PermuteR20P512U(output2, 0, counter, state);

		if (output1 != output2)
		{
			throw TestException(std::string("Permutation256: Permutation output is not equal! -CP1"));
		}

#if defined(__AVX__)

		std::array<uint, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output3(256);

		ChaCha::PermuteP4x512H(output3, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 256; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation256: Permutation output is not equal! -CP2"));
				}
			}
		}

#endif

#if defined(__AVX2__)

		std::array<uint, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(512);

		ChaCha::PermuteP8x512H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation256: Permutation output is not equal! -CP3"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<uint, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output5(1024);

		ChaCha::PermuteP16x512H(output5, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output5[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation256: Permutation output is not equal! -CP4"));
				}
			}
		}

#endif
	}

	void ChaChaTest::CompareP512()
	{
#if defined(CEX_CHACHA512_STRONG)
		const size_t ROUNDS = 80;
#else
		const size_t ROUNDS = 40;
#endif
		std::array<uint, 2> counter{ 128, 1 };
		std::vector<byte> output1(64);
		std::array<uint, 14> state;

		MemUtils::Clear(state, 0, state.size() * sizeof(uint));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);

#if defined(__AVX__)

		std::array<uint, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output2(256);

		ChaCha::PermuteP4x512H(output2, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 256; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output2[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation512: Permutation output is not equal! -CP1"));
				}
			}
		}

#endif

#if defined(__AVX2__)

		std::array<uint, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output3(512);

		ChaCha::PermuteP8x512H(output3, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation512: Permutation output is not equal! -CP2"));
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<uint, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(1024);

		ChaCha::PermuteP16x512H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException(std::string("Permutation512: Permutation output is not equal! -CP3"));
				}
			}
		}

#endif
	}

	void ChaChaTest::Exception(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("ChaCha"), std::string("Exception: Exception handling failure! -CE1"));
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

			throw TestException(std::string("ChaCha"), std::string("Exception: Exception handling failure! -CE2"));
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

			throw TestException(std::string("ChaCha"), std::string("Exception: Exception handling failure! -CE3"));
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

			throw TestException(std::string("ChaCha"), std::string("Exception: Exception handling failure! -CE4"));
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

			throw TestException(std::string("ChaCha"), std::string("Exception: Exception handling failure! -CE6"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ChaChaTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
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
			throw TestException(std::string("Finalization: MAC output is not equal! -CF1"));
		}

		if (!IntUtils::Compare(code2, 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -CF2"));
		}

		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -CF3"));
		}

		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -CF4"));
		}
	}

	void ChaChaTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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
			throw TestException(std::string("Kat: Decrypted output does not match the input! -CK1"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, Expected.size()))
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -CK2"));
		}
	}

	void ChaChaTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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
			throw TestException(std::string("MonteCarlo: Encrypted output does not match the expected! -CM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo: Decrypted output does not match the input! -CM2"));
		}
	}

	void ChaChaTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;	
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
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
				throw TestException(std::string("Parallel: Cipher output is not equal! -CP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel: Cipher output is not equal! -CP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ChaChaTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

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

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress: Transformation output is not equal! -CS1"));
			}
		}
	}

	void ChaChaTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
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
			throw TestException(std::string("Verification: Decrypted output does not match the input! -CV1"));
		}

		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -CV2"));
		}

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code, 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -CV3"));
		}
	}

	//~~~Private Functions~~~//

	void ChaChaTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> code =
		{
			std::string("B0C905554F91231E6EC46E21B3034DD96191C3FAFC889838B135F9E2AE2AF7E8"),																	// csx256h256
			std::string("9D1FD40468A730474AFA8789891722FFEC143BC7DB701DFADD01F3F33911FFE7B69754C4E37CD3AE84BC843ABF7386714232862A3F8AA0F3C9985E785379A235"),	// csx256h512
			std::string("7C10AE9FC18AF04C4002FE3F8C21146F5F69736F47F0F41555E219514798FD29"),																	// csx256k256
			std::string("01E8ACAE1B96A76FA94CEE5AC13EED86EE61A12A15CFD8AEBCB96F855441DA5058CBA964E54322B535ACAF53FCDAD67867AEBEC7A8DE7001F5A78B44FC0A54C0"),	// csx256k512

			// csx256 finalization tests: mac-2
			std::string("903CF3362B553BD6EBCF999B500676D77F7F1EC69EDFF1E3E329CAD1D19E0835"),																	// csx256h256
			std::string("9AB627E453768234FD7B4120F5D7087BC6B1AFBD065C03EA28CA2BADAEA502DF22EADFB6546115CC1FDB753862464E50086DA72B63FE81B84B5648AF550CEED3"),	// csx256h512
			std::string("0DE735892A9EB0AC4EC7C2B2F20B020A0CE7AD49ED15360F8F821CC08718B0BC"),																	// csx256k256
			std::string("218500975BD39D7815A8DB18FE950C5099A38DE9B535CE773D9AEE71680CA864DBD7C452070DB84760C30EF8A9090E554EDBC5E0634279E5C9D457E14DCD24F2"),	// csx256k512

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("CA9D818A71CDADF62DB04ACBBA85ECB03A82F8FBC2819A4FAF8BD8FF6CCAA253"),																	// csx512h256
			std::string("33AC9A448240B4B3214DC8E068666D5B63341E80F8B7093A69166DBCBF6B5CC4AA95F84607D6345B86BCEEA287C205FF4ADA15F70B2BF710A02F46C47A3A11D9"),	// csx512h512
			std::string("7984855BD86FBD21091382FFDA9FEBFFEBDBE8A339CA749A030966EE7546AA0D"),																	// csx512k256
			std::string("03C11C414DD614C147AB216724D6C4FD6A6F78D66A043019934EDD132068A9575EB6DB0A849B741C6C135780CE7879457CCDBD5F62300548BD4CAC3676728B18"),	// csx512k512

			// csx512p80 finalization tests: mac-2
			std::string("30BF629DF5DEB8B374AB2EAFC66C1093267CC351493C3951152E28E2888DEC5B"),																	// csx512h256
			std::string("8B7206DB1E3170AB809D34A251A95088BFC2ED12680A4862980D6D2508E7D515E48ADDA901C65C61A6B678B886B342321517B1E5FB90B07D4B59A66366F4B635"),	// csx512h512
			std::string("30C1A3D24AED8B9CF029D865F90D0A45FB63DBB6C4DFB6947D13837F5C8F7EEA"),																	// csx512k256
			std::string("DB021373ED8BEC5000CD6232D00144B2DF3A1A3AD309C6695C9F8D9FB58FB9A85E7D672657B38DD5D3038714C53ED2C09D100D6479544F0C6ACF008EBFA672D5")		// csx512k512
#else
			// csx512p40 - verification
			std::string("691007615DE3D823669B360E964271923CE1128533D328390CAEBBD650011046"),																	// csx512h256
			std::string("73C3BEB98CBCB1813A82A8BDE11BC9879D2576B32834871500011D64D25839B1D3CC77E663C8A7510E4FC39844FB74AA5667854D39CCAE010DD809B0BF9B357E"),	// csx512h512
			std::string("B13111DAF7B1B4C7699A63C9B025CD34A2282B2D782B8B48A749B790444853C8"),																	// csx512k256
			std::string("4EE95CB107D9539981CA0C67C71FD4277A22ECA9A8C186CD8F37596320DBA698526086077E8FD49F3310891F764AE7047751DD7F9F446BA49E18D9B275994095"),	// csx512k512

			// csx512p40 finalization tests: mac-2
			std::string("541D6F4CFA584D223393EB1632B70769239C4A1FB4F30837B3C924C33DCB70B5"),																	// csx512h256
			std::string("A44FEF649FD0F12E2ED21C960D13F1107C8F842565894B10003846430560AB45CB9051D6D5C1E6E5BE35BABC7E7A1F2A28ADEB368295F86B6A6229DB12C6B600"),	// csx512h512
			std::string("A0F62357BAEC20D11A7C87FBE0E2502E00F46E39E350E0FBC78298A93366AB2A"),																	// csx512k256
			std::string("9B00FE4B17CF05C2E0ECD2AD90A60289A587FABD09086BB58C015026B0B3E72AB1754BA9B5EE2B0B111061D7F33DE33620476E3A5498C63A4EA874993B3B22F6")		// csx512k512
#endif
		};
		HexConverter::Decode(code, 16, m_code);

		const std::vector<std::string> expected =
		{
			std::string("5820D2B2BF9D2D10EB87359DC639A21715A08C5D535E6439887D8B20E37C5FC7F80FA87324C898CB605975CDAFFE9E1736DF913E4D3720B6FA55DE73A6F2907B"),	// csx256h256
			std::string("90DD44BCCF955FDFF98BFED3E14F149384CED3BF18C4884DF099C49D9BA77C0DB64621A1D9D0B272B727C7F91565D8FE32A8252E8F07CD75DDE7A05FE3B1217D"),	// csx256h512
			std::string("39A1BB6F123B4FE8AF780CEB88FB3226049377ADF8C5F32D3A311697452073C6C7CEE34CC67641DD69F05D6266DE7EEF3DE4C359B4728F6D847454210D5E4C8A"),	// csx256h256
			std::string("2BC828E740B604163FF1580E64B9A97CEB1F45B05E6A4EA29EDC0A311F40020D8B49B3D4B318A41436D5F1487D8C59E87651335E96F11E1E8BFC0A4F541B92FC"),	// csx256h512
			std::string("F66211E346998E81F7D58A42FF371502141F67690001D28D8647B072D9DEC451433F828241F5B49CCD4A7AC0FAFCEB5F5642913D597CB3A742316071DAA7D8E9"),	// csx256s
			std::string("AF21CAA680572942CBF1589CC125021CB60A6E91F93E1719FD8F592633E34E2E27C5B31855E719A2AEA73E8B1AFEEAD85D8AAFC7E861B8888C0D682D5739FFA7"),	// csx256s
			std::string("81CB96EE5B99875A3F20540CC6257FFF0D5C70C9B82AD6809A5D806207353C60DCB7C22AB21FAA978B864C93E396C09613E2D775F4936216DF60A97F01ABEF07"),	// csx256s
			std::string("215ED5718249E565D83B0250C164919389FBD3FB9C6BFF3BDBD0C78954D749A2D859B2AD97CC2A90367EE10206DCB3F847A6EC3A4001BCCF3F7E6A98EB0D46A1"),	// csx256s

#if defined(CEX_CHACHA512_STRONG)
			std::string("716E1BDC7BDA5FD2F1D7EB84432EF4B1F1BAC4E7A5A905FC24D25521BB3E6F58DC22F791DEDE440583394CF614A371BD6C14D253323B3B4F0BF17506DB08F155"),	// 80r-512c
			std::string("AB7F86209C2C8202ADEAA248F3067325096F07521F3F68013D27BC92CA8FAF999089DC20453A0F4B4693BB85569880887D4D0D2A81C326036320D3C5D4A24368"),	// 80r-512c
			std::string("41ABC7B51F100D6D0BAA25F0AAD9C411A2EA4CAF7F5EE70CF4273C7DB83D6C8745314A621805F3C4CE2D4BF61033F7BD2D6BEEA6C82FF70DA96B641A0D0287A5"),	// 80r-512s
			std::string("9DD867BCE8BD9FC5111E5F635698034D20518D95493410EC4F968C97E086E61F591765AEDC3B5FC1C86318C88AA682412A82316B947322D7683F47EB61AE1ADA"),	// 80r-512s
			std::string("E8B7594B1C5FFBE43D52318EB1B1E9231E2DD50275C9A6E5CBF33DACED3B2EF4B2FAD30DADD96FC634EBFD4D3897DE8A0DE9D3F846CDE0AA7EA31EA08A2F444F"),	// 80r-512s
			std::string("54B70E75C5B79BBFCCF88DE2B1C356EB385C05C2F3AF91EE803A5AE8396F3DDDAF8D41DF905AA242AD7F27126596A829B890B34621F5E267C1D46DA8A44BEA8B"),	// 80r-512s
#else
			std::string("B04981146EEB2E62EB522345D76886BB49A2CA9327CDA1806668EF52C766FD67B649A45150BB3222932F8E1E579F08ADE4865F1267B6EDF970D4DECC90898E98"),	// 40r-512c
			std::string("FA60D4B97C7BAAD4EBDEE4B0B800CE10759DF6ECFE4C813207E2D6D2B9830DAC7395CD8855F050843F1D83EF21959198F8AB286DE91FA79309506E88C6A85B5B"),	// 40r-512c
			std::string("EE8C5F81FF6CBAEAEB4FA358883F908070099489EB4728A84A3D9680ECD70DB3984A7C40A22C53914703759261758894EC1EAD2BAC6683DD66873BC3605C325A"),	// 40r-512s
			std::string("B58C72C70C9215FA9A408A1E67BC513C6663A1965125BA148D59427B1B8A82CBDD5FBE5EAC2A527427B39CABEF6FF37E36A3089169DFA675DE7399B97426055D"),	// 40r-512s
			std::string("87E9E06B911153EEF0291D1C4B5624DCEBE9D64228D30FFD56F940923531A8E8D1A9013F1957D758E0330D92977987ED45A50053B8154586D739F4CDA6D6E6DE"),	// 80r-512s
			std::string("67EB972A7390E2B4971D0BBCB17F9BD8A8C135E83B9D5338B9D66426E4B8495A9B4E02BE2DE52A8FB139BDA519728AC519EEBD8F3AC2495F4088E49A2C54DDB7"),	// 80r-512s
#endif
			// IETF chacha-poly1305 for TLS, test vector 1
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),
			// IETF test vector 2
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),
			// IETF test vector 3
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E3"),
			// IETF test vector 4
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B")
		};
		HexConverter::Decode(expected, 18, m_expected);

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF120053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			// TLS chacha20-poly1305 test vector 1
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			// TLS chacha20-poly1305 test vector 2
			std::string("0000000000000000000000000000000000000000000000000000000000000001"),
		};
		HexConverter::Decode(key, 6, m_key);

		const std::vector<std::string> message =
		{
			// IETF poly1305 test vector 1
			std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			// IETF poly1305 test vector 2
			std::string("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69"
				"636174696F6E20617320616C6C206F722070617274206F6620616E204945544620496E7465726E65742D4472616674206F722052464320616E6420616E79207374617465"
				"6D656E74206D6164652077697468696E2074686520636F6E74657874206F6620616E204945544620616374697669747920697320636F6E7369646572656420616E202249"
				"45544620436F6E747269627574696F6E222E20537563682073746174656D656E747320696E636C756465206F72616C2073746174656D656E747320696E20494554462073"
				"657373696F6E732C2061732077656C6C206173207772697474656E20616E6420656C656374726F6E696320636F6D6D756E69636174696F6E73206D61646520617420616E"
				"792074696D65206F7220706C6163652C207768696368206172652061646472657373656420746F")
		};
		HexConverter::Decode(message, 2, m_message);

		const std::vector<std::string> monte =
		{
			std::string("3F7FA9CFB44E78D277827206B2B91A0025188AA0AD93C0E72D05D1E8E92E982F72EFDABC4AE6237EC50771B84B3F9F069A7C3C0BBA0FECFDD8F05BE601D90CCA"),  // csx256h256
			std::string("BCB75CB01E5DC295C1EC80B0941ADC34032BC045D33F00CBB87133921EF70470C35ED872C556C78FEDD9B7894661E8522B6512214E78BC2AE98BC7EBF5997399"),  // csx256h512
			std::string("3624ba23db6cf0309371c68edb94ebb83be48266856bf95d34c457fe10c063a69d9590f04b816f249753bedc3c21cecacbc09da2ddee3f0480cb63b086b6a8b1"),  // csx256s

#if defined(CEX_CHACHA512_STRONG)
			std::string("D82427B64DAC0C5515C6378AA0F64EC0C8F7E6291FE591326B8420098045AD9939151D182C93FD49BCD38AA46AC33EAE92C492DD270D6C46D47270F1F7D89F9A"),  // 80r-512c
			std::string("6AAEA1E6EEDD2AD04AF889F2F343862DEDDC9A7763C7F2357FE2C0719F9BD7E238DD76793F10BDB03A17D75FEA0BA5D6B3C85F992B50FBF7D492D3F6576D6B8C"),
			std::string("3A8FF5F63349F7446D7D66244D4059D79AEC43226761213D01EF75C097CB14D7FA52F0F2C3E9B9D6D500527E5F907B317517ACA93CCD9792323D93AD20F0047E")
#else
			std::string("1951F948779960792FF44DB976EC427D3E55B71EC81E25EB514B4777755F5551B02D38A3CC9B70CE699ED1BB9F35788D5EF614EF2688F09CB6A7DEA5E62E5A4A"),  // 40r-512c
			std::string("EEE0831816C55CDBCEF69EE7457F56257906B46B9788D16FE6A308151A6F8140B633C21778203A292E2C411B35DC30EF5D3D099CD4FCF115BAE795EE3A979FDA"),
			std::string("5C3EF665FA206CD9698B85B355271590E6C1C290AB2920E5CD875C741BAB7AC75B7A8B55CAF55422FB741CA847D8C922C4D247F492D2F7388EE97BC2B1FBB73B")
#endif
		};
		HexConverter::Decode(monte, 6, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("0D74DB42A91077DE"),
			std::string("167DE44BB21980E7"),
			std::string(""),
			std::string("0D74DB42A91077DE167DE44BB21980E7"),
			std::string("0000000000000000"),
			std::string("0000000000000001"),
			std::string("0100000000000000")
		};
		HexConverter::Decode(nonce, 7, m_nonce);

		/*lint -restore */
	}

	void ChaChaTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}