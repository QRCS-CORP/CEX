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
			ChaCha256* csx256k256 = new ChaCha256(StreamAuthenticators::KMAC256);
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
			Finalization(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[2]);
			Finalization(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[1], m_code[3]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			// chachapoly20-hmac256: hmac(sha-256) vectors
			Kat(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256h256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			// chachapoly20-kmac256 vectors
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[3]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[4], m_expected[4]);
			Kat(csx256k256, m_message[0], m_key[5], m_nonce[4], m_expected[5]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[5], m_expected[6]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[6], m_expected[7]);
			// IETF vectors: non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[4], m_nonce[4], m_expected[8]);
			Kat(csx256s, m_message[0], m_key[5], m_nonce[4], m_expected[9]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[5], m_expected[10]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[6], m_expected[11]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer cipher tests.."));
			
			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(csx256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer authentication tests.."));

			delete csx256h256;
			delete csx256k256;
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

			Finalization(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[12], m_code[4], m_code[8]);
			Finalization(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[15], m_code[5], m_code[9]);
			Finalization(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[16], m_code[6], m_code[10]);
			Finalization(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[19], m_code[7], m_code[11]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer finalization tests."));

			Kat(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[12]);
			Kat(csx512h256, m_message[0], m_key[3], m_nonce[7], m_expected[13]);
			Kat(csx512h512, m_message[0], m_key[2], m_nonce[7], m_expected[14]);
			Kat(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[15]);
			Kat(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[16]);
			Kat(csx512k256, m_message[0], m_key[3], m_nonce[7], m_expected[17]);
			Kat(csx512k512, m_message[0], m_key[2], m_nonce[7], m_expected[18]);
			Kat(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[19]);
			Kat(csx512s, m_message[0], m_key[2], m_nonce[7], m_expected[20]);
			Kat(csx512s, m_message[0], m_key[3], m_nonce[7], m_expected[21]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer cipher tests.."));

			MonteCarlo(csx512s, m_message[0], m_key[3], m_nonce[7], m_monte[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 stress tests.."));
			
			Verification(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[12], m_code[4]);
			Verification(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[15], m_code[5]);
			Verification(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[16], m_code[6]);
			Verification(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[19], m_code[7]);
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
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

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

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN))
			{
				throw TestException(std::string("Authentication: MAC output is not equal! -CA1"));
			}

			if (!IntUtils::Compare(inp, 0, otp, 0, MSGLEN))
			{
				throw TestException(std::string("Authentication: MAC output is not equal! -CA2"));
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
			throw TestException(std::string("Finalization: MAC output is not equal! -CF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -CF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -CF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -CF4"));
		}

		// use constant time IntUtils::Compare to verify
		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -CF5"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -CF6"));
		}
	}

	void ChaChaTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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
		std::vector<byte> cpt(MSGLEN + TAGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -CV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -CV2"));
		}
		if (otp != Message)
		{
			throw TestException(std::string("Verification: Decrypted output does not match the input! -CV3"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -CV4"));
		}
	}

	//~~~Private Functions~~~//

	void ChaChaTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> code =
		{
			std::string("A39594A79F0FDEEE7DA96C6BF14740F359DF24E423F40C07C3A05D1B5E8FB224"),																	// csx256h256
			std::string("383D5FFC7E44C1F4BD2FD5F606727C9FF3E9A8B780D63BF234A43D5C088AC171"),																	// csx256k256

			// csx256 finalization tests: mac-2
			std::string("ABFA51E6C41EF64217027BFC086D9127D7F4BA76F70629F6D88F0D9CE3205D10"),																	// csx256h256
			std::string("39C267EA6C4D734D85253E289294114878D478E96C3075ACD27F3A63FF335992"),																	// csx256k256

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("0B084632CC4CA012ED52AA6E3D7D9CB4F541DDE8825D879DB7EA56D9659096FB"),																	// csx512h256
			std::string("7FCEBCFA1A3D3E398B49B551CC8ED8C9901F6A37F08EAEDB92FFA74C772D3EAA53B5A901C6DA292A203E82510E42A9DFDA78730AC905283133EDC53DF99A05F5"),	// csx512h512
			std::string("C3A6F4C77B699731F52A671E815CA3A81AB4D693FBD266F0A485260D28F962FF"),																	// csx512k256
			std::string("A064F63E44BF50830756C91BFBDE48DAB308D61EBB7EBF19CBE2983803DCCC1D9736734040EF165064FA71D2EEBD6048DE45B2EBDE760A87CA29BA6293E0A277"),	// csx512k512

			// csx512p80 finalization tests: mac-2
			std::string("84A73FAE2FF71DC088D1AC4C503F718A5E2A9F024960D634F9923EE5B1B95AF1"),																	// csx512h256
			std::string("5F37ED1A7B8FA0039C3E490244CB8755B3938150F4F0BF676EE5DBAC487379DDCE8E95C0E23B5FE240B8A3DA1CA25E847FE2FB51C7559E107F0ED0CB4A494C3E"),	// csx512h512
			std::string("4AE5964D83E104032379350AE48049AF28E37061D09CA1B4B6C55892A2CA4DB7"),																	// csx512k256
			std::string("FBB055FB1F8D1057F75C0228B4665C4ADCB47130F014FE12520655CE9EF4059F3D02E2A14058E764CBFF37E60BE28A30044DA772A2C0DDED31EB42A9046174B6")		// csx512k512
#else
			// csx512p40 - verification
			std::string("A9953EBED15DC72D782176FA7E3E9FF608C3DF05C5807B9B2F4FDD4C7900C680"),																	// csx512h256
			std::string("6ACF42408DA6BC2B1196415A83E48EC98A7CEFC702B0D3DB6A150CBD2297E4743A9B5C56DC731155BA0C5292F41E27C2E0D6598D078F828A512E328A64560AF0"),	// csx512h512
			std::string("8B16832B4B43AAFEF9727E4CF8E933960DA911A9280509E629BEA25A2BEF4DF3"),																	// csx512k256
			std::string("C2BE5A317D0BEF63FDD2BD0092CB29A61A7EDCCF16BB067FE744CFD62C84E4DC0D6ADB1CC5451168BF4CBB6D14ABDFE750248B2B08910BF92D706E7C0893ED03"),	// csx512k512

			// csx512p40 finalization tests: mac-2
			std::string("89F1D8424628EE9FF228297F8120714CF71BF9A8B97DC4A2BB56C555C8F56AF2"),																	// csx512h256
			std::string("E76D6004F90D007F3D9B0F1AAFFF562E8094D17F10BE50881CD37794FB6140C9D1306C354983867F98E4D2D3800392B68DE6E65D4ACA56C2C60A79F0A36C2DCF"),	// csx512h512
			std::string("C4E2F7D4941F4B99FE766BD1C0BCE2C1993DF43F1ECD02185A22E9AC5C4BC44F"),																	// csx512k256
			std::string("A6EDF24EF07E018AEC04B78A89A0E8F35170FC3A25FAA691C56E42B5DDEED187426E2A0E599C8592036B832C578A0D569F56E8807A02D7067A89940E578C1334")		// csx512k512
#endif
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("A991D2C9CA9FF63EB8310AA3D6EC77DC552D5BE4F5D340BF779AAAD48B3527A576BE0923E84C6495FFAA3BE6735C08B6FF8DDFD542673A50F98F44678989F041"),	// csx256h256
			std::string("9F788EB117A002E7C188565A5947E4F9DF909A5891231086A4EA33708CD4D089BDDC88A0D26D3D92BD34DA19142D1B1B3DAACF9556CA2F03B049CC62DD309DF8"),	// csx256h256
			std::string("A4E59655CDC3A6597E9B6013E263A52F665761D200013F6EFFBAEA1BCAEB444BAEB7FBB176F5C3E52466F26BDA11A62E27B74187092A246F22CE52D2B123F234"),	// csx256k256
			std::string("159DF936E9BD7E64BBBF23F70AD66F1ED734CF4C9016DBEBF001C2AC3E9E1C7D619D4128F35B084A553C938A7BD0D44822AE582FD8909EBA5DFEE685219C807D"),	// csx256k256
			std::string("E318D2D2A8DB6C70B71DCAAA5A9E0E655D85210AB1923E4F93C7C7EA824CBC9FF3CAAD9BA0022F3A39E60B70E5FDE09E0AF64DEAFBB93A63CE80A92E670CCE72"),	// csx256k256
			std::string("FD39998A115F0B8C1E7833944F9F3E857EE531D74FA5CC5FC8BEC44BCF6E2F5B4E6E1B87DD7F49A02190261B9672462897D4BBD426EDD309BD9BCEBDD53256AC"),	// csx256k256
			std::string("155CE519DA409555FD8E74C1C82195CF25152361D6E6D67DBA0BFA6B6CF445224641B050B746C6EAA0A91AEAC79274875488F2F9FA6726B6ED8648C830D4DBE6"),	// csx256k256
			std::string("C08D8F0C44FF4D0CDDF1DCF3A4683710E7EB44B5E276C5DC86A8D7CBA2839A6B876D2B423092C16ABB9B3AC95C36A677F69246EE3D082631B26C048B3E7395F5"),	// csx256k256
			// IETF chacha-poly1305 for TLS, test vectors
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),	// csx256s: IETF test vector 1
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),	// csx256s: IETF test vector 2
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E3"),			// csx256s: IETF test vector 3
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B"),	// csx256s: IETF test vector 4

#if defined(CEX_CHACHA512_STRONG)
			std::string("58BC2802EB5BDA70DDAE99D1DEABA98839FEF74107CC75F1D680CCD24BFCAB5FD93936550BB5698B677F9B3CEEB67129762F9595B6B427C45392BBB063CD79E6"),
			std::string("95D54389142122FC405E87C486A485E6122FA10C87CDA7D2BBA97A27252C04C331578D2D2723870E087544D3DC6CACE393E2DE99FDB117AF8C82138090BBCB99"),
			std::string("3C0FDA2F5D1BE03A878A7D6D50FFF171183308DFBA747F904E2EBC7927551411C204CB09FF12E440AC64BB298BB2A70FA63FA7FEC7E7A48948D0E218FF8E3EE6"),
			std::string("70D28AFEA4B117B00156E1A1C632E8D20E9B7E687A0C1654561657BD33A0CB4C48390B727430D4186C54C33084B16E42A3D090229904387D1517839C500975E9"),
			std::string("AC11DD37517A9A26C30FF6F22E2ECBA26D7A0C70D0F24FF234DBF527678BE30039F320F2710EE0A246BD6C8198722FE0E0773F35D69939845004A4DF4DDCCB47"),
			std::string("B13A9C5FF9069CE17737619028B5D8657E15593132DA4512CA3BA52B9E0C5392E26BEF8A9D6824C716A061EAA79F4466F9987A08EC79B295084C98558DAB972E"),
			std::string("2D643464118359BD43B4C4CA5EA297CA466769516920757AF81E0C753E6CA631261D6ADA2ACFF225D6686EB01A58D4591F527D5C97A98B6FE68CB479ED342700"),
			std::string("BE155498EED65C1F05B22F2EE22926B26AE963DA24D6F6DEB4D6117DE32818E5B4EDCBC2D4E3325E6F7A930A19F2C8668378D46E0FBB89E6EB0CB2755A38A0BF"),
			std::string("23A5B37570F6E3585EFB4614460616A926243B865CFD6C2C1CBFC33CC4C8B8F3C8F67FD56A9589C2C144D5F02029C9DEE003A7A6A7185AE697D242FD531F0D69"),
			std::string("DCBA51986EED0FDA2E15F9AD021B26CE17567A3EBE9F43FE8B5BD460527EDA8D77BB80C5B8BE29850A21428A7D390DF9631C5C126EFCED7E14441E8CD2A9AFF1")
#else
			std::string("420BCCB5E9CD77DE8929055E0B8CCBB9865D945E227411FCFCA191C5F9B64AED6CEC37AF00EE1B583935F1368C6A77C97F522C91430EA9E42E9EADCA8017F822"),
			std::string("17488B8E8D6A69818BB55508CA6E407E2302311969A643FAE8034D85F615367A677C90F8668AAA8819212A18F3536BCA4B0DE92F85F45BEAC385FC5BB62A75D6"),
			std::string("CA9ADF46D39490719E62676434064B3638E12D06480383E05462FD2A585AAE6B74A383362F0FD45170F56379F512561C0CF5D2E295BE52C350387CA589107109"),
			std::string("9994ADE320633AEF5924A467D17EDF25C68EB75859684E8430AEE62D396374F9C3BD25190BD9101715351B99B177C3EF9983D91073D8ECCAE31492F5C2645B43"),
			std::string("2E9EF32216F823C1200CFDA58B7D411B4B5EC7464679B1864CCE1E4330E40649DAC0706B5B959DE8505F945D4B1EED996C778BA0991D8F4D817DB55BAD2A23D4"),
			std::string("6D1BAA2981D6F2650D3819EF01D38F2F8A80B8A14D20A1947A4917B992629969B1E625D40538E8D96885DBC7B7B78D49982511DB112279051790BE28C6F7FAF5"),
			std::string("521C582B6FF692430FE2561EBB9DBFC9A99BECAA6366B2BD4F800D4B38250C08E87C2C176676B1430CE5A75EEEB0844A84762B84119FF53B16F989B1217381E9"),
			std::string("D448C80D3F80E8B9E2C301586AA214DA54B29A5C4D17DA5FF5AEF54914C6C535954F4E4568AFA4076C45D34C6BE2693DE5603639EE88520E2B46366DF88EFED9"),
			std::string("5ADBA319A0A42546444C3121E94D3AFA40B5E63CEC9C667109DEF0E17009399E74C994AB07D7631344CBF266754DDE31C265082A9B630E97DE287023AAED8A21"),
			std::string("C67BE57127D42320B584074F0964C75C643768B94E01C2D61A9F4071F71604D5F4A8A90A867FC47FA90592DEF26D36C72DC5CE7561B9AF564DCC217A19045175")
#endif

		};
		HexConverter::Decode(expected, 22, m_expected);

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
			std::string("3624BA23DB6CF0309371C68EDB94EBB83BE48266856BF95D34C457FE10C063A69D9590F04B816F249753BEDC3C21CECACBC09DA2DDEE3F0480CB63B086B6A8B1"),  // csx256s

#if defined(CEX_CHACHA512_STRONG)
			std::string("A4D6E529B5A3D23246521C00B303C50421D4993159ED3B75A10EAE99F01F7D55CC76BC49690BBB4856C25810C77BDCAAD34B97F62DC63E52473DD683181A82E9")   // csx512-80
#else
			std::string("C7713AA5B89B2F6ED4CE1FF40FA601B60C0DF81A6EB2E4AF71AD45706F04CBA8CF38E1CD8637410CE77E339A64577F30D29316F9B88F377064BDAC86AD277A17")   // csx512-40
#endif
		};
		HexConverter::Decode(monte, 2, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("0D74DB42A91077DE"),
			std::string("167DE44BB21980E7"),
			std::string("167DE44BB21980E7"),
			std::string("0D74DB42A91077DE"),
			std::string("0000000000000000"),
			std::string("0000000000000001"),
			std::string("0100000000000000"),
			std::string("")
		};
		HexConverter::Decode(nonce, 8, m_nonce);

		/*lint -restore */
	}

	void ChaChaTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}