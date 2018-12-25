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
			Finalization(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1], m_code[3]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256h256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			// default: chachapoly20-kmac256
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[4], m_expected[2]);
			Kat(csx256k256, m_message[0], m_key[5], m_nonce[4], m_expected[3]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[5], m_expected[4]);
			Kat(csx256k256, m_message[0], m_key[4], m_nonce[6], m_expected[5]);
			// IETF vectors: non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[4], m_nonce[4], m_expected[10]);
			Kat(csx256s, m_message[0], m_key[5], m_nonce[4], m_expected[11]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[5], m_expected[12]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[6], m_expected[13]);
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
			Verification(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1]);
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

			Finalization(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[6], m_code[4], m_code[8]);
			Finalization(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[7], m_code[5], m_code[9]);
			Finalization(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[6], m_code[6], m_code[10]);
			Finalization(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[7], m_code[7], m_code[11]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer finalization tests."));

			Kat(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[6]);
			Kat(csx512h256, m_message[0], m_key[3], m_nonce[7], m_expected[7]);
			Kat(csx512h512, m_message[0], m_key[2], m_nonce[7], m_expected[6]);
			Kat(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[7]);
			Kat(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[6]);
			Kat(csx512k256, m_message[0], m_key[3], m_nonce[7], m_expected[7]);
			Kat(csx512k512, m_message[0], m_key[2], m_nonce[7], m_expected[6]);
			Kat(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[7]);
			Kat(csx512s, m_message[0], m_key[2], m_nonce[7], m_expected[8]);
			Kat(csx512s, m_message[0], m_key[3], m_nonce[7], m_expected[9]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer cipher tests.."));

			MonteCarlo(csx512s, m_message[0], m_key[3], m_nonce[7], m_monte[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 stress tests.."));
			
			Verification(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[6], m_code[4]);
			Verification(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[7], m_code[5]);
			Verification(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[6], m_code[6]);
			Verification(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[7], m_code[7]);
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
			std::string("A0104EEFB30CDC749951579BB6BE12EA66902BC8513BC1E58B1511F14CC0DA34"),																	// csx256h256
			std::string("549753A171D4FB0D31BB884E9221B7289C91BF1FE8FDB3E558DCABD2851D4BD1"),																	// csx256k256

			// csx256 finalization tests: mac-2
			std::string("77ACB0912BD97AE199E7C7639D68D5016FF45619812464619DE65F2F16ED9D98"),																	// csx256h256
			std::string("66F8F60B01B121003321A299A3E09D12ED99A0EA764C45996D14ACF2028D62E9"),																	// csx256k256

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("A4C69322B046BF1955933A413F025991CB67FA1C33701FC726A70DB8A9A5A0AD"),																	// csx512h256
			std::string("211FE254682121610EDF7527287EE3DC3DBF331DABB6AEDDE640C9103142ADB403EDCB8C71F4D603F1560BB8757DC6E360C9455C0BC569443E7FACA6D928170C"),	// csx512h512
			std::string("752DA4ED2244D2DD3E917F6D776C663A6D1D088EA1D6EE9E29186BCD0B815CF1"),																	// csx512k256
			std::string("82958DB4B669F5EEBB6A5C82FEF5550AE653A2DF8E535B263EDCADF929F37579C268644ECF5E7310975755165AA6B4406FE0ECA9C13D5CC8090FDD1C82A7FA06"),	// csx512k512

			// csx512p80 finalization tests: mac-2
			std::string("415FBDC6C89888483DB93DB8B7BCFB6BEE1F3F8884D9AA50FDBCAFF499B18A36"),																	// csx512h256
			std::string("BC1188BF7B98F184B48E062B5343C26655AEB5ACD83B16C567B1513D1AD5B7D169086964FBE098A4F5A5635769CDD5AAAFEFC39229B51CCA1E5B40C703A72A38"),	// csx512h512
			std::string("57D1938BB000D703C26EB7979B3F4E686F20528F0490C534263B6828F0CCD8C9"),																	// csx512k256
			std::string("41F171C83BB5AECFD2F27AC4AC0D73315A3DAE7BFB166128646BB3BC0C66821208C9D7D56875307CF84677FBFB38F784FF0B8268DBBAC36DD3F65AAA9DF8F96D")		// csx512k512
#else
			// csx512p40 - verification
			std::string("256082DDF84FCCF19BE6CB5AF53D3E5C7A771AB217CE3602FD12D82F0E889254"),																	// csx512h256
			std::string("22E53BA1EDA9A4C66A6FD33971EF02C8D364F55D17D39091E2F19D4089019781EB260698682AED2DA2BB257CD152D30488429A9A0F52D5C322C4DE8AFE481D99"),	// csx512h512
			std::string("DA2A0F7BC0A31DED59713D302DDEE831B262141A33E391B6F31054F11262DAED"),																	// csx512k256
			std::string("C90122ED0E792CA819306B2D4E6AB68C2CD46A60945DD886E63F76EA62DE8177C85BC5F7C1FAC44FAF9746755807FC1389A8177E2EC5F40A8CE63A86338B954B"),	// csx512k512

			// csx512p40 finalization tests: mac-2
			std::string("DE4538650C5A4B7B6BFD38A408AFC2E812EE520D3DB432FA4F3F912944CD0571"),																	// csx512h256
			std::string("5711D5E018D33EBF5EC19E3C126836A94C77178D7C06DBD89295610D9E651848DC82120C872D0069B57705750DC517F98A5D4C8417D195ABA1303A8AA0159FBD"),	// csx512h512
			std::string("6059EB049167DD5107D342A637621DE838C7F0694F9EC4335C97703EAE9FBC9D"),																	// csx512k256
			std::string("4689F766E07C2E7468CC605BB02A3E9F433DC7D8C83FC631C82496BE4FE53ED6654E36B5873A20D4189E29970792F61BEDF2C29E536F999C601FD3BCDEE7D252")		// csx512k512
#endif
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("5820D2B2BF9D2D10EB87359DC639A21715A08C5D535E6439887D8B20E37C5FC7F80FA87324C898CB605975CDAFFE9E1736DF913E4D3720B6FA55DE73A6F2907B"),	// csx256h256
			std::string("39A1BB6F123B4FE8AF780CEB88FB3226049377ADF8C5F32D3A311697452073C6C7CEE34CC67641DD69F05D6266DE7EEF3DE4C359B4728F6D847454210D5E4C8A"),	// csx256h256
			std::string("F66211E346998E81F7D58A42FF371502141F67690001D28D8647B072D9DEC451433F828241F5B49CCD4A7AC0FAFCEB5F5642913D597CB3A742316071DAA7D8E9"),	// csx256s
			std::string("AF21CAA680572942CBF1589CC125021CB60A6E91F93E1719FD8F592633E34E2E27C5B31855E719A2AEA73E8B1AFEEAD85D8AAFC7E861B8888C0D682D5739FFA7"),	// csx256s
			std::string("81CB96EE5B99875A3F20540CC6257FFF0D5C70C9B82AD6809A5D806207353C60DCB7C22AB21FAA978B864C93E396C09613E2D775F4936216DF60A97F01ABEF07"),	// csx256s
			std::string("215ED5718249E565D83B0250C164919389FBD3FB9C6BFF3BDBD0C78954D749A2D859B2AD97CC2A90367EE10206DCB3F847A6EC3A4001BCCF3F7E6A98EB0D46A1"),	// csx256s
			
#if defined(CEX_CHACHA512_STRONG)
			std::string("06412BB11C35DCA2340F51820E4C0FA37566ACDFE97960447F03B668BEF8CB7D926E3CD4B82A21B96898585CDCEB2FAFD311ED57F68D4ACB24F9080040AFF86D"),	// 80r-512c
			std::string("1ED8EDBC3865FC41DF7FB648A45C7328372AA47B3D7BFE954F99BF4F9E91538E397A101F1D00770A686A1FA93F1B6C26D975A49571347DBFC1EBA8F93F7B0E1A"),	// 80r-512c
			std::string("23A5B37570F6E3585EFB4614460616A926243B865CFD6C2C1CBFC33CC4C8B8F3C8F67FD56A9589C2C144D5F02029C9DEE003A7A6A7185AE697D242FD531F0D69"),	// 80r-512s
			std::string("DCBA51986EED0FDA2E15F9AD021B26CE17567A3EBE9F43FE8B5BD460527EDA8D77BB80C5B8BE29850A21428A7D390DF9631C5C126EFCED7E14441E8CD2A9AFF1"),	// 80r-512s
#else
			std::string("039BE443D7DD231178541C999DC07AE8936CAD5B0882A11A962112E43C153FFE6C2EFB3D450B88FAB87881089A1A4786CA9842152268C971E0E238F4138C4675"),	// 40r-512c
			std::string("A95827381446A4E0C53F89D242D00EE38CDA9034CF364A2FF6D6937AC338C520D2156F80C16D31583E5DA1043BF1BFA783E22DC6CD5363887436AF5BE09C3C62"),	// 40r-512c
			std::string("5ADBA319A0A42546444C3121E94D3AFA40B5E63CEC9C667109DEF0E17009399E74C994AB07D7631344CBF266754DDE31C265082A9B630E97DE287023AAED8A21"),	// 40r-512s
			std::string("C67BE57127D42320B584074F0964C75C643768B94E01C2D61A9F4071F71604D5F4A8A90A867FC47FA90592DEF26D36C72DC5CE7561B9AF564DCC217A19045175"),	// 40r-512s
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
		HexConverter::Decode(expected, 14, m_expected);

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