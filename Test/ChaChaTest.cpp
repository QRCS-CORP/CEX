#include "ChaChaTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/ChaCha256.h"
#include "../CEX/ChaCha512.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
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
	using Cipher::Stream::ChaCha;
	using Cipher::Stream::ChaCha256;
	using Cipher::Stream::ChaCha512;
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ChaChaTest::CLASSNAME = "ChaChaTest";
	const std::string ChaChaTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the ChaCha stream cipher.";
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
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
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

	void ChaChaTest::Authentication(IStreamCipher* Cipher)
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

		// test large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(MSGLEN + TAGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			if (nonce.size() > 0)
			{
				IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			}
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
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -CA1"));
			}

			if (!IntegerTools::Compare(inp, 0, otp, 0, MSGLEN))
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -CA2"));
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

		MemoryTools::Clear(state, 0, state.size() * sizeof(uint));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);
		ChaCha::PermuteR20P512U(output2, 0, counter, state);

		if (output1 != output2)
		{
			throw TestException(std::string("CompareP256"), std::string("PermuteP512"), std::string("Permutation output is not equal! -CP1"));
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
					throw TestException(std::string("CompareP256"), std::string("PermuteP4x512H"), std::string("Permutation output is not equal! -CP2"));
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
					throw TestException(std::string("CompareP256"), std::string("PermuteP8x512H"), std::string("Permutation output is not equal! -CP3"));
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
					throw TestException(std::string("CompareP256"), std::string("PermuteP16x512H"), std::string("Permutation output is not equal! -CP4"));
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

		MemoryTools::Clear(state, 0, state.size() * sizeof(uint));

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
					throw TestException(std::string("CompareP512"), std::string("PermuteP4x512H"), std::string("Permutation output is not equal! -CP1"));
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
					throw TestException(std::string("CompareP512"), std::string("PermuteP8x512H"), std::string("Permutation output is not equal! -CP2"));
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
					throw TestException(std::string("CompareP512"), std::string("PermuteP16x512H"), std::string("Permutation output is not equal! -CP3"));
				}
			}
		}

#endif
	}

	void ChaChaTest::Exception(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE1"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE2"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE3"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE6"));
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

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF4"));
		}

		// use constant time IntegerTools::Compare to verify
		if (!IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) || !IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -CF5"));
		}
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Output does not match the known answer! -CF6"));
		}
	}

	void ChaChaTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -CK1"));
		}
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, Expected.size()))
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -CK2"));
		}
	}

	void ChaChaTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Encrypted output does not match the expected! -CM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Decrypted output does not match the input! -CM2"));
		}
	}

	void ChaChaTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
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

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
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
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -CP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -CP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ChaChaTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
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
			cpt.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -CS1"));
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

		if (!IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -CV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -CV2"));
		}
		if (otp != Message)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Decrypted output does not match the input! -CV3"));
		}
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Output does not match the known answer! -CV4"));
		}
	}

	//~~~Private Functions~~~//

	void ChaChaTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> code =
		{
			std::string("6638E9C07B0B56AAFAF06543269FBA9DAFE8F20E557FB538306620A5AAE93A5A"),																	// csx256h256
			std::string("4EC130FEF93D6FF71F29820681EA0E4F71A05748D895DE2FFA4292D98347D209"),																	// csx256k256

			// csx256 finalization tests: mac-2
			std::string("DE329466ED4A3199E52483EBB76CA0F751F040DA796AFB465AEC56F1CAE124A6"),																	// csx256h256
			std::string("3ADD4B11290E054215FC56D5D6E9D29F10357399FF95257572B8A3917A6AED87"),																	// csx256k256

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("372B81A0D05393C96A886698765006D43D87633B0791A56890FC0F5DA1D1EE40"),																	// csx512h256
			std::string("EE971CEEE8746BD884683A888D1F5CB7FBC7AC20C99108A3D6C83257F621A60163FE11EF9D6F19CDB9CBBFB01634EF05E1664F445F75E86B9B0BF513E7DA244A"),	// csx512h512
			std::string("BB1056615F3E8F2A3D33FF44C212D24942E9B614AD02B3930B3CAF9B5DD10CC9"),																	// csx512k256
			std::string("D41F410ED5F7D5333724AED9EBE3D5081719978E9A2E604BF128FACA49E625AC8B1272AF85E836F6EE319E905B78D6ED08AB3498A2454EC52422DBD77FA4569D"),	// csx512k512

			// csx512p80 finalization tests: mac-2
			std::string("03EA3F4E7A557CAA67A2A1B09BF132DC20C11EC628031A4DC669C180B8E8E164"),																	// csx512h256
			std::string("95A593D639F7A7225D4FF55056C92D5197C1896A65EC74EA93E915FA99E3A0F84BDB9768E047A9ED9C1BC0FEFED06692303332C4617D9374D34AC9B57052ABBC"),	// csx512h512
			std::string("5E489A6C2DB134B735E7CFE98FD144DDCE05600DE8552F0317E504B2B251459F"),																	// csx512k256
			std::string("BE7D12EA0C4EE67288CCFE927AF5B156CE6C0E5A178CC8CB539EFAD25B9AF9E3066C8DBE559DA73B493DE97A1CA1926DAFA3E69B5AEFC8DF221CBD96E571C41E")		// csx512k512
#else
			// csx512p40 - verification
			std::string("134C58038A7C32AA80DF20B794D48D92924108BA08FE5A7C987B09850B4F57F6"),																	// csx512h256
			std::string("5B060B3FAD2B6F8F490E8AF2DA05F912FB6A5C8DFD3E0F9FEBAE61C30914246E30361D67A4EA096C9AB8541356908269EF0C7ABC0D6EEA6649E5640350A08234"),	// csx512h512
			std::string("57AE41792A553522DC0777FD7A5410336D2D0FB9069F142128AE931DCA132555"),																	// csx512k256
			std::string("744261C0F32058C8256542C3712CA3CC38FBD0DDAD9614E0022119F965D3E778D17F81D440768B80EA6142E5A90229A06CF1CEB346B03D33902C47059FBAACD9"),	// csx512k512

			// csx512p40 finalization tests: mac-2
			std::string("8A5F004FA20FABF0367197004F3414D66847041F2826A0C41A837C25DC77C8A1"),																	// csx512h256
			std::string("D02E1037378CF8F6E224CB9073F42BD053EC3A83B50C9961ED6B3A6C7EC0324A2E6C5A504A36606687C0548EA96AF5298AD94C4E334B129203E3995E5178A6A0"),	// csx512h512
			std::string("CB348ABC78DC486044E4C3C8E54E026286DEF5B70627664EA32F820C9938929A"),																	// csx512k256
			std::string("D60386482B2165C7755ED3358AF7CFD02F921516A91B9999D51BFE81C6B7FC9489835C8F1985538BA1A5A218B0EFD60B3A3377011F4F2F4EB2E7682E557AD67A")		// csx512k512
#endif
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("AFA6F8F9B527053F0E7F242E49947EC5791D121C37D0C295762B8804F53A5DAA2BE48F976055177C825F2E1CC1AA80D9B45E77A252F905A30C3B3D64C800A83C"),	// csx256h256
			std::string("B01A0425D63C8C7F27FD956D7528DFF316AA00D818DADD6CEE9073802AB5047FCE93FF18CABD09BE6EA6A9EDCEB031923DEA24185BD358B9E3CAF9C23381B408"),	// csx256h256
			std::string("B318E77F38D67A6B4E82D47297C5E5D4AB7537AFBACBA384423A90C55FF2481C22D3FFD15A8FD2879636DD81650D6B0B5A88F0F91040C333E55EFE36528B34AF"),	// csx256k256
			std::string("3F2C7538E080631DFB67DA75E70FF7929B1073C2D2D968107C190A4077F7EF171BED1D853938C680F046D79A8E3DC2E3BAEEB0BA51E98DCB848DEF864E575A44"),	// csx256k256
			std::string("F77DAF38A1D5054D24C0F1DFD0989CA00B47393A36BFDD731521353730DE0F60B7684121CF480B9F3F11232DE28277050C98C26FD61CD7F48F093DA2A92DF037"),	// csx256k256
			std::string("9DD37AB5D781BA65C91BC4B4C1AF826197BEC0B8EBAF308B2BDB7E85411EFE06313721238B67D3CF1CDC279AF0D39757E6F5EB0C7D4338E92F0DBFFDCEFE57EF"),	// csx256k256
			std::string("EBA022DC33D77E1213522571D14201C3657797BADC093568C913B36A60A7CD1F4D566FC4E8D5AA8D49C19CE51222ECD9E5849EDB1A99E4C47ED13C84360616C3"),	// csx256k256
			std::string("D6D56F1B78D046F351C5474B9A271356240637AA3A47E771FAE0CB244652BE6E87577A2FDBBEF9AADB794E348A5F7DA064137A4F92BACA4DF867581C5B54900A"),	// csx256k256
			// IETF chacha-poly1305 for TLS, test vectors
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),	// csx256s: IETF test vector 1
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),	// csx256s: IETF test vector 2
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E31AFAB757"),	// csx256s: IETF test vector 3
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B"),	// csx256s: IETF test vector 4

#if defined(CEX_CHACHA512_STRONG)
			std::string("34615F7934D518A5AFB2B72A794424B0C583E8C7A88F33AE63E3B167972730922E284365FDA9D92889D5DAEAE94A0490A747D2DBF0C536F0FD205D3A81981509"),
			std::string("FA812E839B6234590E89E8B7FDD3982EE41E59807C567C670AF1E1166E516984815FA314D0A7819701814AC2F800E8427CA03A482C9983E18FED2EAC15996487"),
			std::string("CBDCFCDE1070CE61FD55512A6682E3ED50DCBF9E85AD0A0E00B279BBB3C13BE924A1DF04A39B73689F1DB48C04789DBBDF36A8C23E71B615690CB38CCCFE97BA"),
			std::string("F35502B5B1809920BFC46CFA13ED560D4F546DD324EF26F4DDD92F97CC79B0141650A0FAFDA3902DD8BE5C903404C04A683CEFE5D10133D25ACF2A52CF99DA09"),
			std::string("ED1AD1E5DB57E25EA593B616187C5A70E8CF6743DC0C32323B9938159E73058A2F86859B15A1F342B0304B222A88B7133B07405BC1BD5F29A5469D5A76E5B93A"),
			std::string("8E1C2C27B78F84815E860087E2B6822DA52D443F046BFB658F1EE5AC862B3C12180A210C60D5E277C2D31AB3757FD8C161E9A82A1B9E8886ED04F2956CE7D252"),
			std::string("A3F9827B3589780409D750050995D7E7E3F40F72534F7E4537544F530088CE84EB6EE59033FFCE2942040D4881EE6E1DB992625A8762629A1B76DF66ABA53E72"),
			std::string("8DE302EB7762FB38F1EE9FD08C69EC6F9AA25321F83DE484E4253697DF0F06F97C391CFF4B1BC78420A60A0F58F8ACA37875F57CB23D64A980D2F0C1A55621F1"),
			std::string("23A5B37570F6E3585EFB4614460616A926243B865CFD6C2C1CBFC33CC4C8B8F3C8F67FD56A9589C2C144D5F02029C9DEE003A7A6A7185AE697D242FD531F0D69"),
			std::string("DCBA51986EED0FDA2E15F9AD021B26CE17567A3EBE9F43FE8B5BD460527EDA8D77BB80C5B8BE29850A21428A7D390DF9631C5C126EFCED7E14441E8CD2A9AFF1")
#else
			std::string("21AA224964A24744C1D171CAD96C36EB3074E96363DAA5496C138CC52B4AAFA1C5442D1564416F56373C6CBFA9418002B0733A1C1EEC4EF2E8943BD5F54A711D"),
			std::string("4BF93EC53EE2143A833FD6C968DC1445C331A94514ABA8B68F416BEA93731F64C2B2D2E5F1662F7A80DCFBD4202EEAB930BF13CB166E2691EC0F7D9787220CBE"),
			std::string("54E1F1E72B4F411E0ECC77F30520178D856AE586D5077203A44868FE708AA2A0DFE76DBA4FB6AC1882D25AE49EA7742D831CE78AEE655211EEC818C9DD83A6E2"),
			std::string("919BAF4DD22123BD9F73E4EDED468DBA514DC280484190FAEE55CEC5B4D49375B6D7C3245EED40BFFB3C934AD2764CEC72D24026B230B5A4C1BE390A17A1041F"),
			std::string("26F3E196D0D59A0921F64E46CE527D0ACF0457EFBDD7A308911F8C7EF6A97007E4FEE91612914F6278CBD9D1AF9CB67A5E421669F35FCFC6BC41DFFE07AFD355"),
			std::string("615FFE620E2E798D06F219D8EC6F1B491206339F01D49D4FDB8102E40C70FA9708E5285108C13869885614ECCA779A8A40A4A2835A186A7146E97B9503705EC6"),
			std::string("279D8CF7C53ACBA3ADC2EC6316221F284E8D25A271F74F83FE006D47E8E6B383C1532811C73909B91AA840E5364AD94992FD8236C3FEDFE28113D33A227C60E6"),
			std::string("E02A1CB67FAE1D8989B103A3F010CE1E6BCF0772555BCBFB9C06B0C687A6417B82BC8068EBEB1E275407BCF5140568A2F4BCC983142E57C1E40135B730D8FCA3"),
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

	void ChaChaTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}