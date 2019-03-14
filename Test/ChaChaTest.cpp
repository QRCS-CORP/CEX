#include "ChaChaTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/CSX256.h"
#include "../CEX/CSX512.h"
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
	using Cipher::Stream::CSX256;
	using Cipher::Stream::CSX512;
	using Exception::CryptoSymmetricException;
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
			CSX256* csx256h256 = new CSX256(StreamAuthenticators::HMACSHA256);
			CSX256* csx256k256 = new CSX256(StreamAuthenticators::KMAC256);
			CSX256* csx256p256 = new CSX256(StreamAuthenticators::Poly1305);
			CSX256* csx256s = new CSX256(StreamAuthenticators::None);

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
			Finalization(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[1]);
			Finalization(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
			Finalization(csx256p256, m_message[0], m_key[0], m_nonce[0], m_expected[8], m_code[4], m_code[5]);
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
			// chachapoly20-poly1305 vectors
			Kat(csx256p256, m_message[0], m_key[0], m_nonce[0], m_expected[8]);
			Kat(csx256p256, m_message[0], m_key[1], m_nonce[1], m_expected[9]);

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
			Verification(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer authentication tests.."));

			delete csx256h256;
			delete csx256k256;
			delete csx256s;

			// ChaChaPoly80 is the default if CEX_CHACHA512_STRONG is defined in CexConfig, or ChaChaPoly40 as alternate
			CSX512* csx512h256 = new CSX512(StreamAuthenticators::HMACSHA256);
			CSX512* csx512h512 = new CSX512(StreamAuthenticators::HMACSHA512);
			CSX512* csx512k256 = new CSX512(StreamAuthenticators::KMAC256);
			CSX512* csx512k512 = new CSX512(StreamAuthenticators::KMAC512);
			CSX512* csx512s = new CSX512(StreamAuthenticators::None);

			Authentication(csx512h256);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 permutation variants equivalence test.."));

			Exception(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 exception handling tests.."));

			Finalization(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[14], m_code[6], m_code[7]);
			Finalization(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[17], m_code[8], m_code[9]);
			Finalization(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[18], m_code[10], m_code[11]);
			Finalization(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[21], m_code[12], m_code[13]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer finalization tests."));

			Kat(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[14]);
			Kat(csx512h256, m_message[0], m_key[3], m_nonce[7], m_expected[15]);
			Kat(csx512h512, m_message[0], m_key[2], m_nonce[7], m_expected[16]);
			Kat(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[17]);
			Kat(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[18]);
			Kat(csx512k256, m_message[0], m_key[3], m_nonce[7], m_expected[19]);
			Kat(csx512k512, m_message[0], m_key[2], m_nonce[7], m_expected[20]);
			Kat(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[21]);
			Kat(csx512s, m_message[0], m_key[2], m_nonce[7], m_expected[22]);
			Kat(csx512s, m_message[0], m_key[3], m_nonce[7], m_expected[23]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer cipher tests.."));

			MonteCarlo(csx512s, m_message[0], m_key[3], m_nonce[7], m_monte[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 stress tests.."));
			
			Verification(csx512h256, m_message[0], m_key[2], m_nonce[7], m_expected[14], m_code[6]);
			Verification(csx512h512, m_message[0], m_key[3], m_nonce[7], m_expected[17], m_code[8]);
			Verification(csx512k256, m_message[0], m_key[2], m_nonce[7], m_expected[18], m_code[10]);
			Verification(csx512k512, m_message[0], m_key[3], m_nonce[7], m_expected[21], m_code[12]);
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE2"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE3"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE6"));
		}
		catch (CryptoSymmetricException const &)
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
		const size_t MINSMP = Cipher->ParallelBlockSize();
		const size_t MAXSMP = Cipher->ParallelBlockSize() * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;	
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
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

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
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
	}

	void ChaChaTest::Stress(IStreamCipher* Cipher)
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
			std::string("22A276A4A7E878E305DE15B14B63785B55F974FB01425A994FED06015BB23DD4"),																	// csx256h256
			std::string("2A2410DF99D811D6A0A0609B055D554BA52E85C8E2E7E695674AF73128F3384B"),

			// csx256 finalization tests: mac-2
			std::string("C8A1895F47422265160F768004F9F9775659C748C8B1539ADC0486022865F409"),																	// csx256h256
			std::string("8C139298CAF31C595CBA3F2E398770AC8E6796D9810175A1F627C6449EB57619"),

			// csx256 finalization tests: mac-2
			std::string("A25E79042E782D2773A2F180D4E729EE"),																									// csx256p256
			std::string("0EF5240B05134793B60923051EF7AE4F"),

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("DDD1BC1363EE81007B73672C28A2D6E2B5D8E95DB725F6379BC6D6F5E345649B"),																	// csx256h256
			std::string("61C0F3E3DF6D115054CACBA0D8E20DFB056D8FDA17BE10465408E1822996EC69"),
			std::string("40BDDC8AAE96D4E6426B0CC85C6E83B5AC85EF4B0A79FF9093E6B18DFE3890AE33316D40B08EDD346DE1175EC683CB9E770EBC84BA959C1886E9DFFFA808DA21"),	// csx512k512
			std::string("64CB334E00B2A235D9AB300FEFCF40DB9A2EADB58F44C78A5D04E1556230513080D4C828DEA73BE22E432F897FF7C7FF28A6739DE8F274DEECCD80FFC30D3431"),

			// csx512p80 finalization tests: mac-2
			std::string("35F1C836BF7239193CC2241495F145BCD8B19A8E295929EE8A313DB371D85852"),																	// csx512h256
			std::string("915256DC5121F11C60B1545DC42323750D5CFF3A34A9ADA09A8CA1606D14FB9D"),
			std::string("880117A461BEA31125A96F97093A98E24329E5676F810A34689C308E5F05B83F211C7D8D218F11DD59CF24C5D868F9414FAF7F3F5FF3D27A41694C5F0DBB56E6"),	// csx512k512
			std::string("6499C86DB99C46106D284BF0D70D9F3B14499C02A4B743A9BA03610B3ADD113C0E37320789F1A851C26C84C83065C4C7773A11CD53480F1630708013491F66F4")
#else
			// csx512p40 - verification
			std::string("F5590F821728D3C332218E3785A2CD1F471FA43FDE2A334D9BEF59737DFC3A28"),																	// csx512h256
			std::string("7F7C4A8E775913AE8081FD79FFEF0CEF0FBD01E45FC7D9B86745D9F016DE03C6"),
			std::string("10078627D60BBFA0CDD67C84880ED4B6400FD7BEE3FB238EC74B92EBBE4E4EF2CE95F1569B0EA48E0D8347153726072D90808D5523861360C95546C4D65F93C3"),	// csx512k512
			std::string("F123AB71DE508CD21A1AEAAB823DD28B64B69B1EBCD8C692B50D31DDA730355C04BE50AA07872BFE6AFD6DA0704B7699106C8722FA8BD044F87F253B11852AEE"),

			// csx512p40 finalization tests: mac-2
			std::string("3036EC2237D8E88327218DB5A8EC31649CA43894FFCCF929AF94E0DA86F68F1C"),																	// csx512h256
			std::string("A8F408B93F8421CB75E198A7A112C06E524ADC41394E59BB731078D735C121A5"),
			std::string("35EB2121F7064B8C7D832491921EFA568F541AF962198E2DCACF7D483181FA7665B8E697F1B44F28D23307BA74D2F4BB62E4EBFAD303E72FB35DC491684826A3"),	// csx512k512
			std::string("C43985B79378BD4A5F3E53457579203991BBC46CE033686FDFF1301EE0AD4539EEC47A62ABA36105D4861BA36F49CA35E0DFD5A85B5C3AFEE7C785A829F52B0D")
#endif
		};
		HexConverter::Decode(code, 14, m_code);

		const std::vector<std::string> expected =
		{
			std::string("5C81F21837498A2559DA6701B490112AE82D5990FE7E22EF6C1F01A3F8BB08F90E7821DC846597615D33F09FFEBCA951B1B92CB289DA8954D08FA31741FCE276"),	// csx256h256
			std::string("623D965EC31A557B7AAAAE1AB61BA5B6EC97B18519C75D652156390A35D5B05B3DB07E4C21E3D6AEC2E129DE74816E2E7599A386BF17E1248A988033F83A5E86"),	// csx256h256
			std::string("4C06EFD4708B975E9C36E7980C1A8DF4ADCAFA582B4CF0DB7471EE2E283C5669D107E378ED0846B0DDAB57BA99399248890B0C65C5D1CDF3B22C366084B6A099"),	// csx256k256
			std::string("1E954D3ED600B37457A3C61C66C1462A87384FB66A439A9741C7AABCB8B455717936F2340E95C243BB41066E0456C7BDC1734603F61DC31481F27DF615E7F940"),	// csx256k256
			std::string("9EA9A8644C6A098A162EF890D631E10FDFD51F294357829025D11A7D7AC8EA1C58B33C23534A90C51F508D5BAC758F7C9847E04BE45C3CE340A0B491EE754406"),	// csx256k256
			std::string("56DB7DD6BBD795E30E0E7C8AB01F5809D1333FB2CB72B21F3F0C0ED5D43F44BF3828F929C29BBA3EFC77F5A2D83F915973E9534A53F88D3CFC94E09D1F8DE3E3"),	// csx256k256
			std::string("72D4196641D52B440A66FEE9F23A82B3F1D410C8F78DAE182A9BD8EF7E8B2CA8C5119C5249525A3F06211B86A87F946F5EED6CC6A3EF011D829DD5D6AEB3907C"),	// csx256k256
			std::string("C73AD84C26BE700C646DC0E2DB2A96F68221AF59341EE693EC5F7AFDC0B62F35731F90C70B233ED90CBAD3820BE19AB4D706AA015F6EBCF38E34828669FF820D"),	// csx256k256
			std::string("14A8B4F493D707DC2ACEEABBAD1BA949CE0197A25B080F148986FA4F50058B380C63A13143D1FA0A31902629C8D17AE677E96D395F6AD3C9A84D0FD1982E7F78"),	// csx256p256
			std::string("8392235DECAE5DC4F3491E2ABCE2FB25D3F0CB81370AEB550D40C8A3D7FAC76CBA78AA0229C1B24D6E908B2A0E7FB6F45DBDA10720122555DAADFEB1DA84BE8F"),	// csx256p256
			// IETF chacha-poly1305 for TLS, test vectors
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),	// csx256s: IETF test vector 1
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),	// csx256s: IETF test vector 2
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E31AFAB757"),	// csx256s: IETF test vector 3
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B"),	// csx256s: IETF test vector 4

#if defined(CEX_CHACHA512_STRONG)
			std::string("18AD32FBA6504045B733F3AA0CBDAD2AFAD6540152DD19BFDF7EAADB8930B73AD6309DD874315E7DDD74C2953958AFC2B0256B74E1B347ED897DB041ABF34DFA"),	// csxp80256h256
			std::string("4AEA13BC19DC7979877B2330636A6C6206979890BD730353CE104458C6D2FAC091D1A169693876598A48C5C46D7E71467285179E93A1DC65D87C6C29209E4B9E"),
			std::string("E7CAC5160D697C8D7E0269CCE5990E4A117BA75D617442A757849FAF8921C3DFE9EBC500CA8265CB3B59E5FD9EAF36C4227ACD316304BCDA3D2BD2B179C2944B"),	// csxp80256h512
			std::string("9476E544CD233A3885A114EAEA470228265EF3D267A5914C62ABA21121998E637E3B385611167356C47EBE42F52362D291E503C6C048845DA7D0B074A9186783"),
			std::string("4459B5A9E5CB4CBDBA3DD6D489F48CBF548F632161EDAC983DDF7677E7406C5780CE18B8841915860BAA477440966D8C5A2D76EE8467CB1112DF04AFAC841612"),	// csxp80256kh256
			std::string("DC6EFB6227E6E278F0E9DF98D7A68E3B4DA625F3FD3FEE1ADDFC056D07C4ADF3BA3A3DB46EBF903C5A3350D80AEB76FB46FD985CF54A46F04DD53CAB72E02AF1"),
			std::string("9469954FBD272C2B4227C8F971D6E5AC46C3AAA96EC25525AC8B0D6D78671CAE31C5DE245A8C92ADED0534B1F87708D6C2BC31C1B881EB56FAD1E800A1E14913"),	// csxp80256h512
			std::string("7B4C96D6FB7D2917E06CADCCBDE36C3F298633747BA41855109C9D1688928DC822443FE980435B0C807CA2CDB78F2F5563195B9C6AED7026F8BBDC4972471E0D"),
			std::string("23A5B37570F6E3585EFB4614460616A926243B865CFD6C2C1CBFC33CC4C8B8F3C8F67FD56A9589C2C144D5F02029C9DEE003A7A6A7185AE697D242FD531F0D69"),	// csxp80256s
			std::string("DCBA51986EED0FDA2E15F9AD021B26CE17567A3EBE9F43FE8B5BD460527EDA8D77BB80C5B8BE29850A21428A7D390DF9631C5C126EFCED7E14441E8CD2A9AFF1")
#else
			std::string("FC4045B5B67B5D7212A4C26D78BA0602AE83FDB8A0A12E512140CA3528F7CA0457356E5D8F71AF834924C89C30349FC9BC1DBC5D63E069107FF5BC034496C2BF"),	// csxp40256h256
			std::string("81577699A387884D6FC123F19E68C34F5E8228E6C2779BB4130EAA7AAEE1B6B0B03D8284EB3C32C72C03D589A0C8C45E8AD71FB69600A49B6B5D43B54D20A895"),
			std::string("4B447313946643682678B8E9D63399DF6F70144D4CBA3EABF80D482782B99EC4010A5C5E6D36E137E6866C3EDEC6F9F77844E4092FF0AD51D02C3B09F203EB56"),	// csxp40256h512
			std::string("DD994D5B597F76E3F16A411211617EE0BCFE1CB4B730BAC10EE790C5C490102E0F973CEA6B854916D142FA0606616D6EAC343760817148BF51989B0154DF894A"),
			std::string("2F6D970F4810001F6DD7F6B20DF25007E77AE969D2C44A3A172D984DAB1CE84132C16C228642A5F51FB3658FF76502A57BB23361D13BDEF9A24029BEE1E7E853"),	// csxp40256kh256
			std::string("F3889A1594EAF7B84737C3B07376CE9AEE1C113E309E75E6A8B551A5A71BEE412DAB1E644138FDA8F30574E9F82B79CC3767679E1EDEE5974F6EE3141F11CEBC"),
			std::string("D3E291737933AA45E2F0FCC1764E5757238AEAF149F9F327DE6542594038B161146872032936365903B9D6ADA58080359D5DCD45044FF52C068C16613651E156"),	// csxp40256h512
			std::string("E300B36EEC4896F2BC65D81F996EB91AD810665CCA525058B89B691FBDCF403EC34546A7B8A42A1B7CABF2EE18254D962C0792AEE230BD0A097A6444929A2BEB"),
			std::string("5ADBA319A0A42546444C3121E94D3AFA40B5E63CEC9C667109DEF0E17009399E74C994AB07D7631344CBF266754DDE31C265082A9B630E97DE287023AAED8A21"),	// csxp40256s
			std::string("C67BE57127D42320B584074F0964C75C643768B94E01C2D61A9F4071F71604D5F4A8A90A867FC47FA90592DEF26D36C72DC5CE7561B9AF564DCC217A19045175")
#endif

		};
		HexConverter::Decode(expected, 24, m_expected);

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