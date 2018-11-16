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

			ChaCha256* csx256h256 = new ChaCha256(Enumeration::StreamAuthenticators::HMACSHA256);
			ChaCha256* csx256h512 = new ChaCha256(Enumeration::StreamAuthenticators::HMACSHA512);
			ChaCha256* csx256k256 = new ChaCha256(Enumeration::StreamAuthenticators::KMAC256);
			ChaCha256* csx256k512 = new ChaCha256(Enumeration::StreamAuthenticators::KMAC512);
			ChaCha256* csx256s = new ChaCha256();

			Authentication(csx256h256);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 MAC authentication tests.."));

			CompareP256();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 permutation variants equivalence test.."));

			Exception(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 exception handling tests.."));

			Finalization(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[4]);
			Finalization(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1], m_code[5]);
			Finalization(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2], m_code[6]);
			Finalization(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[3], m_code[7]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer finalization tests."));

			// check each variant for identical cipher-text output
			Kat(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256h256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256h512, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k256, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256k512, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			// non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(csx256s, m_message[0], m_key[1], m_nonce[1], m_expected[3]);

			Kat(csx256s, m_message[0], m_key[4], m_nonce[4], m_expected[8]);
			Kat(csx256s, m_message[0], m_key[5], m_nonce[4], m_expected[9]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[5], m_expected[10]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[6], m_expected[11]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer cipher tests.."));
			
			// check each variant for identical cipher-text output
			MonteCarlo(csx256h256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(csx256h512, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(csx256k256, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(csx256k512, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			// non-authenticated standard chachapoly20
			MonteCarlo(csx256s, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 monte carlo tests.."));

			Parallel(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 parallel to sequential equivalence test.."));

			Stress(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 stress tests.."));

			// original mac vectors
			Verification(csx256h256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			Verification(csx256h512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[1]);
			Verification(csx256k256, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[2]);
			Verification(csx256k512, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[3]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer authentication tests.."));

			delete csx256h256;
			delete csx256h512;
			delete csx256k256;
			delete csx256k512;
			delete csx256s;

			// ChaChaPoly80 is the default if CEX_CHACHA512_STRONG is defined in CexConfig, or ChaChaPoly40 as alternate

			ChaCha512* csx512h256 = new ChaCha512(Enumeration::StreamAuthenticators::HMACSHA256);
			ChaCha512* csx512h512 = new ChaCha512(Enumeration::StreamAuthenticators::HMACSHA512);
			ChaCha512* csx512k256 = new ChaCha512(Enumeration::StreamAuthenticators::KMAC256);
			ChaCha512* csx512k512 = new ChaCha512(Enumeration::StreamAuthenticators::KMAC512);
			ChaCha512* csx512s = new ChaCha512();

			Authentication(csx512h256);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 permutation variants equivalence test.."));

			Exception(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 exception handling tests.."));

			Finalization(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[8], m_code[12]);
			Finalization(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[9], m_code[13]);
			Finalization(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[10], m_code[14]);
			Finalization(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[11], m_code[15]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer finalization tests."));

			// check each authenticated variant for identical cipher-text output
			Kat(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[4]);
			Kat(csx512h256, m_message[0], m_key[3], m_nonce[3], m_expected[5]);
			Kat(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[4]);
			Kat(csx512h512, m_message[0], m_key[3], m_nonce[3], m_expected[5]);
			Kat(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[4]);
			Kat(csx512k256, m_message[0], m_key[3], m_nonce[3], m_expected[5]);
			Kat(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[4]);
			Kat(csx512k512, m_message[0], m_key[3], m_nonce[3], m_expected[5]);
			// non-authenticated extended chachapoly80/40
			Kat(csx512s, m_message[0], m_key[2], m_nonce[2], m_expected[6]);
			Kat(csx512s, m_message[0], m_key[3], m_nonce[3], m_expected[7]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 known answer cipher tests.."));

			// check each variant for identical cipher-text output
			MonteCarlo(csx512h256, m_message[0], m_key[3], m_nonce[3], m_monte[2]);
			MonteCarlo(csx512h512, m_message[0], m_key[3], m_nonce[3], m_monte[2]);
			MonteCarlo(csx512k256, m_message[0], m_key[3], m_nonce[3], m_monte[2]);
			MonteCarlo(csx512k512, m_message[0], m_key[3], m_nonce[3], m_monte[2]);
			// non-authenticated standard chachapoly20
			MonteCarlo(csx512s, m_message[0], m_key[3], m_nonce[3], m_monte[3]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-512 stress tests.."));

			// original mac vectors
			Verification(csx512h256, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[8]);
			Verification(csx512h512, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[9]);
			Verification(csx512k256, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[10]);
			Verification(csx512k512, m_message[0], m_key[2], m_nonce[2], m_expected[4], m_code[11]);
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

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code1, 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -CF1"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);
		Cipher->Finalize(code2, 0, TAGLEN);

		// use constant time IntUtils::Compare to verify mac
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
			throw TestException(std::string("Kat: Decrypted output does not match the input! -CV1"));
		}

		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -CV2"));
		}

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code, 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Authentication: MAC output is not equal! -CV3"));
		}
	}

	//~~~Private Functions~~~//

	void ChaChaTest::Initialize()
	{
		/*lint -save -e417 */
		 //8,10,12,14
		const std::vector<std::string> code =
		{
			// csx256 - verification
			std::string("B0C905554F91231E6EC46E21B3034DD96191C3FAFC889838B135F9E2AE2AF7E8"),																	// csx256h256
			std::string("EA6C8AD167CDB02DD4AF28C8B0C09B64556F1F0DD461FCE431DD935399B0BDE75BC332A9DD611FD9722095158D8EA3B36161D152F2ED2A71D179BF3826066DA5"),	// csx256h512
			std::string("7C10AE9FC18AF04C4002FE3F8C21146F5F69736F47F0F41555E219514798FD29"),																	// csx256k256
			std::string("D9646293C0FE4298D85429B5AE3C03BA1B15C14BEB948D36F28ADC0350B246A1B87768C403090502272FCB521BE98347CB4C68A85970E1FBE093A8C06985205C"),	// csx256k512

			// csx256 finalization tests: mac-2
			std::string("903CF3362B553BD6EBCF999B500676D77F7F1EC69EDFF1E3E329CAD1D19E0835"),																	// csx256h256
			std::string("208FDA2C23858DFAE5208080FEF079D35BAEFF374F9518A62F12E68802CB695771797147361447367D6431067471132AF18793CEE32A8260F5B113E0782B9CAB"),	// csx256h512
			std::string("0DE735892A9EB0AC4EC7C2B2F20B020A0CE7AD49ED15360F8F821CC08718B0BC"),																	// csx256k256
			std::string("A982B855126661B982ADAA4D84FDA0B4605C197E377184242C7858235EAB4FD1A54510D5C2B062DCD8A331CAEAA1A52BE9473474243AD55E5A058FABEA248137"),	// csx256k512

#if defined(CEX_CHACHA512_STRONG)
			// csx512 - verification
			std::string("CA9D818A71CDADF62DB04ACBBA85ECB03A82F8FBC2819A4FAF8BD8FF6CCAA253"),																	// csx512h256
			std::string("BA4402EB0586A7E6C13EA75FA2FA9A8FEF4FA2B6EB6F5E627366997F6D2B4253747CA530986CACEAEA5FB71CE8BEC0B5A227BE7551E8DC689E76E0894292B274"),	// csx512h512
			std::string("7984855BD86FBD21091382FFDA9FEBFFEBDBE8A339CA749A030966EE7546AA0D"),																	// csx512k256
			std::string("D07D36389266A9849CDC616FE7397F717DD54D61E61B15861070685E81C1A8763559523722D02ED882BDA85A92ACA337E9172A5E3C2F750A1DA35609D56650C0"),	// csx512k512

			// csx512p80 finalization tests: mac-2
			std::string("30BF629DF5DEB8B374AB2EAFC66C1093267CC351493C3951152E28E2888DEC5B"),																	// csx512h256
			std::string("993BEEF5DF5AFF1833CA19E32F7147A892298063349A3AA363C1E2313501BDFC70D7EDDAFFC7177D8F2AB8E6DF5131586729C53156C3B9D6FFB94788F6BE60A8"),	// csx512h512
			std::string("30C1A3D24AED8B9CF029D865F90D0A45FB63DBB6C4DFB6947D13837F5C8F7EEA"),																	// csx512k256
			std::string("ADE84DAF9D430CA3FD79DEB5BB037F508587A82572CD5A6B97A873A34E01A85C1D5E17A53A9FB4E75C9BE9470AE4855F84839887216D740C4297A45BF1925372")		// csx512k512
#else
			// csx512p40 - verification
			std::string("691007615DE3D823669B360E964271923CE1128533D328390CAEBBD650011046"),																	// csx512h256
			std::string("D339BD50FD36DA0890CA0394A975C76905C3DAC7A4901D69F34C6B7170198252E2552265AA89C9CBFC705BF7A383CEC87BF4D5816B8CF403F478B94DF4B3B968"),	// csx512h512
			std::string("B13111DAF7B1B4C7699A63C9B025CD34A2282B2D782B8B48A749B790444853C8"),																	// csx512k256
			std::string("ADE51542EDF5FEC17E71D8000A98A7A07C1FF3AD5A1B18BFE9AB096D69CC95AE04CDE9CB9D6AF7D4C9051BF65149329E85D8C23A2E8CF63B34BEB2E882ED82B0"),	// csx512k512

			// csx512p40 finalization tests: mac-2
			std::string("541D6F4CFA584D223393EB1632B70769239C4A1FB4F30837B3C924C33DCB70B5"),																	// csx512h256
			std::string("17C341762A4B4FC56F19CE9F77BA846E623BF0590E318D72DAD7015479962DBC43804126608DFDC728E14B8394EF63D9C37EAA50ECDCED777D9BB9EB5CED93D5"),	// csx512h512
			std::string("A0F62357BAEC20D11A7C87FBE0E2502E00F46E39E350E0FBC78298A93366AB2A"),																	// csx512k256
			std::string("FC16549CBBABD8AAD6E4D37E694BCA550A47066CB73B4DE9BBFBBD89EA01E57FE54378F2832023FF7EDC400CC7C08C198C723B058E05718C65B3E963CBBEB459")		// csx512k512
#endif
		};
		HexConverter::Decode(code, 16, m_code);

		const std::vector<std::string> expected =
		{
			std::string("5820D2B2BF9D2D10EB87359DC639A21715A08C5D535E6439887D8B20E37C5FC7F80FA87324C898CB605975CDAFFE9E1736DF913E4D3720B6FA55DE73A6F2907B"),	//20r-256c
			std::string("39A1BB6F123B4FE8AF780CEB88FB3226049377ADF8C5F32D3A311697452073C6C7CEE34CC67641DD69F05D6266DE7EEF3DE4C359B4728F6D847454210D5E4C8A"),	//20r-256c
			std::string("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3"),	//20r-256s
			std::string("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99"),	//20r-256s

#if defined(CEX_CHACHA512_STRONG)
			std::string("716E1BDC7BDA5FD2F1D7EB84432EF4B1F1BAC4E7A5A905FC24D25521BB3E6F58DC22F791DEDE440583394CF614A371BD6C14D253323B3B4F0BF17506DB08F155"),	//80r-512c
			std::string("41ABC7B51F100D6D0BAA25F0AAD9C411A2EA4CAF7F5EE70CF4273C7DB83D6C8745314A621805F3C4CE2D4BF61033F7BD2D6BEEA6C82FF70DA96B641A0D0287A5"),	//80r-512c
			std::string("E8B7594B1C5FFBE43D52318EB1B1E9231E2DD50275C9A6E5CBF33DACED3B2EF4B2FAD30DADD96FC634EBFD4D3897DE8A0DE9D3F846CDE0AA7EA31EA08A2F444F"),	//80r-512s
			std::string("54B70E75C5B79BBFCCF88DE2B1C356EB385C05C2F3AF91EE803A5AE8396F3DDDAF8D41DF905AA242AD7F27126596A829B890B34621F5E267C1D46DA8A44BEA8B"),		//80r-512s
#else
			std::string("B04981146EEB2E62EB522345D76886BB49A2CA9327CDA1806668EF52C766FD67B649A45150BB3222932F8E1E579F08ADE4865F1267B6EDF970D4DECC90898E98"),	//40r-512c
			std::string("EE8C5F81FF6CBAEAEB4FA358883F908070099489EB4728A84A3D9680ECD70DB3984A7C40A22C53914703759261758894EC1EAD2BAC6683DD66873BC3605C325A"),	//40r-512c
			std::string("87E9E06B911153EEF0291D1C4B5624DCEBE9D64228D30FFD56F940923531A8E8D1A9013F1957D758E0330D92977987ED45A50053B8154586D739F4CDA6D6E6DE"),	//40r-512s
			std::string("67EB972A7390E2B4971D0BBCB17F9BD8A8C135E83B9D5338B9D66426E4B8495A9B4E02BE2DE52A8FB139BDA519728AC519EEBD8F3AC2495F4088E49A2C54DDB7"),	//40r-512s
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
		HexConverter::Decode(expected, 12, m_expected);

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
			std::string("3F7FA9CFB44E78D277827206B2B91A0025188AA0AD93C0E72D05D1E8E92E982F72EFDABC4AE6237EC50771B84B3F9F069A7C3C0BBA0FECFDD8F05BE601D90CCA"),  //20r-256c
			std::string("3624BA23DB6CF0309371C68EDB94EBB83BE48266856BF95D34C457FE10C063A69D9590F04B816F249753BEDC3C21CECACBC09DA2DDEE3F0480CB63B086B6A8B1"),
#if defined(CEX_CHACHA512_STRONG)
			std::string("D82427B64DAC0C5515C6378AA0F64EC0C8F7E6291FE591326B8420098045AD9939151D182C93FD49BCD38AA46AC33EAE92C492DD270D6C46D47270F1F7D89F9A"),  //80r-512c
			std::string("3A8FF5F63349F7446D7D66244D4059D79AEC43226761213D01EF75C097CB14D7FA52F0F2C3E9B9D6D500527E5F907B317517ACA93CCD9792323D93AD20F0047E")
#else
			std::string("1951F948779960792FF44DB976EC427D3E55B71EC81E25EB514B4777755F5551B02D38A3CC9B70CE699ED1BB9F35788D5EF614EF2688F09CB6A7DEA5E62E5A4A"),  //40r-512c
			std::string("5C3EF665FA206CD9698B85B355271590E6C1C290AB2920E5CD875C741BAB7AC75B7A8B55CAF55422FB741CA847D8C922C4D247F492D2F7388EE97BC2B1FBB73B")
#endif
		};
		HexConverter::Decode(monte, 4, m_monte);

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