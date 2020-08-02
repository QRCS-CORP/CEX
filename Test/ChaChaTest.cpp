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
	using Tools::IntegerTools;
	using Tools::MemoryTools;
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
	const std::string ChaChaTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the ChaCha stream cipher (CSX256 and CSX512) authenticated stream ciphers.";
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
			CSX256* csx256a = new CSX256(true);
			CSX256* csx256s = new CSX256(false);

			// stress test authentication and verification using random input and keys
			Authentication(csx256a);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 MAC authentication tests.."));

			// compare parallel to sequential output for equality
			CompareP256();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 permutation variants equivalence test.."));

			// test all exception handlers for correct operation
			Exception(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(csx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[1]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			// chachapoly20-kmac256 vectors
			Kat(csx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256a, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256a, m_message[0], m_key[4], m_nonce[4], m_expected[2]);
			Kat(csx256a, m_message[0], m_key[5], m_nonce[4], m_expected[3]);
			Kat(csx256a, m_message[0], m_key[4], m_nonce[5], m_expected[4]);
			Kat(csx256a, m_message[0], m_key[4], m_nonce[6], m_expected[5]);

			// IETF vectors: non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[4], m_nonce[4], m_expected[6]);
			Kat(csx256s, m_message[0], m_key[5], m_nonce[4], m_expected[7]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[5], m_expected[8]);
			Kat(csx256s, m_message[0], m_key[4], m_nonce[6], m_expected[9]);
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
			Verification(csx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer authentication tests.."));

			delete csx256a;
			delete csx256s;

			// ChaChaPoly80 is the default if CEX_CSX512_STRONG is defined in CexConfig, or ChaChaPoly40 as alternate
			CSX512* csx512a = new CSX512(true);
			CSX512* csx512s = new CSX512(false);

			Authentication(csx512a);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("ChaChaTest: Passed CSX-512 permutation variants equivalence test.."));

			Exception(csx512s);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 exception handling tests.."));

			Finalization(csx512a, m_message[1], m_key[3], m_nonce[7], m_expected[11], m_code[2], m_code[3]);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 known answer finalization tests."));

			Kat(csx512a, m_message[1], m_key[2], m_nonce[7], m_expected[10]);
			Kat(csx512a, m_message[1], m_key[3], m_nonce[7], m_expected[11]);
			Kat(csx512s, m_message[1], m_key[2], m_nonce[7], m_expected[12]);
			Kat(csx512s, m_message[1], m_key[3], m_nonce[7], m_expected[13]);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 known answer cipher tests.."));

			MonteCarlo(csx512s, m_message[1], m_key[3], m_nonce[7], m_monte[1]);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 stress tests.."));
			
			Verification(csx512a, m_message[1], m_key[3], m_nonce[7], m_expected[11], m_code[2]);
			OnProgress(std::string("ChaChaTest: Passed CSX-512 known answer authentication tests.."));

			delete csx512a;
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
		std::vector<byte> nonce(ks.IVSize());
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

			rnd.Generate(inp, 0, MSGLEN);
			rnd.Generate(key, 0, key.size());
			rnd.Generate(nonce, 0, nonce.size());

			SymmetricKey kp(key, nonce);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntegerTools::Compare to verify mac
			if (IntegerTools::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN) == false)
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -CA1"));
			}

			if (IntegerTools::Compare(inp, 0, otp, 0, MSGLEN) == false)
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

#if defined(__AVX512__)

		std::array<uint, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output5(1024);

		ChaCha::PermuteP16x512H(output5, 0, counter32, state, ROUNDS);

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

#elif defined(__AVX2__)

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

#elif defined(__AVX__)

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
	}

	void ChaChaTest::CompareP1024()
	{
#if defined(CEX_CSX512_STRONG)
		const size_t ROUNDS = 80;
#else
		const size_t ROUNDS = 40;
#endif
		std::array<ulong, 2> counter{ 128, 1 };
		std::vector<byte> output1(128);
		std::array<ulong, 14> state;

		MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));

		ChaCha::PermuteP1024C(output1, 0, counter, state, ROUNDS);

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(1024);

		ChaCha::PermuteP8x1024H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 128)
		{
			for (size_t j = 0; j < 128; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PermuteP16x512H"), std::string("Permutation output is not equal! -CP3"));
				}
			}
		}

#elif defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output3(512);

		ChaCha::PermuteP4x1024H(output3, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 128)
		{
			for (size_t j = 0; j < 128; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PermuteP8x512H"), std::string("Permutation output is not equal! -CP2"));
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

		// test invalid parallel options
		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.IVSize());
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

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -CF4"));
		}

		// use constant time IntegerTools::Compare to verify
		if (IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) == false || IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -CF5"));
		}
		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
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

		if (IntegerTools::Compare(cpt, 0, Expected, 0, Expected.size()) == false)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -CK2"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -CK1"));
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
		const uint MINSMP = static_cast<uint>(Cipher->ParallelBlockSize());
		const uint MAXSMP = static_cast<uint>(Cipher->ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;	
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.IVSize());
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
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
		std::vector<byte> nonce(ks.IVSize());
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
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

		if (IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -CV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -CV2"));
		}
		if (otp != Message)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Decrypted output does not match the input! -CV3"));
		}
		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
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
			// csx256 finalization tests: mac-2
			std::string("E53392F5CB6927638E7448D4FC31FCD8A8CE05290785FCFC77DBCD442F08E7C2"),																	// csx256k256
			std::string("F4AC79068D44B120355EA595B93BD936C02C3DE89B3DFA70406E7A1077F82A4A"),

#if defined(CEX_CSX512_STRONG)
			// csx512 - verification
			std::string("4F0A7737FCB82B9E31F6449D77973000AA34B5489AD081FA95CAB4DA20976100A8330079D0D123D3AC96DBA88F1315B47BD475EA47CA8DAAF0977AD7FDD9F818"),	// csx512k512
			std::string("C59B8B1716EFA4CFDA1315D2482F65E66F8D5036C2BCFD2905667085D5CE5490CE1749F6250CD75CE156338EACBB61C43FA0BE096D2503FCA420CBCFAD1E6BA2")
#else
			// csx512p40 - verification
			std::string("13ACCAAAC740FEFBEE26F4F4EA49CB7108760C09F7DFF7FCCDAF09E7D644FB4BCDD9DE48B91C14FEF4E054CC79674642B2A717F722EA782A7D8E237676DA74AD"),	// csx512k512
			std::string("D45DA1A2863C20DEF734883D6E8926D15BAFC0485AD918CC3046C8CC321C9BEE9FE40345FDA2C0BCD05261D609C433EB1BFCFC7C1AD9908038F83ABFBF757624")
#endif
		};
		HexConverter::Decode(code, 4, m_code);

		const std::vector<std::string> expected =
		{
			std::string("4C06EFD4708B975E9C36E7980C1A8DF4ADCAFA582B4CF0DB7471EE2E283C5669D107E378ED0846B0DDAB57BA99399248890B0C65C5D1CDF3B22C366084B6A099"),	// csx256k256
			std::string("1E954D3ED600B37457A3C61C66C1462A87384FB66A439A9741C7AABCB8B455717936F2340E95C243BB41066E0456C7BDC1734603F61DC31481F27DF615E7F940"),	// csx256k256
			std::string("9EA9A8644C6A098A162EF890D631E10FDFD51F294357829025D11A7D7AC8EA1C58B33C23534A90C51F508D5BAC758F7C9847E04BE45C3CE340A0B491EE754406"),	// csx256k256
			std::string("56DB7DD6BBD795E30E0E7C8AB01F5809D1333FB2CB72B21F3F0C0ED5D43F44BF3828F929C29BBA3EFC77F5A2D83F915973E9534A53F88D3CFC94E09D1F8DE3E3"),	// csx256k256
			std::string("72D4196641D52B440A66FEE9F23A82B3F1D410C8F78DAE182A9BD8EF7E8B2CA8C5119C5249525A3F06211B86A87F946F5EED6CC6A3EF011D829DD5D6AEB3907C"),	// csx256k256
			std::string("C73AD84C26BE700C646DC0E2DB2A96F68221AF59341EE693EC5F7AFDC0B62F35731F90C70B233ED90CBAD3820BE19AB4D706AA015F6EBCF38E34828669FF820D"),	// csx256k256
			// IETF chacha-poly1305 for TLS, test vectors
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),	// csx256s: IETF test vector 1
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),	// csx256s: IETF test vector 2
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E31AFAB757"),	// csx256s: IETF test vector 3
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B"),	// csx256s: IETF test vector 4

#if defined(CEX_CSX512_STRONG)
			std::string("F9EE028326197A2ED0718A1B3439A397F2D82FC464CA0B01FB62852819DEA153F94EAC57953AB3654D4E92F5F7C6FB134E5F24F3841A4EF52039890232EA3450"	// csx512k512
				"943A531F57AE2083A6FC445977D32222F4ACECF8B8C86093335E938E8EB8C24A1AA97D7F5683898BBD681150986A9611C72F2AA74CFAD98DBD6D586576601281"),
			std::string("63344FB3B4A67BE9BB5C9D686CE6B44ACCBCE1BF90445E7B43A9A17D557C1A98A1ADD4B12A12A6C94735CAD66AB151F8ABCC01DA8B949DB92C7352F7B7337F0C"
				"DD2011FF15D2D19E3EF7A7CA4D83404557F0D460E109745317C457BAE517943C4FCC44D48691310F3710350B33E8491BF2A73B31A7A11EED54A5E6804D3CC384"),
			std::string("2E28054CCFF76ECA3BA88B6686E1C3E5BD359C3AA063AB0AF2F8C0B6375E615CA7851A7DCA1B483889C7A59CF73686A4B9ED57B87D0F40CC8B02D67B0BFB9F6B"	// csx512s
				"7D8AD7EFC39CC2ACECAD60C2C95CB5935072FA6646CB694DC4F75F17AD710AE088E036CADDE3F2FA21B6BCAF0E6049A90B5EC488A415268E6C069AF44F6FE78F"),
			std::string("E5C20D17687DCF16489DFB89E5FDDF128C288F3AE6C68C974F0A4FD4C76C9A6118B1C6D9214A7F155E1FC72C178A329D385D74C07320E3FDBF2DE30F8BD516CB"
				"38E2FBA6139EDCB9B569C622EA6F0EA55F8991AF7AC823CA36E3CF0319CB4DAB0104C145CEC7F8DDE11BE3613D10C27AE95C13DA5B559CDECBAC342EC79BF394"),
#else
			std::string("F734D4F2352AD01BAB3D93248915E91700FDB623E7CC8668DE122A780C0076F13BA13559CB0935E4EBE5D984029003318A1D6F9435F1F7B3C5C73FADA5F219D4"
				"49B26B8A817B4C745061771D4472E912019E24406DE860ECC5F2641EDF5A934CDC68444D742A0A7E63B07DBD10311638051737F43A4BE9FB3940E6CBA250A79F"),
			std::string("B5D43CF6C57CCBA5D855E3079E6AF1C49E2F32464365B90DDD670F899237AD15F65D99BBAA15B0003E6A1AC94299A3FD733708A321F6191F713AB6A340FDA3B6"
				"3539B48AE97A049D0FA4C511936EF40134717B517F177F0F2B0511D98AA3C3575A2DD59E9223DB2259F26140A39B96EBF4C6C2810198E8B1F457086E1BAB6918"),
			std::string("5D51BC336E9047F112E6F20F4D2A16CBB83728194D4DFD17CC18BFA8D18C1BBB80197F3D2C7782DD292F11BD850FBB8579E4FED8CC0E91EBB52A5006FE31A548"
				"87B815190BD1CE69D865232D94E9141AF4A831CFD3382B70642CC36640046E79311B7BADCB8C00C0DC3F500E6DBA621F814BF07471D66A73746165BEF79ED918"),
			std::string("4312594A721785A7171A2D54D05FD55B183B5F7D83B4384A0A45CA8178BBF6DD58EF478E0549491EE57416216276DAE343501539C85963AD4EE916015F51581A"
				"459DF82669F9DD6B189BAE6B3E714937AF9653D336149AB11593320266B005D756FC36831F4D7BCB1D85A7CC7CF705A12F6EA41DBE39491AAD9B75E33F8C1566"),
#endif

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
			// CSX-512
			std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
				"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			// IETF poly1305 test vector 2
			std::string("416E79207375626D697373696F6E20746F20746865204945544620696E74656E6465642062792074686520436F6E7472696275746F7220666F72207075626C69"
				"636174696F6E20617320616C6C206F722070617274206F6620616E204945544620496E7465726E65742D4472616674206F722052464320616E6420616E79207374617465"
				"6D656E74206D6164652077697468696E2074686520636F6E74657874206F6620616E204945544620616374697669747920697320636F6E7369646572656420616E202249"
				"45544620436F6E747269627574696F6E222E20537563682073746174656D656E747320696E636C756465206F72616C2073746174656D656E747320696E20494554462073"
				"657373696F6E732C2061732077656C6C206173207772697474656E20616E6420656C656374726F6E696320636F6D6D756E69636174696F6E73206D61646520617420616E"
				"792074696D65206F7220706C6163652C207768696368206172652061646472657373656420746F")
		};
		HexConverter::Decode(message, 3, m_message);

		const std::vector<std::string> monte =
		{
			std::string("3624BA23DB6CF0309371C68EDB94EBB83BE48266856BF95D34C457FE10C063A69D9590F04B816F249753BEDC3C21CECACBC09DA2DDEE3F0480CB63B086B6A8B1"),  // csx256s

#if defined(CEX_CSX512_STRONG)
			std::string("1CC27FBA6EE5A37BEB859C8D4FC47D6D29FB0D15C892CC6318D67197595812D3E0A253C972F1F2FC3BA29C78C926BFF3EED121F31AD6734411F0BBB7E8C72A73"    // csx512-80
				"944CBDDB69047812157D7899174B91E211F16C836D625DC0DD5D5AA6E462A2A58D2FF280570278BBAF89F8F7074F6E63E307624DE09A8D5F04201F95AF51310A")
#else
			std::string("7F4AA348BC99869315B625BAEFC569DC20BAEF069302DEB2DD94656EB0565C7B23972ACE173D3728D1CBDEE5C902194B4C06D4464E9EF189C09FA9812FFC7F8F"    // csx512-40
				"A26D281E16F78585DC2B34F4E580B2F4191FDE7A971FA8CB20A9507418C2E60FB61D0756D89074FD74DE3D0A0CC8BCD179812EC8249E19E9995557014E63B9DD")
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
			std::string("000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(nonce, 8, m_nonce);

		/*lint -restore */
	}

	void ChaChaTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}