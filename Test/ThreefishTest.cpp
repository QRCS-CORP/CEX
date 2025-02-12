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
	using Tools::IntegerTools;
	using Tools::MemoryTools;
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
	const std::string ThreefishTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ThreeFish stream cipher (TSX256, TSX512, TSX1024) authenticated stream ciphers.";
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
			TSX256* tsx256s = new TSX256(false);
			TSX256* tsx256a = new TSX256(true);

			// stress test authentication and verification using random input and keys
			Authentication(tsx256a);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 MAC authentication tests.."));

			// compare parallel to sequential otput for equality
			CompareP256();
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 permutation variants equivalence test.."));

			// test all exception handlers for correct operation
			Exception(tsx256s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 exception handling tests.."));
			
			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(tsx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0], m_code[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(tsx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(tsx256s, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
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
			Verification(tsx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0], m_code[0]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-256 known answer authentication tests.."));

			delete tsx256a;
			delete tsx256s;

			// threefish512 standard and authenticated variants
			TSX512* tsx512s = new TSX512(false);
			TSX512* tsx512a = new TSX512(true);

			Authentication(tsx512a);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 MAC authentication tests.."));

			CompareP512();
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 permutation variants equivalence test.."));

			Exception(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 exception handling tests.."));

			Finalization(tsx512a, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[2], m_code[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer finalization tests."));

			Kat(tsx512a, m_message[1], m_key[1], m_nonce[1], m_expected[2]);
			Kat(tsx512s, m_message[1], m_key[1], m_nonce[1], m_expected[3]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer cipher tests.."));

			MonteCarlo(tsx512s, m_message[1], m_key[1], m_nonce[1], m_monte[1]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 monte carlo tests.."));

			Parallel(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 parallel to sequential equivalence test.."));

			Stress(tsx512s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 stress tests.."));

			Verification(tsx512a, m_message[1], m_key[1], m_nonce[1], m_expected[2], m_code[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-512 known answer authentication tests.."));

			delete tsx512a;
			delete tsx512s;

			// threefish1024 standard and authenticated variants
			TSX1024* tsx1024a = new TSX1024(true);
			TSX1024* tsx1024s = new TSX1024(false);

			Authentication(tsx1024a);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 permutation variants equivalence test.."));

			Exception(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 exception handling tests.."));

			Finalization(tsx1024a, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[4], m_code[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			Kat(tsx1024a, m_message[2], m_key[2], m_nonce[2], m_expected[4]);
			Kat(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_expected[5]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer cipher tests.."));

			MonteCarlo(tsx1024s, m_message[2], m_key[2], m_nonce[2], m_monte[2]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 monte carlo tests.."));

			Parallel(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 parallel to sequential equivalence test.."));

			Stress(tsx1024s);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 stress tests.."));

			Verification(tsx1024a, m_message[2], m_key[2], m_nonce[2], m_expected[4], m_code[4]);
			OnProgress(std::string("ThreefishTest: Passed Threefish-1024 known answer authentication tests.."));

			delete tsx1024a;
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
		std::vector<uint8_t> cpt;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> nonce(ks.IVSize());
		std::vector<uint8_t> otp;
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
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -TA1"));
			}
			if (IntegerTools::Compare(inp, 0, otp, 0, MSGLEN) == false)
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("ciphertext output output is not equal! -TA2"));
			}
		}
	}

	void ThreefishTest::CompareP256()
	{
		std::array<uint64_t, 2> counter{ 128, 1 };
		std::array<uint64_t, 4> key;
		std::array<uint64_t, 2> tweak;
		std::array<uint64_t, 4> state1;
		std::array<uint64_t, 4> state2;
		SecureRandom rnd;

		IntegerTools::Fill(key, 0, 4, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 4 * sizeof(uint64_t));
		MemoryTools::Clear(state2, 0, 4 * sizeof(uint64_t));

		Threefish::PemuteP256C(key, counter, tweak, state1, 72);
		Threefish::PemuteR72P256U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP256"), std::string("PemuteP256"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX512__)

		std::array<uint64_t, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<uint64_t, 32> state4;

		MemoryTools::Clear(state4, 0, 32 * sizeof(uint64_t));

		Threefish::PemuteP8x256H(key, counter16, tweak, state4, 72);

		for (size_t i = 0; i < 32; i += 4)
		{
			for (size_t j = 0; j < 4; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP256"), std::string("PemuteP8x256H"), std::string("Permutation output is not equal! -TP3"));
				}
			}
		}

#elif defined(__AVX2__)

		std::array<uint64_t, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<uint64_t, 16> state3;

		MemoryTools::Clear(state3, 0, 16 * sizeof(uint64_t));

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
	}

	void ThreefishTest::CompareP512()
	{
		std::array<uint64_t, 2> counter{ 128, 1 };
		std::array<uint64_t, 8> key;
		std::array<uint64_t, 2> tweak;
		std::array<uint64_t, 8> state1;
		std::array<uint64_t, 8> state2;
		SecureRandom rnd;

		IntegerTools::Fill(key, 0, 8, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 8 * sizeof(uint64_t));
		MemoryTools::Clear(state2, 0, 8 * sizeof(uint64_t));

		Threefish::PemuteP512C(key, counter, tweak, state1, 96);
		Threefish::PemuteR96P512U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP512"), std::string("PemuteP512"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX512__)

		std::array<uint64_t, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<uint64_t, 64> state4;

		MemoryTools::Clear(state4, 0, 64 * sizeof(uint64_t));

		Threefish::PemuteP8x512H(key, counter16, tweak, state4, 96);

		for (size_t i = 0; i < 64; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PemuteP8x512H"), std::string("Permutation output is not equal! -TP3"));
				}
			}
		}

#elif defined(__AVX2__)

		std::array<uint64_t, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<uint64_t, 32> state3;

		MemoryTools::Clear(state3, 0, 32 * sizeof(uint64_t));

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

	}

	void ThreefishTest::CompareP1024()
	{
		std::array<uint64_t, 2> counter{ 128, 1 };
		std::array<uint64_t, 16> key;
		std::array<uint64_t, 2> tweak;
		std::array<uint64_t, 16> state1;
		std::array<uint64_t, 16> state2;
		SecureRandom rnd;

		IntegerTools::Fill(key, 0, 16, rnd);
		IntegerTools::Fill(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 16 * sizeof(uint64_t));
		MemoryTools::Clear(state2, 0, 16 * sizeof(uint64_t));

		Threefish::PemuteR120P1024U(key, counter, tweak, state2);
		Threefish::PemuteP1024C(key, counter, tweak, state1, 120);

		if (state1 != state2)
		{
			throw TestException(std::string("CompareP1024"), std::string("PemuteP1024"), std::string("Permutation output is not equal! -TP1"));
		}

#if defined(__AVX512__)

		std::array<uint64_t, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<uint64_t, 128> state4;

		MemoryTools::Clear(state4, 0, 128 * sizeof(uint64_t));

		Threefish::PemuteP8x1024H(key, counter16, tweak, state4, 120);

		for (size_t i = 0; i < 128; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException(std::string("CompareP1024"), std::string("PemuteP8x1024H"), std::string("Permutation output is not equal! -TP3"));
				}
			}
		}

#elif defined(__AVX2__)
		
		std::array<uint64_t, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<uint64_t, 64> state3;

		MemoryTools::Clear(state3, 0, 64 * sizeof(uint64_t));

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

	}

	void ThreefishTest::Exception(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<uint8_t> key(ks.KeySize() + 1);
			std::vector<uint8_t> nonce(ks.IVSize());
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
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(1);
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
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(ks.IVSize());
			std::vector<uint8_t> info(ks.InfoSize() + 1);
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
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(ks.IVSize());
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

	void ThreefishTest::Finalization(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, 
		std::vector<uint8_t> &Expected, std::vector<uint8_t> &MacCode1, std::vector<uint8_t> &MacCode2)
	{
		const size_t CPTLEN = Message.size() + Cipher->TagSize();
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<uint8_t> cpt(CPTLEN * 2);
		std::vector<uint8_t> otp(MSGLEN * 2);
		SymmetricKey kp(Key, Nonce);

		// encrypt msg 1
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF4"));
		}

		// verify the output
		if (IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) == false || IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -TF5"));
		}
		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Output does not match the known answer! -TF6"));
		}
	}

	void ThreefishTest::Kat(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> cpt(CPTLEN);
		std::vector<uint8_t> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -TV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV2"));
		}
	}

	void ThreefishTest::MonteCarlo(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> msg = Message;
		std::vector<uint8_t> enc(CPTLEN);
		std::vector<uint8_t> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, MSGLEN);
			msg = enc;
		}

		if (IntegerTools::Compare(enc, 0, Expected, 0, MSGLEN) == false)
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
		const uint32_t MINSMP = static_cast<uint32_t>(Cipher->ParallelBlockSize());
		const uint32_t MAXSMP = static_cast<uint32_t>(Cipher->ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<uint8_t> cpt1;
		std::vector<uint8_t> cpt2;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> otp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> nonce(ks.IVSize());
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

			rnd.Generate(inp, 0, MSGLEN);
			rnd.Generate(key, 0, key.size());
			rnd.Generate(nonce, 0, nonce.size());

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
		const uint32_t MINPRL = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint32_t MAXPRL = static_cast<uint32_t>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<uint8_t> cpt;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> nonce(ks.IVSize());
		std::vector<uint8_t> otp;
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

			rnd.Generate(inp, 0, MSGLEN);
			rnd.Generate(key, 0, key.size());
			rnd.Generate(nonce, 0, nonce.size());
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

	void ThreefishTest::Verification(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &Mac)
	{
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<uint8_t> cpt(CPTLEN);
		std::vector<uint8_t> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN) == false)
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
		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
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
			std::string("83366535C77EA20C9BDA27714B06AE4FCF615C469C5FEDB249A0FD24EB89273F"),																	// tsx256k256
			std::string("FD84BEE7151D260C52C67E9634EA83E30F25B0C7620EB15C868AC9EACAEE8616"),
			// tsx512 mac512
			std::string("8E78A52890DB35E890287C9E5DE861A6FF2A8EC6DFC46DDD128BDE350B87F6A5DAD191F6D14D091F6E8467FF28D80B3D70ACA143D68CD95F72B02B48842EDC09"),	// tsx512k512
			std::string("17AB9475ACBB133A100771DB30B56438CD06CE50D5CF8E28763DE3193308BC7498C5A77D73E0B101612770C68447742BF81554495371BE9EFC88E776ED0BACAE"),
			// tsx1024 mac1024
			std::string("42F9C235C97B4FF540F884858A2464F4019982FA53AA028C91710007C1ABB37DBA3BD7B9FB6C51968DA2A0D549A8B8A69CE419743F7BA6F903CB39995AD93D10"
				"4BBF7817A7A9F26BC4E1718F0F52E1F7B17D03329480342A08D60DB3665CC192103CE5FFEFA1DB8AB1B7D24B6A41B06B1A24509A82CD438F5285D01A9EABFE04"),
			std::string("F53A7B161B9E76EF550AA341CF1DFA3425E3031702D82A0F43D19CFF409A0073DE231BF72D91816606619568B45CD0ADADCBBDACCCFEC6DDB8511BD658B0F1ED"
				"E9BB9B72D7027630392A0F57361F3F5335903F65CE8B9FD73FFE163973F73A71F5A1BBFED51C0E16444B5BF33D42AA2847BC59C30DC0EA44758564272C716438")
		};
		HexConverter::Decode(code, 6, m_code);

		const std::vector<std::string> expected = 
		{
			// tsx256
			std::string("F483F8DAB670B5CEA16E1246683D87D567090519531908A433BFFDE65313F1CA83366535C77EA20C9BDA27714B06AE4FCF615C469C5FEDB249A0FD24EB89273F"),																	// tsx256k256
			std::string("70EA75CE071C24670A8AB583ED7ADDB64AE83D669BCA9E5E42F5ED70F691166A"),
			// tsx512
			std::string("C59B94E79547F1167CA534438421FECBC73705D8D23E7EBDC0D573EE8C63D15E50DC6A5DBCDE0C2F02C36288242EBF7E313FA1B05405218A4624EDE79C81ED25"
				"8E78A52890DB35E890287C9E5DE861A6FF2A8EC6DFC46DDD128BDE350B87F6A5DAD191F6D14D091F6E8467FF28D80B3D70ACA143D68CD95F72B02B48842EDC09"),
			std::string("0F43C172A46F8EAC0E961938B2E56BC128B982CBA28DDE70C88C2DA3EF37BA3DBB457F420390EE146735169E573620C6B0415160284749DDFC72A3D13904557E"),
			// tsx1024
			std::string("0267F65A1CB54AC4FA003B6F427250B7535D1B393EFAEA724BC5F37902DA7C1DB75C2BFE80C35CF8570EA570A2A94C3A10A64F572ADC1E1B5417A7A85E6A955B"
				"7A23578C9B5DF76923BE053DB17EFA2E80E90624763AC9B87F10871C7CD84A910B649E26CACD54DB8AB4FECD9B6FC708C47F99FDCBCC28DDE6EAC80CD6589D82"
				"42F9C235C97B4FF540F884858A2464F4019982FA53AA028C91710007C1ABB37DBA3BD7B9FB6C51968DA2A0D549A8B8A69CE419743F7BA6F903CB39995AD93D10"
				"4BBF7817A7A9F26BC4E1718F0F52E1F7B17D03329480342A08D60DB3665CC192103CE5FFEFA1DB8AB1B7D24B6A41B06B1A24509A82CD438F5285D01A9EABFE04"),
			std::string("B3F7134A5977D657479377A1224CA0ACF29C79B4AF0C8A23B269850F6DAEEDB37F8EFCD7F0B65BA7B4F5264E255B459E96AC4D1DD13D7957B6581DB116C7F584"
				"8BCD73FA5B588D28B0EE942F8E5F01C85E4E85B743B7CB0EC885B77533D733ABD811B6AB5D2AA25DFADA55138EEB5E3FF150BE937F1AB241DC374DB1F1BA6D09")
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C"
				"0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180")
		};
		HexConverter::Decode(message, 3, m_message);

		const std::vector<std::string> monte =
		{
			std::string("963A9EAB3EBEFCAAF8BD27F68755D00DB8269C1EBADD4BD3BE75A36A39A31F9F"),
			std::string("39AB0176F64ED6A121D85C78DEF78D7A548118A89FC5E4C00508F3D5DED5DABC34D0544262FF32BBAD7F2BDF2963F10EE796FB7A1A70BE4BDC2546A95788849D"),
			std::string("4FE91078F7C2BE5A8AA30D5F53C71C77A421D1A836EA0F08D6AA543415A792CDD9B05BD4A0725501B14E87BF1A13F57A5EFE4A50C8D69571401CA74659C06C0D"
				"CC8F7B905BFD5E67E7A8FFAF122DAEB6E209A6C0C57E6A45380EB24ACEF0D5E2A0E6A4580043AA1E5A172FD54CA80CFAA87B82ADBA96AD909034F44DACCC5474")
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
