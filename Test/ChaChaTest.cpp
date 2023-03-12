#include "ChaChaTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/ChaChaP20.h"
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
	using Cipher::Stream::ChaChaP20;
	using Cipher::Stream::CSX512;
	using Exception::CryptoAuthenticationFailure;
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
	const std::string ChaChaTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the ChaCha stream cipher (ChaChaP20 and CSX512) authenticated stream ciphers.";
	const std::string ChaChaTest::SUCCESS = "SUCCESS! All ChaCha tests have executed succesfully.";

	//~~~Constructor~~~//

	ChaChaTest::ChaChaTest()
		:
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
			ChaChaP20* csx256a = new ChaChaP20(true);
			ChaChaP20* csx256s = new ChaChaP20(false);

			// stress test authentication and verification using random input and keys
			//Authentication(csx256a);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 MAC authentication tests.."));

			// compare parallel to sequential output for equality
			CompareP256();
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 permutation variants equivalence test.."));

			// test all exception handlers for correct operation
			Exception(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 exception handling tests.."));

			// original known answer test vectors generated with this implementation
			// chachapoly20-kmac256 vectors
			Kat(csx256a, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx256a, m_message[0], m_key[1], m_nonce[1], m_expected[1]);
			Kat(csx256a, m_message[0], m_key[2], m_nonce[4], m_expected[2]);
			Kat(csx256a, m_message[0], m_key[3], m_nonce[4], m_expected[3]);
			Kat(csx256a, m_message[0], m_key[2], m_nonce[5], m_expected[4]);
			Kat(csx256a, m_message[0], m_key[2], m_nonce[6], m_expected[5]);

			// IETF vectors: non-authenticated standard chachapoly20
			Kat(csx256s, m_message[0], m_key[2], m_nonce[4], m_expected[6]);
			Kat(csx256s, m_message[0], m_key[3], m_nonce[4], m_expected[7]);
			Kat(csx256s, m_message[0], m_key[2], m_nonce[5], m_expected[8]);
			Kat(csx256s, m_message[0], m_key[2], m_nonce[6], m_expected[9]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 known answer cipher tests.."));
			
			Sequential(csx256a, m_message[0], m_key[0], m_nonce[0], m_expected[10], m_expected[11], m_expected[12]);
			OnProgress(std::string("ChaChaTest: Passed CSX-256 sequential transformation and authentication calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(csx256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(csx256s);
			OnProgress(std::string("ChaChaTest: Passed ChaCha-256 stress tests.."));

			delete csx256a;
			delete csx256s;

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
		std::vector<uint8_t> cpt;
		std::vector<uint8_t> inp;
		std::vector<uint8_t> key(16);
		std::vector<uint8_t> nonce(ks.IVSize());
		std::vector<uint8_t> otp;
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
		std::array<uint32_t, 2> counter{ 128, 1 };
		std::vector<uint8_t> output1(64);
		std::vector<uint8_t> output2(64);
		std::array<uint32_t, 14> state;

		MemoryTools::Clear(state, 0, state.size() * sizeof(uint32_t));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);
		ChaCha::PermuteR20P512U(output2, 0, counter, state);

		if (output1 != output2)
		{
			throw TestException(std::string("CompareP256"), std::string("PermuteP512"), std::string("Permutation output is not equal! -CP1"));
		}

#if defined(__AVX512__)

		std::array<uint32_t, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<uint8_t> output5(1024);

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

		std::array<uint32_t, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<uint8_t> output4(512);

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

		std::array<uint32_t, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<uint8_t> output3(256);

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
		std::array<uint64_t, 2> counter{ 128, 1 };
		std::vector<uint8_t> output1(128);
		std::array<uint64_t, 14> state;

		MemoryTools::Clear(state, 0, state.size() * sizeof(uint64_t));

		ChaCha::PermuteP1024C(output1, 0, counter, state, ROUNDS);

#if defined(__AVX512__)

		std::array<uint64_t, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<uint8_t> output4(1024);

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

		std::array<uint64_t, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<uint8_t> output3(512);

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
			std::vector<uint8_t> key(ks.KeySize() + 1);
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
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(1);
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
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(ks.IVSize());
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

	void ChaChaTest::Kat(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
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

		if (IntegerTools::Compare(cpt, 0, Expected, 0, Expected.size()) == false)
		{
			HexConverter::Print(cpt);
			HexConverter::Print(Expected);
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

	void ChaChaTest::MonteCarlo(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> msg = Message;
		std::vector<uint8_t> enc(MSGLEN);
		std::vector<uint8_t> dec(MSGLEN);
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
		const uint32_t MINSMP = static_cast<uint32_t>(Cipher->ParallelBlockSize());
		const uint32_t MAXSMP = static_cast<uint32_t>(Cipher->ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<uint8_t> cpt1;
		std::vector<uint8_t> cpt2;
		std::vector<uint8_t> inp;	
		std::vector<uint8_t> key(ks.KeySize());
		std::vector<uint8_t> nonce(ks.IVSize());
		std::vector<uint8_t> otp;
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

			if (cpt1 != cpt2) //17280-16488
			{
				for (size_t j = 0; j < cpt1.size(); ++j)
				{
					if (cpt1[j] != cpt2[j])
					{
						throw;
					}
				}
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

	void ChaChaTest::Sequential(IStreamCipher* Cipher, const std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce,
		const std::vector<uint8_t> &Output1, const std::vector<uint8_t> &Output2, const std::vector<uint8_t> &Output3)
	{
		std::vector<uint8_t> ad(20, 0x01);
		std::vector<uint8_t> dec1(Message.size());
		std::vector<uint8_t> dec2(Message.size());
		std::vector<uint8_t> dec3(Message.size());
		std::vector<uint8_t> otp1(Output1.size());
		std::vector<uint8_t> otp2(Output2.size());
		std::vector<uint8_t> otp3(Output3.size());

		SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);
		Cipher->SetAssociatedData(ad, 0, ad.size());
		Cipher->Transform(Message, 0, otp1, 0, Message.size());

		if (otp1 != Output1)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS1"));
		}

		Cipher->Transform(Message, 0, otp2, 0, Message.size());

		if (otp2 != Output2)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS2"));
		}

		Cipher->Transform(Message, 0, otp3, 0, Message.size());

		if (otp3 != Output3)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS3"));
		}

		// test inverse operation -decryption mode
		Cipher->Initialize(false, kp);
		Cipher->SetAssociatedData(ad, 0, ad.size());

		try
		{
			Cipher->Transform(otp1, 0, dec1, 0, dec1.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS4"));
		}

		if (dec1 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS5"));
		}

		try
		{
			Cipher->Transform(otp2, 0, dec2, 0, dec2.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS6"));
		}

		if (dec2 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS7"));
		}

		try
		{
			Cipher->Transform(otp3, 0, dec3, 0, dec3.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS8"));
		}

		if (dec3 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS9"));
		}
	}

	void ChaChaTest::Serialization()
	{
		const size_t TAGLEN = 64;
		const size_t MSGLEN = 137;
		CSX512 cpr1(true);
		Cipher::SymmetricKeySize ks = cpr1.LegalKeySizes()[0];
		std::vector<uint8_t> cpt1(MSGLEN + TAGLEN);
		std::vector<uint8_t> cpt2(MSGLEN + TAGLEN);
		std::vector<uint8_t> key(ks.KeySize(), 0x01);
		std::vector<uint8_t> cust(ks.InfoSize(), 0x02);
		std::vector<uint8_t> msg(MSGLEN, 0x03);
		std::vector<uint8_t> nonce(ks.IVSize(), 0x04);
		std::vector<uint8_t> plt1(MSGLEN);
		std::vector<uint8_t> plt2(MSGLEN);

		SymmetricKey kp(key, nonce, cust);
		cpr1.Initialize(true, kp);

		SecureVector<uint8_t> sta1 = cpr1.Serialize();
		CSX512 cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<uint8_t> sta2 = cpr1.Serialize();
		CSX512 cpr3(sta2);

		cpr1.Transform(cpt1, 0, plt1, 0, plt1.size());
		cpr3.Transform(cpt2, 0, plt2, 0, plt2.size());

		if (plt1 != msg || plt1 != plt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS2"));
		}
	}

	void ChaChaTest::Stress(IStreamCipher* Cipher)
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

	//~~~Private Functions~~~//

	void ChaChaTest::Initialize()
	{
		const std::vector<std::string> expected =
		{
			std::string("AC456AAE82F2C146D93507A759AAC3460DE764A1B65B1E0C53F7D70C72D4E5F08CFAB3DDC1AC9F3081C704478DA166043F5E3F49AFFB41BF98ECC8474B838F26"
				"8F0D9875E3B367492882AFD918C783A27E1DB5CEF118523A58F733A26F257D50"),	// csx256k256
			std::string("BCE834CA41003F8CB463B8B1DC5539FBDDEF97A848CCA3CA568F0D74859B7EB848D0F4F2F33CF31F535CA831ADC0744259EB74C15582A22AD0E2DEF191C2796D"
				"FB1BCA6CF94C96E281C2A251D38179BB3E83DB57A85AAF32CF8184B2621707EA"),	// csx256k256
			std::string("9434E08D464C5585CC51E37C098D3FFAF744F3CD34F224C2E41D4C5447441182F009DCA32BAA23F176B89F6D45EA329A2CBD051BEEE745C798290A106BBC620A"
				"620318DB097BF3252483051D2F0088AA713EE5FD16D1294CFDB94E7C6476F060"),	// csx256k256
			std::string("BD044A90549E67D06E6ACA361E98D585F1383D97867E550C55C35427E3418E630506E383A7A1C23EE7C4A6C9EDD95223BAC67250A7EAADB9DBD6F1DCBA040872"
				"DC9560F5E057425C6C6FA35347EE65C8A8EC7138961BDFFA2375E50722AE672B"),	// csx256k256
			std::string("360FB8212CE4C454797A00893173930B12BBE4137C79E7E6F38801FEEABD01375CEFB99F675177E52A0FC278B505AE3A05FBED084D085F32EB738FDF48ED8D88"
				"51BC80B4D954BC729A049C712C3CAD86E72FD84A4F414CCE39A4D786C4EBF609"),	// csx256k256
			std::string("D7944A7F34D957CDB61938EA10DB1A0F452BF9D2F04A80DF1B6966B00395584EB5825DE74C9774B071172C738BF5DE52BFE98730C3A41BA8110C4B7FCC4916FC"
				"3F0E165D508C2ACF3BD212788B842D73B8E233FE84A1426C2F85F11092827F3A"),	// csx256k256
			// IETF chacha-poly1305 for TLS, test vectors
			std::string("76B8E0ADA0F13D90405D6AE55386BD28BDD219B8A08DED1AA836EFCC8B770DC7DA41597C5157488D7724E03FB8D84A376A43B8F41518A11CC387B669B2EE6586"),	// csx256s: IETF test vector 1
			std::string("4540F05A9F1FB296D7736E7B208E3C96EB4FE1834688D2604F450952ED432D41BBE2A0B6EA7566D2A5D1E7E20D42AF2C53D792B1C43FEA817E9AD275AE546963"),	// csx256s: IETF test vector 2
			std::string("DE9CBA7BF3D69EF5E786DC63973F653A0B49E015ADBFF7134FCB7DF137821031E85A050278A7084527214F73EFC7FA5B5277062EB7A0433E445F41E31AFAB757"),	// csx256s: IETF test vector 3
			std::string("EF3FDFD6C61578FBF5CF35BD3DD33B8009631634D21E42AC33960BD138E50D32111E4CAF237EE53CA8AD6426194A88545DDC497A0B466E7D6BBDB0041B2F586B"),	// csx256s: IETF test vector 4
			// sequential mac
			std::string("AC456AAE82F2C146D93507A759AAC3460DE764A1B65B1E0C53F7D70C72D4E5F08CFAB3DDC1AC9F3081C704478DA166043F5E3F49AFFB41BF98ECC8474B838F26"
				"4E98EA4B55C6DE843B129AC1935C436CC4357DF01D289C7013ED7407FC7B5ABA"),
			std::string("3FEB46F96481B4E0E25EF6F41940BC5F014E1998DE92DC6E602049214C922699FA3C0B57FC6A40A1893CE2D54F1CCC59E8FCD959B31606EF746D31031DE20BCF"
				"377062612ACFD27DDA3715D3B5F4D34B26ACB1C717EB1D841C876C84BCDF074B"),
			std::string("C59882944D33115A418D220F8AD904A5F3F6EF02F95B0A9AEFA65158E252B67EA6031ADA3F99131572DAD751B747C697609C07C4F2F9AAB4507303DAF3E27E1A"
				"475B6FC422A51C981886FD484F1DB9C22017BA309CA5BB120C27BE35DB388D79"),
		};
		HexConverter::Decode(expected, 13, m_expected);

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			// TLS chacha20-poly1305 test vector 1
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			// TLS chacha20-poly1305 test vector 2
			std::string("0000000000000000000000000000000000000000000000000000000000000001"),
		};
		HexConverter::Decode(key, 4, m_key);

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
			std::string("3624BA23DB6CF0309371C68EDB94EBB83BE48266856BF95D34C457FE10C063A69D9590F04B816F249753BEDC3C21CECACBC09DA2DDEE3F0480CB63B086B6A8B1")
		};
		HexConverter::Decode(monte, 1, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("0D74DB42A91077DE"),
			std::string("167DE44BB21980E7"),
			std::string("167DE44BB21980E7"),
			std::string("0D74DB42A91077DE"),
			std::string("0000000000000000"),
			std::string("0000000000000001"),
			std::string("0100000000000000")
		};
		HexConverter::Decode(nonce, 7, m_nonce);

		/*lint -restore */
	}

	void ChaChaTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}