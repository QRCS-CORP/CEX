#include "RWSTest.h"
#include "../CEX/RWS.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/RWS.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Cipher::Stream::RWS;
	using Exception::CryptoAuthenticationFailure;
	using Exception::CryptoSymmetricException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Cipher::Stream::RWS;
	using Prng::SecureRandom;
	using Enumeration::KmacModes;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string RWSTest::CLASSNAME = "RWSTest";
	const std::string RWSTest::DESCRIPTION = "Tests the 256 and 512 bit key versions of the  Rijndael 512-bit wide block (RWS) authenticated stream cipher.";
	const std::string RWSTest::SUCCESS = "SUCCESS! All RWS tests have executed succesfully.";
	const bool RWSTest::HAS_AESNI = HasAESNI();

	//~~~Constructor~~~//

	RWSTest::RWSTest()
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

	RWSTest::~RWSTest()
	{
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string RWSTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RWSTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string RWSTest::Run()
	{
		try
		{
			// qot standard and authenticated variants
			RWS* rwss = new RWS(false);
			RWS* rwsa = new RWS(true);

			// stress test authentication and verification using random input and keys
			Authentication(rwsa);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("RWSTest: Passed RWS-256/512 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0], m_code[1]);
			Finalization(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(rwss, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 known answer cipher tests.."));

			Sequential(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[3], m_expected[4], m_expected[5]);
			Sequential(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[6], m_expected[7], m_expected[8]);
			OnProgress(std::string("RWSTest: Passed RWS sequential transformation calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(rwss, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(rwss);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 parallel to sequential equivalence test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("RWSTest: Passed RWS state serialization test.."));

			// looping test of successful decryption with random keys and input
			Stress(rwss);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0]);
			Verification(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2], m_code[2]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512 known answer authentication tests.."));

			delete rwss;
			delete rwsa;

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

	void RWSTest::Authentication(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t TAGLEN = ks.KeySize();
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
			rnd.Generate(nonce, 0, nonce.size());
			SymmetricKey kp(key, nonce);

			// encrypt plain-text, writes mac to output stream
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
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("Ciphertext output output is not equal! -TA2"));
			}
		}
	}

	void RWSTest::Exception()
	{
		// test serialized loading with invalid state
		try
		{
			SecureVector<uint8_t> sta(100);
			RWS cpr2(sta);

			throw TestException(std::string("RWS"), std::string("Exception"), std::string("Exception handling failure! -AE1"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}


		// test initialization key and nonce input sizes
		try
		{
			RWS cpr(false);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize() + 1);
			std::vector<uint8_t> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -AE2"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// no nonce
		try
		{
			RWS cpr(false);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -AE3"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// illegally sized nonce
		try
		{
			RWS cpr(false);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize());
			std::vector<uint8_t> nonce(1);
			SymmetricKey kp(key, nonce);

			cpr.Initialize(true, kp);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -AE4"));
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
			RWS cpr(false);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<uint8_t> key(ks.KeySize());
			SymmetricKey kp(key);

			cpr.Initialize(true, kp);
			cpr.ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), cpr.Name(), std::string("Exception handling failure! -AE5"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void RWSTest::Finalization(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &MacCode1, std::vector<uint8_t> &MacCode2)
	{
		const size_t TAGLEN = Key.size();
		const size_t CPTLEN = Message.size() + TAGLEN;
		const size_t MSGLEN = Message.size();
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

		// use constant time IntegerTools::Compare to verify in real-world use
		if (IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) == false || IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -TF5"));
		}

		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Output does not match the known answer! -TF6"));
		}
	}

	void RWSTest::Kat(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Key.size() : Message.size();
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

	void RWSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<uint8_t> msg = Message;
		std::vector<uint8_t> enc(MSGLEN);
		std::vector<uint8_t> dec(MSGLEN);
		size_t i;

		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}
		
		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Decrypted output does not match the input! -TM2"));
		}
	}

	void RWSTest::Parallel(IStreamCipher* Cipher)
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
		size_t i;

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.resize(MSGLEN);
			cpt2.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
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

	void RWSTest::Sequential(IStreamCipher* Cipher, const std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce,
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

	void RWSTest::Serialization()
	{
		const size_t TAGLEN = 32;
		const size_t MSGLEN = 137;
		RWS cpr1(true);
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
		RWS cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<uint8_t> sta2 = cpr1.Serialize();
		RWS cpr3(sta2);

		cpr1.Transform(cpt1, 0, plt1, 0, plt1.size());
		cpr3.Transform(cpt2, 0, plt2, 0, plt2.size());

		if (plt1 != msg || plt1 != plt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS2"));
		}
	}

	void RWSTest::Stress(IStreamCipher* Cipher)
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

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
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

	void RWSTest::Verification(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &Mac)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Key.size();
		std::vector<uint8_t> cpt(MSGLEN + TAGLEN);
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

		if (IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN) == false)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -TV2"));
		}

		if (otp != Message)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV3"));
		}

		// use constant time IntegerTools::Compare to verify mac
		if (IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN) == false)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Output does not match the known answer! -TV4"));
		}
	}

	//~~~Private Functions~~~//

	bool RWSTest::HasAESNI()
	{
#if defined(__AVX__)
		CpuDetect dtc;

		return dtc.AVX() && dtc.AESNI();
#else
		return false;
#endif
	}

	void RWSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// qotc256k256
			std::string("49F58F189B0790DB736A732D26F39AAC927B04FF916E786BFEB9C8EB0721EE94"),
			std::string("F2D7B6D9D321D45C9D5307C6925E5CF77FBAEB8F63A831125D8037D793E82AF7"),
			// qotc512k512
			std::string("824A7428505B2917388F66243B564174C339532909C5A04FA788F1A3B2CA5818D52885541E7576641DA3D34430CB00BDA6197069E3838DDC8F9948C049FC4FC0"),
			std::string("5AF5E8272DEDDB452E9CDDE68A1985B82A042597E47425E6A33D17FFC5412EC00B8CABD5CD2D0B081BE0F3A40CBDDBC4E31E053AE3C11D6E601B1B22A4AFA52D")
		};
		HexConverter::Decode(code, 4, m_code);

		const std::vector<std::string> expected =
		{
			// kat tests
			// qot256s
			std::string("F0085E32FCDB8D919F1DAEF1CAF6097FC415A10EBA481A90ACFF04DCE894A92A"),
			// qotc256k256
			std::string("3AF0F958D9172905EE1FE77DA3E80ABED2223E4DCBB0D9F9314BD5CE124FB8AA49F58F189B0790DB736A732D26F39AAC927B04FF916E786BFEB9C8EB0721EE94"),
			// qotc512k512
			std::string("7C83DB1AED7C005BB0BBDB9F01B128DCB5BDB9741D4D383AC3659667962183FE1F11207E68F4B329F9D975E5CCE2DDF1E6F8BB3831B9F7B2AF7691E7F86CDC9B"
				"824A7428505B2917388F66243B564174C339532909C5A04FA788F1A3B2CA5818D52885541E7576641DA3D34430CB00BDA6197069E3838DDC8F9948C049FC4FC0"),
			// sequential tests
			// hbar256k256
			std::string("3AF0F958D9172905EE1FE77DA3E80ABED2223E4DCBB0D9F9314BD5CE124FB8AAB5E0824563A6F57D04F7978F18C6D2F7CC19B74DB66957522B1C6F437A7A0A0A"),
			std::string("81311074FFF9A89B37A63534439373C152742C2854306A67B40F965047215F5D7979963F6A1809949731A0BCCBB59CF047B72EB323C41CF1C3D9B7DCEF59E0AF"),
			std::string("C0A22A4329D01EE6CB658D0E85B8F11700ECB8EA4E4E9E9DA098FC662F1747C0C1B5EC4ED6F72BCD0507AF801D7F0521692549940FC029C42D396FF763B5E230"),
			// hbar512k512
			std::string("7C83DB1AED7C005BB0BBDB9F01B128DCB5BDB9741D4D383AC3659667962183FE1F11207E68F4B329F9D975E5CCE2DDF1E6F8BB3831B9F7B2AF7691E7F86CDC9B"
				"6CB9CB12C4815746C101215E815C3ED7A41B23EF6D13A3FC41051870006C0CE3387A986B63BBABD399BB1E988DCBDDDC0041730F19A619C0142FD52663BE04E9"),
			std::string("C7DA61C5CBB92758E03CD166F9022EB03446927352001CDD009457D9449C157812DE0C08F7618F84E650CDAADFF412CFAB852A814F66885C9B8831CAFCFBB3C3"
				"88ED25C91BFC893406B8CA0A6F19DFEF488CC11CA8FA26FFEAB8F7E952425E9D360FA8DCF730DF44562109492F45F5F95AFCB3C0D4C992E866CFBF77ECBB94A1"),
			std::string("1DB31278E0C7F30032A7C045F7A8DC7D4CFD2E96DFC904A03AC539F7FFBD9D5FB27C81263BDE90E4D2D7E0D118F38BFC76B93797E97515D9A366259AC17D338B"
				"2D0311C107BE7F070FF4462B2A1EC44F8C4ADD7ED59B8B7A582277250995A2BF2ADDDD509E41E3EFB4AB40E693250B22BE436D820C38C647C9BDE7505D766C0D")
		};
		HexConverter::Decode(expected, 9, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 2, m_key);

		const std::vector<std::string> message =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F")
		};
		HexConverter::Decode(message, 2, m_message);

		const std::vector<std::string> monte =
		{
			std::string("EAD6019E750A5905233607A0614FFF1DA3D77F462EB7F38E2CAB74693930497C")
		};
		HexConverter::Decode(monte, 1, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		/*lint -restore */
	}

	void RWSTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
