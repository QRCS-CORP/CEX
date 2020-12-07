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
	const std::string RWSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit key versions of the  Rijndael 512-bit wide block (RWS) authenticated stream cipher.";
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
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0], m_code[1]);
			Finalization(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
			Finalization(rwsa, m_message[2], m_key[2], m_nonce[0], m_expected[3], m_code[4], m_code[5]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(rwss, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2]);
			Kat(rwsa, m_message[2], m_key[2], m_nonce[0], m_expected[3]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 known answer cipher tests.."));

			Sequential(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[4], m_expected[5], m_expected[6]);
			Sequential(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[7], m_expected[8], m_expected[9]);
			Sequential(rwsa, m_message[2], m_key[2], m_nonce[0], m_expected[10], m_expected[11], m_expected[12]);
			OnProgress(std::string("RWSTest: Passed RWS sequential transformation calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(rwss, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(rwss);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 parallel to sequential equivalence test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("RWSTest: Passed RWS state serialization test.."));

			// looping test of successful decryption with random keys and input
			Stress(rwss);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(rwsa, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0]);
			Verification(rwsa, m_message[1], m_key[1], m_nonce[0], m_expected[2], m_code[2]);
			Verification(rwsa, m_message[2], m_key[2], m_nonce[0], m_expected[3], m_code[4]);
			OnProgress(std::string("RWSTest: Passed RWS-256/512/1024 known answer authentication tests.."));

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
			SecureVector<byte> sta(100);
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
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.IVSize());
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
			std::vector<byte> key(ks.KeySize() + 1);
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
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(1);
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
			std::vector<byte> key(ks.KeySize());
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

	void RWSTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
	{
		const size_t TAGLEN = Key.size();
		const size_t CPTLEN = Message.size() + TAGLEN;
		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(CPTLEN * 2);
		std::vector<byte> otp(MSGLEN * 2);
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

	void RWSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Key.size() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(CPTLEN);
		std::vector<byte> otp(MSGLEN);
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

	void RWSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
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
		const uint MINSMP = static_cast<uint>(Cipher->ParallelBlockSize());
		const uint MAXSMP = static_cast<uint>(Cipher->ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.IVSize());
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

	void RWSTest::Sequential(IStreamCipher* Cipher, const std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce,
		const std::vector<byte> &Output1, const std::vector<byte> &Output2, const std::vector<byte> &Output3)
	{
		std::vector<byte> ad(20, 0x01);
		std::vector<byte> dec1(Message.size());
		std::vector<byte> dec2(Message.size());
		std::vector<byte> dec3(Message.size());
		std::vector<byte> otp1(Output1.size());
		std::vector<byte> otp2(Output2.size());
		std::vector<byte> otp3(Output3.size());

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
		std::vector<byte> cpt1(MSGLEN + TAGLEN);
		std::vector<byte> cpt2(MSGLEN + TAGLEN);
		std::vector<byte> key(ks.KeySize(), 0x01);
		std::vector<byte> cust(ks.InfoSize(), 0x02);
		std::vector<byte> msg(MSGLEN, 0x03);
		std::vector<byte> nonce(ks.IVSize(), 0x04);
		std::vector<byte> plt1(MSGLEN);
		std::vector<byte> plt2(MSGLEN);

		SymmetricKey kp(key, nonce, cust);
		cpr1.Initialize(true, kp);

		SecureVector<byte> sta1 = cpr1.Serialize();
		RWS cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<byte> sta2 = cpr1.Serialize();
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

	void RWSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Key.size();
		std::vector<byte> cpt(MSGLEN + TAGLEN);
		std::vector<byte> otp(MSGLEN);
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
			std::string("5AF5E8272DEDDB452E9CDDE68A1985B82A042597E47425E6A33D17FFC5412EC00B8CABD5CD2D0B081BE0F3A40CBDDBC4E31E053AE3C11D6E601B1B22A4AFA52D"),
			// qot1024k1024
			std::string("0D367770852AFC9BDDCC179B604E818782B54F695DF8F86070666E1414D0EFE58E573E3EDF4EDD0FC46D494DE73952EFBEDF62882506736EF15A91D7DD9E65A3"
				"C11C37970DA2A81D2BDD74F1B4FC3D1ADF96C4F5C58413393458928E814D7A4610A8883FFEB46C0D5014BB431F516C184632C05A2B00DBD6FDA2E65F45129E37"),
			std::string("465E2E8C90894756C6416343910D663DE4837D5E7D106A5A276FE6FF4D8A4EC77A8567B7C2C0AD4A0DFC4220ACE91A70CB376516D5FA2511C0D1EBD0458B6CF5"
				"27513E4374D3F794379650CB9AD1BDCBE72F13595A4C7B44D0873962868BCBDD05F9C4728A484B84BD3B5BAA00AEADF23E3DC6CF9CAA3256B3CE889013F4A73E")
		};
		HexConverter::Decode(code, 6, m_code);

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
			// qotc1024k1024
			std::string("C3F0A1F5D688ADB089273039F4BE6227547D0753AD16D1E8557A83B26B2E3A3AFCF6EFE55B2C668987C79864444BD793DF4AA98477D2FACC5367F48F628FAF46"
				"B203DFDAF5134040A957F4E78F839AD474F9AA698E73E01BE51BA088E8BEB9A98903A747E9C103BA8FBA78869AAC69522A3C81E9187B6A57DE8BEAFDDF0CA6ED"
				"0D367770852AFC9BDDCC179B604E818782B54F695DF8F86070666E1414D0EFE58E573E3EDF4EDD0FC46D494DE73952EFBEDF62882506736EF15A91D7DD9E65A3"
				"C11C37970DA2A81D2BDD74F1B4FC3D1ADF96C4F5C58413393458928E814D7A4610A8883FFEB46C0D5014BB431F516C184632C05A2B00DBD6FDA2E65F45129E37"),
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
				"2D0311C107BE7F070FF4462B2A1EC44F8C4ADD7ED59B8B7A582277250995A2BF2ADDDD509E41E3EFB4AB40E693250B22BE436D820C38C647C9BDE7505D766C0D"),
			// hbar1024k1024
			std::string("C3F0A1F5D688ADB089273039F4BE6227547D0753AD16D1E8557A83B26B2E3A3AFCF6EFE55B2C668987C79864444BD793DF4AA98477D2FACC5367F48F628FAF46"
				"B203DFDAF5134040A957F4E78F839AD474F9AA698E73E01BE51BA088E8BEB9A98903A747E9C103BA8FBA78869AAC69522A3C81E9187B6A57DE8BEAFDDF0CA6ED"
				"5773B604FE76BABDBE0FF3C156E918DD5ABDEF74FBC7241FA443ADD4E3150F6BA29E7CDB929D8DFF49BCC9642907360B0B63A906861FAD37DD8DFDF557EB867F"
				"E75A3692BF3B3FA57FBD6D24982F1D48316A6FA0BBE1EA49B48143DCE3A3161EABE2EA486BA5EF4BE3799511387E989781052E10C10027F4EBDA59BFB6B69D56"),
			std::string("2FD502232C9CCB6F640B680B2942B587DD8EA3A1B1AF0F3B1E49B7AA7AA92A95BBD7F9F52CC51AB0C7471A394E28D2CAB825CCD59C90711A8944D7C22FAD8EEE"
				"FA72EC7E012B8F7595678E10617DFEAC006F8DC3000FB68DB6F6942DA76984A47A2495502DB1038AF07D58688D0000E23FC8698FCBDF1EFD77D9DFF87E9457FB"
				"B095154544FC18F0E22C2A2154EA3C3D1E1C6F0CB92B95CE1CF4E31020C547881D03C5EB419D5B14B27DB3B272736F5EB11EE659ACA4EC17896DDF324631F2DC"
				"612FE586C3198F9A6A921B888B7BADC75B38214605E2BEFA489DF62AC95300F40E72C2DFEE6EC2BC1476C032C3DFFC8D03E2B3663D21C9AF94019F0D9F2394CF"),
			std::string("8DDA10570C6583BCB9F63744D0AC7CB491A4FF1B9C6BCAB503E0713D268B17F20FBC3D2D2BC423BAD14E5C4F2E185377653585EA47FF550D72F918EE419D4B37"
				"4E0CBC3E98BE42444D8CF6CD800EE2F66E338C9981E9413BFE9448F95CB6590417E5A3F128D740782FFC72ADC73538FC975B0A777B0F2F6230E1C2B67034029A"
				"72F76D9D33B5EBEB2F1D906B5E1C76F70B876327B6C546C5DBA6BF3AEF5128ACE6AAE1B0303DD8C17E82BDC0B6892CB3F71E0425DD69CF576E12E8AC206524BD"
				"304F646FFFD8197CB94E8B54E15D9EDE3FF5DDCF218E50517A086E7350830E360AE5F77764593D506E090596E24045514589ED99633AC554D6988C2EB0B61EAF")
		};
		HexConverter::Decode(expected, 13, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
			"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"),
		};
		HexConverter::Decode(message, 3, m_message);

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
