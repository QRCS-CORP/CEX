#include "RCSTest.h"
#include "../CEX/ACS.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/RCS.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Cipher::Stream::ACS;
	using Exception::CryptoAuthenticationFailure;
	using Exception::CryptoSymmetricException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Cipher::Stream::RCS;
	using Prng::SecureRandom;
	using Enumeration::KmacModes;
	using Enumeration::StreamCipherConvert;
	using Enumeration::StreamCiphers;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string RCSTest::CLASSNAME = "RCSTest";
	const std::string RCSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the 256-bit-wide Rijndael (RCS) authenticated stream cipher.";
	const std::string RCSTest::SUCCESS = "SUCCESS! All RCS tests have executed succesfully.";
	const bool RCSTest::HAS_AESNI = HasAESNI();

	//~~~Constructor~~~//

	RCSTest::RCSTest()
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

	RCSTest::~RCSTest()
	{
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string RCSTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &RCSTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string RCSTest::Run()
	{
		try
		{
			// rcs standard and authenticated variants
			RCS* rcss = new RCS(false);
			RCS* rcsa = new RCS(true);

			// stress test authentication and verification using random input and keys
			Authentication(rcsa);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0], m_code[1]);
			Finalization(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2], m_code[3]);
			Finalization(rcsa, m_message[2], m_key[2], m_nonce[0], m_expected[4], m_code[4], m_code[5]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(rcss, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(rcss, m_message[1], m_key[1], m_nonce[0], m_expected[1]);
			Kat(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3]);
			Kat(rcsa, m_message[2], m_key[2], m_nonce[0], m_expected[4]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer cipher tests.."));

			//Sequential(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[5], m_expected[6], m_expected[7]);
			Sequential(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[8], m_expected[9], m_expected[10]);
			Sequential(rcsa, m_message[2], m_key[2], m_nonce[0], m_expected[11], m_expected[12], m_expected[13]);
			OnProgress(std::string("RCSTest: Passed RCS sequential transformation calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(rcss, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(rcss);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 parallel to sequential equivalence test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("RCSTest: Passed RCS state serialization test.."));

			// looping test of successful decryption with random keys and input
			Stress(rcss);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0]);
			Verification(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2]);
			Verification(rcsa, m_message[2], m_key[2], m_nonce[0], m_expected[4], m_code[4]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer authentication tests.."));

			delete rcss;
			delete rcsa;

			if (HAS_AESNI)
			{
				OnProgress(std::string("***Testing the AES-NI implementation ACS***"));

				// rcs standard and authenticated variants
				ACS* acss = new ACS(false);
				ACS* acsa = new ACS(true);

				// stress test authentication and verification using random input and keys
				Authentication(acsa);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 MAC authentication tests.."));

				// test 2 succesive finalization calls against mac output and expected ciphertext
				Finalization(acsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0], m_code[1]);
				Finalization(acsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2], m_code[3]);
				Finalization(acsa, m_message[2], m_key[2], m_nonce[0], m_expected[4], m_code[4], m_code[5]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer finalization tests."));

				// original known answer test vectors generated with this implementation
				Kat(acss, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
				Kat(acss, m_message[1], m_key[1], m_nonce[0], m_expected[1]);
				Kat(acsa, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
				Kat(acsa, m_message[1], m_key[1], m_nonce[0], m_expected[3]);
				Kat(acsa, m_message[2], m_key[2], m_nonce[0], m_expected[4]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer cipher tests.."));

				Sequential(acsa, m_message[0], m_key[0], m_nonce[0], m_expected[5], m_expected[6], m_expected[7]);
				Sequential(acsa, m_message[1], m_key[1], m_nonce[0], m_expected[8], m_expected[9], m_expected[10]);
				Sequential(acsa, m_message[2], m_key[2], m_nonce[0], m_expected[11], m_expected[12], m_expected[13]);
				OnProgress(std::string("RCSTest: Passed ACS sequential transformation calls test.."));

				// run the monte carlo equivalency tests and compare encryption to a vector
				MonteCarlo(acss, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 monte carlo tests.."));

				// compare parallel output with sequential for equality
				Parallel(acss);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 parallel to sequential equivalence test.."));

				// looping test of successful decryption with random keys and input
				Stress(acss);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 stress tests.."));

				// verify ciphertext output, decryption, and mac code generation
				Verification(acsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0]);
				Verification(acsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2]);
				Verification(acsa, m_message[2], m_key[2], m_nonce[0], m_expected[4], m_code[4]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer authentication tests.."));

				delete acss;
				delete acsa;
			}

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

	void RCSTest::Authentication(IStreamCipher* Cipher)
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

	void RCSTest::Exception()
	{
		// test serialized loading with invalid state
		try
		{
			SecureVector<byte> sta(100);
			RCS cpr2(sta);

			throw TestException(std::string("RCS"), std::string("Exception"), std::string("Exception handling failure! -AE1"));
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
			RCS cpr(false);
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
			RCS cpr(false);
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
			RCS cpr(false);
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
			RCS cpr(false);
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

	void RCSTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
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

	void RCSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
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
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -TV2"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV1"));
		}
	}

	void RCSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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

	void RCSTest::Parallel(IStreamCipher* Cipher)
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

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
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

	void RCSTest::Sequential(IStreamCipher* Cipher, const std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce,
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

	void RCSTest::Serialization()
	{
		const size_t TAGLEN = 32;
		const size_t MSGLEN = 137;
		RCS cpr1(true);
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
		RCS cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<byte> sta2 = cpr1.Serialize();
		RCS cpr3(sta2);

		cpr1.Transform(cpt1, 0, plt1, 0, plt1.size());
		cpr3.Transform(cpt2, 0, plt2, 0, plt2.size());

		if (plt1 != msg || plt1 != plt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS2"));
		}
	}

	void RCSTest::Stress(IStreamCipher* Cipher)
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
			cpt.clear();
			inp.clear();
			otp.clear();
			cpt.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
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

	void RCSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
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

	bool RCSTest::HasAESNI()
	{
#if defined(__AVX__)
		CpuDetect dtc;

		return dtc.AVX() && dtc.AESNI();
#else
		return false;
#endif
	}

	void RCSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// rcsc256k256
			std::string("CE628327C50E0893EF608FA819E46E2521CFD604B26326261A40030B88271914"),
			std::string("423E6860E3EA2039EDB2CCA151FE653CED118E4C1A64B511484748795982D512"),
			// rcsc512k512
			std::string("9A15E3108957135AA660986C8DABE15BAA480A4A7360D68E78F5A9C5A7749C0B244C6F740B7492B57F7C57DF95B013E5682A10F3B76D3FBB99A35BB378BFBAC0"),
			std::string("9F6F9ED64DDCC235E798955274B951F016BB5128B2C5092AACC06B2917ECE530E729D350C8E4E437D117FF1CB8107DCBD8747FACEFCE2B2EB175839A2991EC8A"),
			// rcs1024k1024
			std::string("A915546833FEC271D1480F2814EDF992A56AF60A8A87CA130B35FE89AD15DC3FA142BD32135661135F72F4742556CF4D1AB8D5221384F6FDE77D2D7CCD6D555C"
				"D4C42C101BF744D47551410D9ABF604224B23F6773A888203749CDBDD10840FEF246BF45FB92E2CB35B7A57420C8F971E146CEFCEBC4CD821FAE2A5972E8A419"),
			std::string("EDA807B4E2FBC5172CD03B5DAF05F6AF4AF8AB96D50EA2C4DCA6D31901EEA63850C0D353F964352E025AA605F405F83009B1043EA89D9DFFD5833196C3C918A8"
				"8CF074D0F3BE1A59CF996464FAC9180539BA0D662ACBC07C19D91E68B07065CE0DCC6D280653CD5041FA113F6F2AC3F78FCB7923DE248CEFC72D75EA68252D47")
		};
		HexConverter::Decode(code, 6, m_code);

		const std::vector<std::string> expected =
		{
			// kat tests
			// rcs256s
			std::string("9EF7D04279C5277366D2DDD3FBB47F0DFCB3994D6F43D7F3A782778838C56DB3"),
			// rcs512s
			std::string("8643251F3880261010BF195886C0496CC2EB07BB68D9F13BCBD266890467F47F57FA98C08031903D6539AC94B4F17E3A45A741159FF929B0540436FFE7A77E01"),
			// rcsc256k256
			std::string("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03"),
			// rcsc512k512
			std::string("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"),
			// rcsc1024k1024
			std::string("469D7D1F5B83E17BF5D11C806A87BC060C5820C1566AA9CD89BC9606EE7964D3DDE8D819B1489325C2D8A84AB0209FC7A447164D0BD62403A1633D9E6CE1AB9C"
				"42326455C3CF4879708FA3DB260C3075E898CE052F7F39F8428332B2B5CF8B388F8AC64050C74C9947E79AB5661D953A15DEA04F9E86D3F148ABC3467F27DAB3"),
			// sequential tests
			// hbar256k256
			std::string("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03EBC24989F5DC4F8598BF155E24944745E52B7DC27161CA3D9DB7951647F41DB8"),
			std::string("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC05BB0DC047DB2ADA45F363A919EE677C9C1C7478A63E78E0C66AB17078AEC4E30C6B9063BB20B68"),
			std::string("A4F915090E2BE9BB71C93B2847935751E3D9B2A746365462CA26116B661FC0BC4E95F3F17683BD9F9D854AD252B419ACB270E11890924AE8A9CC54CF8A2FD582"),
			// hbar512k512
			std::string("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
				"CA4C3AF6D1BF2FA8694483FC1F429A7ECC7C9B5F6FCB8504265DE0385B4D012A8E11035F172C98090549B38FA4B0525ED747EE9670B240C1EC3C2E03070E3E11"),
			std::string("388270BF8DF03483BB287FFA527D81403F0362210FD525657C8541250DFFE3BAD1285FAB37A6821DA524F3F7FF7EFCB39C5B59E3897B177E45D6AA7F4BB5BE77"
				"F8A3206DD873100E1CC7AD430EDB01A4D464EAE2DB23BF310E53C65A1AABDC92D0F1F64D9A427447296475CA9429F715967863ED209715453FA48030E43C7C35"),
			std::string("80DE0F8E40DB5DCDBE6F844F523C4FDE4AB9681DF7721382AF98A219BC78688A97C0CCCD359F4A21EE875B5D6842CE58AE30512847650223934666175F3F62E4"
				"EECFA967C23272F66EC25C4A7764FEB4E81055350BEEFA40140E2C9001A74E7BE42750B6B9D6D1575D849EACAAD8E21A9049E1A9F1FDFB7375AF1D09ED0B5AC8"),
			// hbar1024k1024
			std::string("469D7D1F5B83E17BF5D11C806A87BC060C5820C1566AA9CD89BC9606EE7964D3DDE8D819B1489325C2D8A84AB0209FC7A447164D0BD62403A1633D9E6CE1AB9C"
				"42326455C3CF4879708FA3DB260C3075E898CE052F7F39F8428332B2B5CF8B388F8AC64050C74C9947E79AB5661D953A15DEA04F9E86D3F148ABC3467F27DAB3"
				"392AF7F78ADAF75A5A1F3D3AFB13D238EE8C4449A748118041D1B0A5635885F96621D2D9E83C05C12EC66DB66C1AE07D2CE9105222139F6D2DB4F06F1A6BF9BA"
				"9E75DD9754A335D154E7D6F08F46D977D4D924A6D640A5748208DF5B125747C37AD1E54E64C6D5CBE692B8C209B7F8C7CC815BD4ED4E7A43FE5C2BB034BC2118"),
			std::string("CEDC009FC7F4B2B7625857F38655AA32DCBB5701FCCFEF2CDA5366952BAE54DB9C1B0FD2C172C49A0692FD9821951C92BB19AEAEA260972C1B5F550EFACD7D93"
				"6D7A2BB73791523FCC44CFC48223C4B552766C9F2E391E6C52FC79C1BE7416AE9CC7408F95CE7DBC177D58E503A637CC8C34CA352872CB04ED49E5A19FA15C74"
				"6B76D66584208807DCA5CB28F7A5C32BB2B5E237CA38FCA1D2800F71F9A250EB7EF241E4304E1F8207BDCB53D063A406DB33C29ED149C9C3BDB6CB83D85BC05B"
				"96F5EC1FB76C06E75CC9CD338494B404E980017DD005CE35161570A3E4EA869D65B9634ECD0604FF32D2E720CAA1AB297B2529C2BB1C93868818BA7A071DB32D"),
			std::string("150DF56DAC5E16F149FC12B2BA84DB85AA5E179454FB45DB906AE541F48618F91401405C1C870549118ED5837374FAF46F811CA9FA5E3307DB73F1256315ABEB"
				"F38CD2910FA820EE514D5CCA2E2DFBD7301CC1A9CBE2C2685372D14979ECCC960098F41358EAD8DD79742A496102E4A6CDAD286DCB42809656AE3377C4F88BC8"
				"4823A98B485F759D8DAC8347F15438A9F7926134DF90B25EC7B4D669CAA98DAC7D4C968093623CA8E56ADE0033CB49038DC9FF324B946BBBE5C852D942A24AF0"
				"BA007D1507161331DB8CEE2859FF672C34F9DFFD7E52FC22E00DCE52CE93963A77537215F9BB3889183924790EE23AC4FF1A2B9AAAAC6771FB7F611112BC035A")
		};
		HexConverter::Decode(expected, 14, m_expected);

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
			std::string("254DF62F340D3D7915CBE59E4B5AE14643EA32DBF976DF1899072BF8F9FB6B8F")
		};
		HexConverter::Decode(monte, 1, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		/*lint -restore */
	}

	void RCSTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
