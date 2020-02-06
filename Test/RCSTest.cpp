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
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Cipher::Stream::RCS;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
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
			RCS* rcs256s = new RCS(StreamAuthenticators::None);
			RCS* rcsc256h256 = new RCS(StreamAuthenticators::HMACSHA256);
			RCS* rcsc256k256 = new RCS(StreamAuthenticators::KMAC256);
			RCS* rcsc256p256 = new RCS(StreamAuthenticators::Poly1305);
			RCS* rcsc512h512 = new RCS(StreamAuthenticators::HMACSHA512);
			RCS* rcsc512k512 = new RCS(StreamAuthenticators::KMAC512);
			RCS* rcsc1024k1024 = new RCS(StreamAuthenticators::KMAC1024);

			// stress test authentication and verification using random input and keys
			Authentication(rcsc256k256);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(rcsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0], m_code[1]);
			Finalization(rcsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
			Finalization(rcsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3], m_code[4], m_code[5]);
			Finalization(rcsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6], m_code[7]);
			Finalization(rcsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5], m_code[8], m_code[9]);
			Finalization(rcsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6], m_code[10], m_code[11]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(rcs256s, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(rcsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(rcsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(rcsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3]);
			Kat(rcsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4]);
			Kat(rcsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5]);
			Kat(rcsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer cipher tests.."));

			Sequential(rcsc256h256, m_message[0], m_expected[7], m_expected[8], m_expected[9]);
			Sequential(rcsc256k256, m_message[0], m_expected[10], m_expected[11], m_expected[12]);
			Sequential(rcsc512h512, m_message[0], m_expected[13], m_expected[14], m_expected[15]);
			Sequential(rcsc512k512, m_message[0], m_expected[16], m_expected[17], m_expected[18]);
			Sequential(rcsc1024k1024, m_message[0], m_expected[19], m_expected[20], m_expected[21]);
			OnProgress(std::string("RCSTest: Passed RCS sequential transformation calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(rcs256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(rcs256s);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 parallel to sequential equivalence test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("RCSTest: Passed RCS state serialization test.."));

			// looping test of successful decryption with random keys and input
			Stress(rcs256s);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(rcsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0]);
			Verification(rcsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2]);
			Verification(rcsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3], m_code[4]);
			Verification(rcsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6]);
			Verification(rcsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5], m_code[8]);
			Verification(rcsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6], m_code[10]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512/1024 known answer authentication tests.."));

			delete rcs256s;
			delete rcsc256h256;
			delete rcsc256k256;
			delete rcsc256p256;
			delete rcsc512h512;
			delete rcsc512k512;
			delete rcsc1024k1024;

			if (HAS_AESNI)
			{
				OnProgress(std::string("***Testing the AES-NI implementation ACS***"));

				// rcs standard and authenticated variants
				ACS* acs256s = new ACS(StreamAuthenticators::None);
				ACS* acsc256h256 = new ACS(StreamAuthenticators::HMACSHA256);
				ACS* acsc256k256 = new ACS(StreamAuthenticators::KMAC256);
				ACS* acsc256p256 = new ACS(StreamAuthenticators::Poly1305);
				ACS* acsc512h512 = new ACS(StreamAuthenticators::HMACSHA512);
				ACS* acsc512k512 = new ACS(StreamAuthenticators::KMAC512);
				ACS* acsc1024k1024 = new ACS(StreamAuthenticators::KMAC1024);

				// stress test authentication and verification using random input and keys
				Authentication(acsc256k256);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 MAC authentication tests.."));

				// test 2 succesive finalization calls against mac output and expected ciphertext
				Finalization(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0], m_code[1]);
				Finalization(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
				Finalization(acsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3], m_code[4], m_code[5]);
				Finalization(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6], m_code[7]);
				Finalization(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5], m_code[8], m_code[9]);
				Finalization(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6], m_code[10], m_code[11]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer finalization tests."));

				// original known answer test vectors generated with this implementation
				Kat(acs256s, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
				Kat(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
				Kat(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
				Kat(acsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3]);
				Kat(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4]);
				Kat(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5]);
				Kat(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer cipher tests.."));

				Sequential(acsc256h256, m_message[0], m_expected[7], m_expected[8], m_expected[9]);
				Sequential(acsc256k256, m_message[0], m_expected[10], m_expected[11], m_expected[12]);
				Sequential(acsc512h512, m_message[0], m_expected[13], m_expected[14], m_expected[15]);
				Sequential(acsc512k512, m_message[0], m_expected[16], m_expected[17], m_expected[18]);
				Sequential(acsc1024k1024, m_message[0], m_expected[19], m_expected[20], m_expected[21]);
				OnProgress(std::string("RCSTest: Passed ACS sequential transformation calls test.."));

				// run the monte carlo equivalency tests and compare encryption to a vector
				MonteCarlo(acs256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 monte carlo tests.."));

				// compare parallel output with sequential for equality
				Parallel(acs256s);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 parallel to sequential equivalence test.."));

				// looping test of successful decryption with random keys and input
				Stress(acs256s);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 stress tests.."));

				// verify ciphertext output, decryption, and mac code generation
				Verification(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0]);
				Verification(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2]);
				Verification(acsc256p256, m_message[0], m_key[0], m_nonce[0], m_expected[3], m_code[4]);
				Verification(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6]);
				Verification(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[5], m_code[8]);
				Verification(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[6], m_code[10]);
				OnProgress(std::string("RCSTest: Passed ACS-256/512/1024 known answer authentication tests.."));

				delete acs256s;
				delete acsc256h256;
				delete acsc256k256;
				delete acsc256p256;
				delete acsc512h512;
				delete acsc512k512;
				delete acsc1024k1024;
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

		// test-1: compare large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(MSGLEN + TAGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt plain-text, writes mac to output stream
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntegerTools::Compare to verify mac
			if (!IntegerTools::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN))
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -TA1"));
			}

			if (!IntegerTools::Compare(inp, 0, otp, 0, MSGLEN))
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
			RCS cpr(StreamAuthenticators::None);
			Cipher::SymmetricKeySize ks = cpr.LegalKeySizes()[0];
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
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
			RCS cpr(StreamAuthenticators::None);
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
			RCS cpr(StreamAuthenticators::None);
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
			RCS cpr(StreamAuthenticators::None);
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
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("MAC output is not equal! -TF4"));
		}

		// use constant time IntegerTools::Compare to verify in real-world use
		if (!IntegerTools::Compare(otp, 0, Message, 0, MSGLEN) || !IntegerTools::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Decrypted output does not match the input! -TF5"));
		}

		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization"), Cipher->Name(), std::string("Output does not match the known answer! -TF6"));
		}
	}

	void RCSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV1"));
		}

		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -TV2"));
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
		std::vector<byte> nonce(ks.NonceSize());
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

	void RCSTest::Serialization()
	{
		const size_t MSGLEN = 137;
		RCS cpr1(StreamAuthenticators::KMAC256);
		Cipher::SymmetricKeySize ks = cpr1.LegalKeySizes()[0];
		std::vector<byte> cpt1(MSGLEN + cpr1.TagSize());
		std::vector<byte> cpt2(MSGLEN + cpr1.TagSize());
		std::vector<byte> key(ks.KeySize(), 0x01);
		std::vector<byte> cust(ks.InfoSize(), 0x02);
		std::vector<byte> msg(MSGLEN, 0x03);
		std::vector<byte> nonce(ks.NonceSize(), 0x04);
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

	void RCSTest::Sequential(IStreamCipher* Cipher, const std::vector<byte>& PlainText,
		const std::vector<byte>& Output1, const std::vector<byte>& Output2, const std::vector<byte>& Output3)
	{
		SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> ad(20, 0x01);
		std::vector<byte> dec1(PlainText.size());
		std::vector<byte> dec2(PlainText.size());
		std::vector<byte> dec3(PlainText.size());
		std::vector<byte> key(ks.KeySize(), 0x02);
		std::vector<byte> nonce(32, 0x03);
		std::vector<byte> otp1(Output1.size());
		std::vector<byte> otp2(Output2.size());
		std::vector<byte> otp3(Output3.size());

		SymmetricKey kp(key, nonce);

		Cipher->Initialize(true, kp);
		Cipher->SetAssociatedData(ad, 0, ad.size());
		Cipher->Transform(PlainText, 0, otp1, 0, PlainText.size());

		if (otp1 != Output1)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS1"));
		}

		Cipher->Transform(PlainText, 0, otp2, 0, PlainText.size());

		if (otp2 != Output2)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS2"));
		}

		Cipher->Transform(PlainText, 0, otp3, 0, PlainText.size());

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

		if (dec1 != PlainText)
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

		if (dec2 != PlainText)
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

		if (dec3 != PlainText)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS9"));
		}
	}

	void RCSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
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
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -TV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntegerTools::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("MAC output is not equal! -TV2"));
		}

		if (otp != Message)
		{
			throw TestException(std::string("Verification"), Cipher->Name(), std::string("Decrypted output does not match the input! -TV3"));
		}

		// use constant time IntegerTools::Compare to verify mac
		if (!IntegerTools::Compare(cpt, 0, Expected, 0, MSGLEN))
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
			// rcsc256h256
			std::string("AB2FCABE5014AB6FCF059F39A95F88B86E27E0037EFA2C17480D40A093C52D52"),
			std::string("1911C02D3D96D700D60F127FFABB04D9EC7C1A1739D61E7952CFDEE5868E1E61"),
			// rcsc256k256
			std::string("8C328773AAD85BB55C99B113122B3BA92341BE0E66181373AE734CB928217CA1"),
			std::string("5B4464A842E7A294EB98F541335992B790A8CF903677E49DD0EB71C9B244A6BB"),
			// rcsc256p256
			std::string("EAFDBC29459199B89B28C3E9632D519C"),
			std::string("BC2D211EC5F7DA286B2F40A13A97DEC9"),
			// rcsc512h512
			std::string("17CA7BEE0E3BD529A17A124E2D5DAA199E0A0BC88A01EFDC1214B7CCD60906248EECF6649B9CFC0B28AF9CA39AE4D1F9D9C5C5770028EB19E673ABADE06A4E59"),
			std::string("15E292606E8ED01E35DBB70BD5808770F230882F47DFCBCB4B01C8833710F4C6AAA8EC0D3AB983DB75A2850025C1A10A88613F00C53F6B8D7B92E54FB287874A"),
			// rcsc512k512
			std::string("DE6C0810F4903AB10A671832AE2F83B8DD26E40150DBC4488A8BBC734DBCC0527095A409CB6390E353AC5F303D354D077AF29591A9BB61C10697776D50F238C7"),
			std::string("343DD647754879EF75DA8C95A8E91A0838ED8120A94196859E0C8A02CC877AF11EC3546FCFA69AD6569945C407A2F1D959C92C9194FED045EF4EB71F74C08646"),
			// rcs1024k1024
			std::string("0080484CA13B51687730B67444753C6B00796742A7BA1DDC5EAADE780783A7CBE174976E3DD6E94288E16F3B1BD0F71CECF94FD5493255431B6804AA4E624861"
				"4EA7965D2B8F0C0FC347114860A0E65DF06E38A4A4DF20378E17778ECDD046A79432592559231EAC31C8290FDD07B9372731BC2EDBBE95794053F897BBCAF364"),
			std::string("2E737AAEA3BEEC657FD48C12848D03E57D08652365AEE54B01BCB39CD2F545380B6E7BE0C8F14F01B09E77AF81F0AACE613A1F3B5A690B3D5D4D4D0944131EA8"
				"9DDE4F2DBF7771C8FF15A2CAFE4FCB34D26A7272C6FA5EA0506C076D0F0BEF7AADAB28A62FD28B682A94A8E93BA7324655EAA1FAC8982B69183ECD1DCF6E365C")
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			// kat tests
			std::string("EF08A1600FF77307C22A18A46BDC0BCC5B3EA82BA520A902C6ED9A7E7B936765"),	// rcs256s
			std::string("9257E21FC45EC728EC630659C88483E23666EE4CE35114C94C1F82B3AA401100"),	// rcsc256h256
			std::string("27E3BDDDB08F97C132D646D7AC5AFB96FDD0C714A6212A294D593552D442F97F"),	// rcsc256k256
			std::string("7BD5EFC3421F968259C2E81D8173DCB95B3085C809A53F7319F23588BF90170F"),	// rcsc256p256
			std::string("57049ECD1B6D11E6DA9C38160B05065D110B8961FF8ABDCACD9BFFB0EF207CDF"),	// rcsc512h512
			std::string("1FF03A20A6185BD94F6D4B4C013CA6756596BF66212523170D079031B43EBCF0"),	// rcsc512k512
			std::string("9CA92DD6F7147D06600915AD07F41321352E763FF96D51497DA10173CEE77EF1"),	// rcsc1024k1024
			// sequential tests
			// hbar256h256
			std::string("F71D600213DB1AE3C3429AD114D95810A151035D5914D1BD25DA8299978BAF480D2570B7F1CAA60562BF85B9AA5D75474301A131A0DDDB8237BA1BF97E90478B"),
			std::string("E217042BE48453B936E91D8264504E4D02B5ACF369EFEC78C55ADA38A0BD741B4B00742A0B6E343AD5F8DADEA5BF48C3139A443CD4119D94BEEEDF136CED88D1"),
			std::string("89063252DCBD0813E0037DACBBBDF53654AD9D8310288D77119727245416681D635550071A7AB54D9F041788388B712675EE894D6A460E2CE71E17D09EF410F7"),
			// hbar256k256
			std::string("B6CFC3290E56C6FC5DA72FDEC716149D217EC98753EC4EDB3E649101E78DA1C5E6B7ECEFBCABEC18AFCE6200DDDAC6230713D028654E6E271D96524B7C915F74"),
			std::string("4318F1C0D859A16653E1BF78DDF5E4906A87A6FE9B153DE6DA0901FF070A2072397F7FF636639D732EEBDE0815A0BFB2DFB323E80B84F54AA790183E5AE8FD0E"),
			std::string("701EE500E487943982B6752253D3881F3C82D95F8E724C159773ADBBAF52A5956CBF57449122797163CD22871CB8A2BD9614C8C376C2408CF4BF5D1DF6C7CFCF"),
			// hbar512h512
			std::string("0172A50DDAB27EE1F5178C44801E6AA69580076E0DCCDFE4DCB45E38B5DB6FB69379656FA8D69F1EA5EF452859BF76487E3786A044E24753D701594BCBF3DA8C"
				"23FE29F2F840F0C44FB3CF6E8825975E01E5E5D390B12BD575CF7541439E251F"),
			std::string("13317D3885062E7036C95D1CA9148BE82006F861B69F24B50C64DDDBF8644B51170CA90C567D150AB0D3588D2892D6962F6225DB97AC6C0D09405ECF38C467F7"
				"98DC34773F8B96DAF443A26BC02CFA8AE0A0852C86441402C26C23B7162CEC5A"),
			std::string("456DD965D9DF88E237956992FEA0E2FE3D12E6292D0AFFE83958D5DA2CE068E1A609C3EA737609753A9A05DB2803D0692387AC176308B3A6DED9ADD2F45891A5"
				"3A8E2C422BE36F5FDAE7E0483547D0A5BD8457CA37FB987D34A02A27242DD109"),
			// hbar512k512
			std::string("20205A447BDC7513C9A92567E2367E9B2DD8E8972CB255686A3FB1D570ACCB202FD683DAEA3AD7575655984E462E517F122E5DEE854EFBB04F9898F69864D268"
				"8D009EB766D47015933E42D75EAA7DAC737517F5BD3BE6FFA2A71BD82EEB6777"),
			std::string("EA573B957BB61316FA4AB57BEE9DA91010BA356C530E4FA6908642672CA1A1885E2F6278928832350221CFD7BD9EFC72C653340AD5B771840664EA4BB5E65F2C"
				"202A904F036E8B6BC505490F51B7FEC862BD1C90C6ADFA0C7C80A2D4ED4F4B66"),
			std::string("541A56C82F3FF6F6C7C7EB0886F0E97AB3322E5F2C075CE32BCAFEBCF9F27C54D85730181185A6BF8EE1B4428BCCD8527066D6FAEF3DBCFAE50410901B9FADD9"
				"3A8648F2EC1D8E35952FF88368F7273D6F3BBEDE07FBD3AF4F9F0D56CF39B35E"),
			// hbar1024k1024
			std::string("95429D8B0B3CE7437F0089C1EC9BA62D3A35C562D82AA7BB1D8C938300B5B00400BFEEEF5B49C174792E0D88D599CB3BC6AB9080D6CC2352797124AF4EF22E8F"
				"42BBD4075E4C26CA08B8AD0D7BA34C8DC8AE6E0B5E2A60C3E7DEA13C0ABA9C631FF88468D44D4D0747EDE0A1FD3B769EF79BFD7A5C116CB23B6A9E74015C79F5"
				"EC3D65DBC7A6430394C533EDED2D6B12B2D358444E0911B00EE6A417D9C16D8F"),
			std::string("9CA17CA9F7E8379FA6179B35EEF1DD96A0FDFBFAAB3392A99FA217272336C1551D0CDCC73BAC502FF3E933A8F5E5690731A7D868EE38DF984F0957FEB032D67D"
				"AA50F2DE39B9C53E890AABECF5986B770D85F3BDE985A2916BE9C2E1621E09028C678494F64850100120E95927F9A71C9C9A75AB73456046BAE636AEF10EBF59"
				"38AB1846E2A3765E772C7C2F6CE0134C22912A6EFF629E23FE481E78C9642933"),
			std::string("B44426DBA019542FA80260E37A52C84AD3B22DE0080C96435B7636A28AE3486628966A50A417C7BB7C7FFAAC9DDE4DF8DF18F4DDC378BBED8882EC7360EBC7D5"
				"BD4515219CB388798430995B7CB17B85C31F5F69F7F7035854825AF24A364945EEBE0E092836AABDC5ABDC05A50E9D0C1F7DB0116B77B44281A60DDABABD398B"
				"B5FFC92BB888EB1274178E5E50F871EEEC4E787CE5176080669789AC93DA830A")
		};
		HexConverter::Decode(expected, 22, m_expected);

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
		};
		HexConverter::Decode(message, 1, m_message);

		const std::vector<std::string> monte =
		{
			std::string("59279D54A9BD57DDA857BEA4F8D6BD1358E7CB23BFF8B00DC13E2B0D8D01596F")
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
