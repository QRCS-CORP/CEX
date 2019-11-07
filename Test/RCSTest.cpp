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
		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
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
			std::string("561825714E22F6B507A26CEC06A37133CC79708A9A41CB48EF00298AE145C8F1"),
			std::string("FFCB284536959D891CA2A8F5BF2E593CE9E44C0759B91DD0AE572EBB8E117C34"),
			// rcsc256k256
			std::string("F00501356BFE37D737C96C689AA191576EDC984049B107B898E28318FF64A757"),
			std::string("333B7C16B8AF5F0CC2D5BEEB1E5177D54A39900C81AFD4E0AD220C1490883224"),
			// rcsc256p256
			std::string("27CB6860D2E7ECB30B090E9B049FC665"),
			std::string("F9AEEAAC05C04B659AEF5CFA202C0780"),
			// rcsc512h512
			std::string("A2DEEA637DC3EB021CC32D6B6B33B7FABD38ACAF89A2701CE157DB5959BF0B8AA054630F6EA00594D419A996CCCA1754AC9A87AD75DC028D0FC357FEA6821CF7"),
			std::string("2EA348E061DDBA93CB0352E6EA4089D6E063342DD584D30A3A5DCDC4CAC3D318BD03FAFC0D3E0B4205E716C70905409D4B09943ACEB9616BBE4064956900AC2C"),
			// rcsc512k512
			std::string("ED546436FF04B913515CD9B06B0DF021896204488F98AEAA8B0A327E195ECFFC403FF01E39623B6AA4A11096E1A820054BD5872E164C8BA4B88142CB74E0076D"),
			std::string("9B78DCE6E831A50DDC6B3671DAE0841F2161C3762F454118549BF8B8400B98F509893B0D3EFAAD29328B0DC3E118AE832DEE0601886A0478402CD98764EE62C1"),
			// rcs1024k1024
			std::string("9ED6938DA37418A861189DB36AC25738FF569DD34AF2900DA501E24170E02CE7A0EF66CF186F130FCF30D669700A055CC9B73B4C871DF53AE7B4057A8A5680B6"
				"65E7115D032E60DA9A35D9364A25409FCDAC32D539B91880430479FC91EB789FD05027C98C8BC5DAD03F2482146D8321691C1E613BD036920EC6422C5F378FAB"),
			std::string("90940CC5BB407DFF9C50E1D2F2065E0AC6022CE6DF753F17977FCBF26AC378F26E040A0AA255C552AE427490C883BB6ADED8583900EDFD8B1BA4D2D590A53BDB"
				"8444D41DEB4132D72718ED7ED6142F5E244EE0A2FFB20756B3BF011F11757D8E05899E9EE02C98D864A1DD3D767906846C92873C674B0ED0414C7AADA5BD6D1A")
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("A0E750C82CC3CC45A253D8013B3235F69B499F6C0098D2D1B1FF17C25C89A70F"),	// rcs256s
			std::string("1829CB0E4B9DD6B985C099E28B5E1074586D4F14FAA8E1EDA32F047CBDC58086"),	// rcsc256h256
			std::string("0A62E14EFEF56C3FFE2570C78EB502046E2F3BE5E60CEA67FA8BD8316B898099"),	// rcsc256k256
			std::string("A1C51A7279E94C164D96902E9C71E2F883DF25358A85A1F09105104FB47299F7"),	// rcsc256p256
			std::string("BFDDD46D4D6EB9DFB5E1FD4B57D091CE65521DFC3419CC362CDE840875BB7325"),	// rcsc512h512
			std::string("5066AF59A10EEF7BE271E2BA1B346EE370C8E88C67CF3F62997CCE4804585EB4"),	// rcsc512k512
			std::string("919E38CB0329A7784B3277017FD86FB97AEAE24B995E91B0EA244E68AEBE82BB")		// rcsc1024k1024
		};
		HexConverter::Decode(expected, 7, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
		};
		HexConverter::Decode(message, 1, m_message);

		const std::vector<std::string> monte =
		{
			std::string("7324D28336C5C8F71FA4287DB0373687E580E9D8490F0B073BB40FE72F568F8C")
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
