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

		// use constant time IntegerTools::Compare to verify
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
		const size_t MINSMP = Cipher->ParallelBlockSize();
		const size_t MAXSMP = Cipher->ParallelBlockSize() * 4;
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
			std::string("1D40A5B9BF4CCA23A8DCA7168CF4BD4277EA702E32FF3FAD004C93AA56EF6261"),
			std::string("555614FE3331D4DFC3F4EC7BD1394AF774C79263EF6D7977F4F5370251FB79C4"),
			// rcsc256k256
			std::string("231FEB02DE792F037DD6C2255E4240BA59176E4ECD560D7F372F001B5CF48287"),
			std::string("3F00657BE24E71D829D9B9C1E5908DA8B69965AD9C0355FF7B767B33A87128CA"),
			// rcsc256p256
			std::string("D78EE06F0F6D3D630F89E781DA72B273"),
			std::string("BEBB0546E2C91A9C91769D7D0803A316"),
			// rcsc512h512
			std::string("FA4C4C575A3A8A570195CD94B88B3902616ACFC826FC8FF585E35C1C3B3FFC493A3214D3BE55875AA8B1D99025F6EC68D1E7188DBD5533EF9753031E6738F174"),
			std::string("F76EC279A34983248FFAA824CB39BCDC9F49C7F84FFFEA4B6D14CF3ABFA506E104F78A0A6DD5B24451121B2CA65425399537EFE56D3033169DD2494C77AE16AE"),
			// rcsc512k512
			std::string("B547C684989EE28177E8985EA828B4C192CEB77EC932934D2E30F39F28EA62FDC704ACE875F891F953FE35018B3E724506265F1F7DD8AB4033D2A0680DA1993E"),
			std::string("84918AAE074AE4288D7640DCBAF8838EF162A90E24422CC9FE9D51090D9FA3BDDE4FEB35016D3D589E8D9A96243D23FCFF714970D7B61797EB2F8C75F300FB3E"),
			// rcs1024k1024
			std::string("B21264DC5D55B0880E70158A488689B1F323BBC07171EFCE8E2656E1BE5E2013C37A2750DAACCC497626B46131321E76DFBFB83072C98DEA28F6AD7FCCE1D810"
				"A0F3DAD7DB3BCD2729D749193A30FE3F94D2E423BA8EDA814EF2D8CF508FB9EEA2E14B7C3772A9FA4DBE7EEE7139E8493D28241152085EC6C8E2F12FD10E2082"),
			std::string("2D17026CF307EB60FFBAFF5663BAF1E90E98C9939308BC88A59D78568035AEEE0104E966D8C694E1924050C3370F472ECB2D3274BCCFE9D28DFB49F7F4BC9977"
				"779C8F2FF07968183127C6761043EF09BC3EB23D5EC9742A9AEDE18653C5054848EE7EEEA254892DF33C9D13083482FA018AD5516B87AD9AFC04B7DC48FCEF97")
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("CC89C77F3A7B0C2A926BC868D7CD680C6C2B1C5FB1975CF32655DB032F232B26"),	// rcs256s
			std::string("57A352F74A695B05A388F4B1160E6000DCA007DAD89BC8A3DC13897917113539"),	// rcsc256h256
			std::string("9F242A4AA69A66ACF89FD3ECBDA751BE2A7AC67C558025C59F493C6E142F0AE9"),	// rcsc256k256
			std::string("3C9B482572A2DCCEF94BEB15FD1753DE51D8A588CA4DF018E68891FC724C13F9"),	// rcsc256p256
			std::string("39C25E6E1E651847CA1771457302B1C131555A9107C890F82897B4A53A3E7549"),	// rcsc512h512
			std::string("375D351BB811FB2801D21D74D629438ED9C460BD0CC0497797C38A8BD25325E2"),	// rcsc512k512
			std::string("1DAD1838BA6CEFBA9098E9E957E2BD6B007CB158B2F9AD7817F9DF57C950D4BD")		// rcsc1024k1024
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
			std::string("F55BC2A2085E494466158E4285A53FB57F73EFC323CAF2FC6E9742616DB12303")
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
