#include "RCSTest.h"
#if defined(__AVX__)
#	include "../CEX/ACS.h"
#endif
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/RCS.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
#if defined(__AVX__)
	using Cipher::Stream::ACS;
#endif

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
	const std::string RCSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the RCS stream cipher.";
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

#if defined(__AVX__)
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
#endif

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
		CpuDetect dtc;

		return dtc.AESNI() && dtc.AVX();
	}

	void RCSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// rcsc256h256
			std::string("DF0BFD53571AB0564110A3D8FFDEAF6D0683199CF86D45259EF47B52B2C68672"),
			std::string("B71B30872C01A391C91D4438BF37DAD6D9722BBBA8B7AB4DA0112DB557F6DD73"),
			// rcsc256k256
			std::string("F1FD64701BCE32F82D3B5569A534F6CFF95258FEAD82A65F2ADA0910031C62D6"),
			std::string("16633571A977CED3C1841AD5A3ECF60C80B57CD3304C4CE4D0DA989AAA8121C1"),
			// rcsc256p256
			std::string("FA35F90B7030A502A14436E0444E4400"),
			std::string("691A6E85162E785E7DB4CD943AFAA8C6"),
			// rcsc512h512
			std::string("160506C9F88FF57CE1365738196C80A5962F820D6D2141FE9892B01212898F2E270B9B53EFCB38C6773CC5D43075C6733879645E21E174E930F97880224A4686"),
			std::string("2463D0053DC94790E4F84694EA24A0597EE3C6965AFEE49DA7B27807858D0BA58333000D83B34343B278745393F029B87ACF10BFCCE7BDA000B311B9CA858BCE"),
			// rcsc512k512
			std::string("A64CF7C9EB60B6FF83AB8EEC38A8C3F92218A7953D6045145EC7830BF6997421A30575471005D2F2F7FD84836B2BB62D3F63E8843AA35C53CF12373F72572E47"),
			std::string("106A50F57B4FB1E322024A3F099C9937D352E5B15940E1EA9BDC4280E7B1FCCCF8F7761F00F4D2F9E5C5E388412F0CB6A68F32AEDBD79520FEB28850D1D9AE63"),
			// rcs1024k1024
			std::string("3B006A067741DD16DC7337374D1C6653380B343C16FE5529B944BE271449A8FA84D67348323E61249CC6DEC660196DDBE09E8D91F54681E8F3BF8A09D5362011"
				"CE9B952A31FA0FA2969223CABB384DE7CEB76667B6458C8AC49974CC4325995928A8C0C884D9C10320430B9B616D993F1FF2DFB773F2AED81ED0659CBFD89614"),
			std::string("ED220E960D9A19735F35B48972EAFE2B410290DA484EF4F943C83B3FB4062B19522B341B21596375F1C828EA82CF6ECC67B91A9D1F847669C2C79CACF8EF78E9"
				"51D9DCD43DE038B06F30E56DB48871E0616D17E0E2E385EF615493506D4911B21EDB6B0FD7539CC6801CC5A2EAA4870B9E1519C9852A94507C38813E793CBFBC")
		};
		HexConverter::Decode(code, 12, m_code);

		const std::vector<std::string> expected =
		{
			std::string("0DE21919E46F7DE3647F752FA55348431139D3516BD0475D00ED68E7FA5FD398"),	// rcs256s
			std::string("30741D2E6B27B2E0A261C4E47CCF392951BB1B7615AC0B5DE0F7A3CF62DE50B8"),	// rcsc256h256
			std::string("62EB90A490C1D5B470BB0FED3268E9BE04C65EC5A7734BAD2A0B7F5EE10DDE20"),	// rcsc256k256
			std::string("C1E223EFCDD8ADED366C90A9386C0E551D11BD17B4BE3993034AE1A66F35E049"),	// rcsc256p256
			std::string("C49411697FA6573841070CA29C25D2F53507F13F9BB46D2B2A0D97398B087267"),	// rcsc512h512
			std::string("4C687BF798DF0518A68DD5386633925125CA7BCF982DADD10D096DD22504DE45"),	// rcsc512k512
			std::string("1CF7F968A58CC3DFAB9C12EE8FEA068F4082247D291C4839508514B950A4195F")		// rcsc1024k1024
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
			std::string("1A3248E5F78C1D44E8CC010F059DA4E16156EB5BD9C5393BD579DF59589D24AF")
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
