#include "RCSTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/RCS.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
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
	const std::string RCSTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the 256-bit-wide Rijndael (RCS) authenticated stream cipher.";
	const std::string RCSTest::SUCCESS = "SUCCESS! All RCS tests have executed succesfully.";

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
			OnProgress(std::string("RCSTest: Passed RCS-256/512 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("RCSTest: Passed RCS-256/512 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0], m_code[1]);
			Finalization(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2], m_code[3]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(rcss, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(rcss, m_message[1], m_key[1], m_nonce[0], m_expected[1]);
			Kat(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 known answer cipher tests.."));

			Sequential(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[4], m_expected[5], m_expected[6]);
			Sequential(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[7], m_expected[8], m_expected[9]);
			OnProgress(std::string("RCSTest: Passed RCS sequential transformation calls test.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(rcss, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(rcss);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 parallel to sequential equivalence test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("RCSTest: Passed RCS state serialization test.."));

			// looping test of successful decryption with random keys and input
			Stress(rcss);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(rcsa, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[0]);
			Verification(rcsa, m_message[1], m_key[1], m_nonce[0], m_expected[3], m_code[2]);
			OnProgress(std::string("RCSTest: Passed RCS-256/512 known answer authentication tests.."));

			delete rcss;
			delete rcsa;

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

	void RCSTest::Exception()
	{
		// test serialized loading with invalid state
		try
		{
			SecureVector<uint8_t> sta(100);
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
			RCS cpr(false);
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
			RCS cpr(false);
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
			RCS cpr(false);
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

	void RCSTest::Finalization(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &MacCode1, std::vector<uint8_t> &MacCode2)
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

	void RCSTest::Kat(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
	{
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

	void RCSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected)
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

	void RCSTest::Parallel(IStreamCipher* Cipher)
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

	void RCSTest::Sequential(IStreamCipher* Cipher, const std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce,
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

	void RCSTest::Serialization()
	{
		const size_t TAGLEN = 32;
		const size_t MSGLEN = 137;
		RCS cpr1(true);
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
		RCS cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<uint8_t> sta2 = cpr1.Serialize();
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

	void RCSTest::Verification(IStreamCipher* Cipher, std::vector<uint8_t> &Message, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce, std::vector<uint8_t> &Expected, std::vector<uint8_t> &Mac)
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
		};
		HexConverter::Decode(code, 4, m_code);

		const std::vector<std::string> expected =
		{
			// kat tests
			// rcs256s
			std::string("9EF7D04279C5277366D2DDD3FBB47F0DFCB3994D6F43D7F3A782778838C56DB3"),
			// rcs512s
			std::string("8643251F3880261010BF195886C0496CC2EB07BB68D9F13BCBD266890467F47F57FA98C08031903D6539AC94B4F17E3A45A741159FF929B0540436FFE7A77E01"),
			// rcsc256k256
			std::string("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03F38582F301390A6B8807C75914CE0CF410051D73CAE97D1D295CB0420146E179"),
			// rcsc512k512
			std::string("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
				"C40E0D50727DC9528664F656270E99A4857D7A2C28F965EB9956658145AC9868F3FDE25C39EC9EEF0C6A7ED955CB3C2F44286CD253C9BE0CF3F389313C47E4B2"),
			// sequential tests
			// hbar256k256
			std::string("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03F38582F301390A6B8807C75914CE0CF410051D73CAE97D1D295CB0420146E179"),
			std::string("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC05BB0DC047DB2ADA2A39BEB441FCD4C5F83F1142F264EEFCBAAA51D7874A0E7DA0A7B285DFD55AA"),
			std::string("A4F915090E2BE9BB71C93B2847935751E3D9B2A746365462CA26116B661FC0BCF1DCCAE7528D03D07D603B69772C7BA5BA4A45452FB1816EF805BDA40A8BA374"),
			// hbar512k512
			std::string("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
				"C40E0D50727DC9528664F656270E99A4857D7A2C28F965EB9956658145AC9868F3FDE25C39EC9EEF0C6A7ED955CB3C2F44286CD253C9BE0CF3F389313C47E4B2"),
			std::string("388270BF8DF03483BB287FFA527D81403F0362210FD525657C8541250DFFE3BAD1285FAB37A6821DA524F3F7FF7EFCB39C5B59E3897B177E45D6AA7F4BB5BE77"
				"9CB2429F4693DF70D38DBBCB00EE86172435C117D442171A8485A87BF1D7282F2D69032C85F1CD1A1FEE794843E0CED7616722A4B0937210E9023220B085EA18"),
			std::string("80DE0F8E40DB5DCDBE6F844F523C4FDE4AB9681DF7721382AF98A219BC78688A97C0CCCD359F4A21EE875B5D6842CE58AE30512847650223934666175F3F62E4"
				"B39346C6079ECEBCC17D9AB91A1150E10114A0F807E226F2D6023DB626CD730BEF40089DF13A98FFEFE2B7B8CCE4803DA6816FA368EC0F7E0F0C252492447D2D"),
		};
		HexConverter::Decode(expected, 10, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
		};
		HexConverter::Decode(key, 2, m_key);

		const std::vector<std::string> message =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"),
		};
		HexConverter::Decode(message, 2, m_message);

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
