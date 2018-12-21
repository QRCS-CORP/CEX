#include "ACSTest.h"
#include "../CEX/ACS.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Cipher::Symmetric::Stream::ACS;
	using Enumeration::BlockCiphers;
	using Enumeration::BlockCipherExtensions;
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntUtils;
	using Utility::MemUtils;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;

	const std::string ACSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ACS stream cipher.";
	const std::string ACSTest::FAILURE = "ACSTest: Test Failure!";
	const std::string ACSTest::SUCCESS = "SUCCESS! All ACS tests have executed succesfully.";

	//~~~Constructor~~~//

	ACSTest::ACSTest()
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

	ACSTest::~ACSTest()
	{
		IntUtils::ClearVector(m_code);
		IntUtils::ClearVector(m_expected);
		IntUtils::ClearVector(m_key);
		IntUtils::ClearVector(m_message);
		IntUtils::ClearVector(m_monte);
		IntUtils::ClearVector(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string ACSTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ACSTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string ACSTest::Run()
	{ 
		try
		{
			// acs standard and authenticated variants
			ACS* acs256s = new ACS(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, StreamAuthenticators::None);
			ACS* acsc256h256 = new ACS(BlockCiphers::AHX, BlockCipherExtensions::HKDF256, StreamAuthenticators::HMACSHA256);
			ACS* acsc256k256 = new ACS(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, StreamAuthenticators::KMAC256);
			ACS* acsc512h512 = new ACS(BlockCiphers::AHX, BlockCipherExtensions::HKDF512, StreamAuthenticators::HMACSHA512);
			ACS* acsc512k512 = new ACS(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512, StreamAuthenticators::KMAC512);
			ACS* acsc1024k1024 = new ACS(BlockCiphers::AHX, BlockCipherExtensions::SHAKE1024, StreamAuthenticators::KMAC1024);

			// stress test authentication and verification using random input and keys
			Authentication(acsc256k256);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception(acs256s);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0], m_code[1]);
			Finalization(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2], m_code[3]);
			Finalization(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[3], m_code[4], m_code[5]);
			Finalization(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6], m_code[7]);
			Finalization(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[5], m_code[8], m_code[9]);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(acs256s, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1]);
			Kat(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[3]);
			Kat(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[4]);
			Kat(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[5]);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 known answer cipher tests.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(acs256s, m_message[0], m_key[0], m_nonce[0], m_monte[0]);
			MonteCarlo(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_monte[1]);
			MonteCarlo(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_monte[2]);
			MonteCarlo(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_monte[3]);
			MonteCarlo(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_monte[4]);
			MonteCarlo(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_monte[5]);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(acs256s);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(acs256s);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(acsc256h256, m_message[0], m_key[0], m_nonce[0], m_expected[1], m_code[0]);
			Verification(acsc256k256, m_message[0], m_key[0], m_nonce[0], m_expected[2], m_code[2]);
			Verification(acsc512h512, m_message[0], m_key[1], m_nonce[0], m_expected[3], m_code[4]);
			Verification(acsc512k512, m_message[0], m_key[1], m_nonce[0], m_expected[4], m_code[6]);
			Verification(acsc1024k1024, m_message[0], m_key[2], m_nonce[0], m_expected[5], m_code[8]);
			OnProgress(std::string("ACSTest: Passed ACS-256/512/1024 known answer authentication tests.."));

			delete acs256s;
			delete acsc256h256;
			delete acsc256k256;
			delete acsc512h512;
			delete acsc512k512;
			delete acsc1024k1024;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + ex.Origin(), ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" Unknown Error")));
		}
	}

	void ACSTest::Authentication(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t TAGLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> code(TAGLEN);
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

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// write mac to output stream
			Cipher->Finalize(cpt, MSGLEN, TAGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
			// write mac to temp array
			Cipher->Finalize(code, 0, TAGLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(code, 0, cpt, MSGLEN, TAGLEN))
			{
				throw TestException(std::string("Authentication: MAC output is not equal! -TA1"));
			}

			if (!IntUtils::Compare(inp, 0, otp, 0, MSGLEN))
			{
				throw TestException(std::string("Authentication: ciphertext output output is not equal! -TA2"));
			}
		}
	}

	void ACSTest::Exception(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key and nonce input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE1"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// no nonce
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE2"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// illegally sized nonce
		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(1);
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE3"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// illegaly sized info
		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			std::vector<byte> info(ks.InfoSize() + 1);
			SymmetricKey kp(key, nonce, info);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE4"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid finalizer call
		try
		{
			// not initialized
			std::vector<byte> code(16);

			Cipher->Finalize(code, 0, 16);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE5"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid parallel options
		try
		{
			std::vector<byte> key(ks.KeySize());
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);
			Cipher->ParallelMaxDegree(9999);

			throw TestException(std::string("ACS"), std::string("Exception: Exception handling failure! -TE6"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ACSTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> code1(TAGLEN);
		std::vector<byte> code2(TAGLEN);
		std::vector<byte> cpt((MSGLEN + TAGLEN) * 2);
		std::vector<byte> otp(MSGLEN * 2);
		SymmetricKey kp(Key, Nonce);

		// encrypt msg 1
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN); //21,222
		Cipher->Finalize(cpt, MSGLEN, TAGLEN);

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);
		Cipher->Finalize(cpt, (MSGLEN * 2) + TAGLEN, TAGLEN);

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
		Cipher->Finalize(code1, 0, TAGLEN);

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);
		Cipher->Finalize(code2, 0, TAGLEN);

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(code1, 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF1"));
		}
		if (!IntUtils::Compare(code2, 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF2"));
		}
		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -TF3"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -TF4"));
		}
	}

	void ACSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(MSGLEN);
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
			throw TestException(std::string("Kat: Decrypted output does not match the input! -TV1"));
		}
		if (cpt != Expected)
		{
			throw TestException(std::string("Kat: Output does not match the known answer! -TV2"));
		}
	}

	void ACSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Key::Symmetric::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo: Encrypted output does not match the expected! -TM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo: Decrypted output does not match the input! -TM2"));
		}
	}

	void ACSTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		Prng::SecureRandom rnd;
		size_t prlSize = Cipher->ParallelProfile().ParallelBlockSize();

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

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			Cipher->ParallelProfile().ParallelBlockSize() = Cipher->ParallelProfile().ParallelMinimumSize();

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
				throw TestException(std::string("Parallel: Cipher output is not equal! -TP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel: Cipher output is not equal! -TP2"));
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ACSTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());

		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

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

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, MSGLEN, rnd);
			IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress: Transformation output is not equal! -TS1"));
			}
		}
	}

	void ACSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
	{
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> code(TAGLEN);
		std::vector<byte> cpt(MSGLEN + TAGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);
		Cipher->Finalize(cpt, MSGLEN, TAGLEN);

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);
		Cipher->Finalize(code, 0, TAGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Verification: Decrypted output does not match the input! -TV1"));
		}

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -TV2"));
		}

		if (!IntUtils::Compare(code, 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -TV3"));
		}
	}

	//~~~Private Functions~~~//

	void ACSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// acsc256h256
			std::string("27143AD8CD957339CF15AE359A33E343E1E83EA29079EC976D6986CFC5572B4A"),
			std::string("BACDAAA6DF63B47DD66F109254EBDDD36A939B583D4B16988ABF6B4138F0AF6E"),
			// acsc256k256
			std::string("7E199833C9BA567A1D4B071B4CC385AA8F33F4E459075D5B25486642925FFA32"),
			std::string("2497EE63511C472F0D14B0B474BEA89A0D88051031B334EB8EF777A841742647"),
			// acsc512h512
			std::string("3F4ECA6B6485CA0E164A7C856DAB8DD01C623C548A9AD993501E0C6F3CCB424FAB364264BD8D9AB53328964B8A44269E7D18982F99169C78B87FB4CD7C789D5B"),
			std::string("E340D2E649D3545E98A793D9B253C3D2C3598036B72BDD4A3244BC348B4FD4B60F17F185C4E66C727DB1A27BFE598343FD5190BA942DB7A96B203F4DDB4D7F93"),
			// acsc512k512
			std::string("99A71F9C92FAB580B02C7EE1AC23AB9C5716902D03FB25BA52BC7745D74B95C7881139E3AEF3BDC0FC60843D2CAF55160071EEBAA72268205BF3C086B9DB7368"),
			std::string("FEF85738A72D34A04B44544B4B05315E0D70D1E6559077A8AC4BF4DB7D8CC062237CD87C9189F18452A943E4A49528A4C0B57DB5271B4B540A8D46E4AB10C7CC"),
			// acs1024k1024
			std::string("CD9189A961A2FC4EE37772D8AB881357F7AF0EE2579E1B8426C3D89B43928747544B23FD68C87B96B778F3397AF03CF9E887799E19DA627FB76C24F433895B2D2114ED8370D4EABFF04FF50C631285BCCBFE708785D97EF97B82A6A8B6702063B94B52B3666F5FB45A00205F7401E10E3A07071BB9DD7ADE6B0A965A2BF082B1"),
			std::string("B596D47B6FADA088B309F0469CBAD1A57B6F399C879B025D0E591B81C666FF3DC6D2D80E70119941AC7F4312E4054CBD3F68274164AFD0F1B71DC548352AF19513C1681D3058CC2276971C2FCE35B165FE5C89127A1BB084B519698572C0A2696CE1883556E63CD67FD18D91D7CCD48BC0B8901297C96941DB01185367A02C7C")
		};
		HexConverter::Decode(code, 10, m_code);

		const std::vector<std::string> expected =
		{
			std::string("79E593AFE194798C43EBEF261FDC19D2"),	// acs256s
			std::string("91D00FE4B4A2A717EFDCEEDC4F7B310C"),	// acsc256h256
			std::string("7F97A702908E1EF4B9146DCF17D443B3"),	// acsc256k256
			std::string("1337B5319E0DC0FB86B9FA6B07DC1FA9"),	// acsc512h512
			std::string("78B9CD13545D2CB7DB4AAB8E85BE62A6"),	// acsc512k512
			std::string("7841CDE374987003B91BF82505B35DEA")		// acsc1024k1024
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::vector<std::string> message =
		{
			std::string("000102030405060708090A0B0C0D0E0F"),
		};
		HexConverter::Decode(message, 1, m_message);

		const std::vector<std::string> monte =
		{
			std::string("FD1B76949451423857666E133C372565"),	// acs256s
			std::string("C3D72062E1EE417B14D6F4965F683C3F"),	// acsc256h256
			std::string("A0D8565A55EAC983B5468F13A03981C0"),	// acsc256k256
			std::string("F143F8AE673D233356420C66015D80E0"),	// acsc512h512
			std::string("FD0E7F68742D9550F8164562B4F0DF56"),	// acsc512k512
			std::string("37B35F87BB85DA00293A73537BD5EF56")		// acsc1024k1024
		};
		HexConverter::Decode(monte, 6, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		/*lint -restore */
	}

	void ACSTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
