#include "ACSTest.h"
#include "../CEX/ACS.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Cipher::Stream::ACS;
	using Enumeration::BlockCiphers;
	using Enumeration::BlockCipherExtensions;
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string ACSTest::CLASSNAME = "ACSTest";
	const std::string ACSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ACS stream cipher.";
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
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
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
			Kat(acs256s, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
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
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void ACSTest::Authentication(IStreamCipher* Cipher)
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

	void ACSTest::Exception(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key and nonce input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE1"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE2"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE3"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE4"));
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

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -TE6"));
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

	void ACSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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

	void ACSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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

	void ACSTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
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

			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(inp, 0, MSGLEN, rnd);
			IntegerTools::Fill(nonce, 0, nonce.size(), rnd);
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

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ACSTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());

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

	void ACSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
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

	void ACSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// acsc256h256
			std::string("419DD01A2B46B47E900B9075A2DC0E2FB3E5C4818FB3B5ED8614040D5CEE4612"),
			std::string("43EEF62EBE4B55941596994FE1D24BAD17747C2DF2355458446CC44B3E27F127"),
			// acsc256k256
			std::string("60F099F4BF537BC8DCE28177F0D15AF54F1C725FE363AB6D8EC7AE832E19CE90"),
			std::string("B08354C7D743FC456102E4F5344A1B8D6FED2483E9F4EFC9D33A8F67F6371E43"),
			// acsc512h512
			std::string("5B6097C8C0CCC4319F6CBCE75D7794A34F3B6C11727DB8B3A3A1BB333F3DF69FAC6C5756B76AF423C2FC57986EFAE1E96E6E6BDC0A474C0623E5301854A498FC"),
			std::string("71A48B4725789EBA99F108B0C441A589C8598522323A852B0A38C3AF3D4011C65F2E9BC6D52AA7B88BF0A944F25A2E7BDEC28BCFDC9801BFFF6ED1CB3B926CA2"),
			// acsc512k512
			std::string("3CCD0B027D413E845B4CADA7AED6DFF0380A452058B6BAECF25FD02539D8EAE5E4392D050048D15E36E952A8D1258465BD778EFF3236F40D92C7221E17279F93"),
			std::string("F70829E1203939F468372D8DE646F7EEDFEE64F8F5D2FF8B8DA89BCE9DCAA89AD91C86734BCDFE5980241670B49B373A121B2FD52A0D35854E150874F01F3EC3"),
			// acs1024k1024
			std::string("3D1D9C67834EEFB3A251EF0A4255FA94D436DA7C19EEB17FC9201975CA2B83A2E6F90C36BD6DEB44AB15B81C08E91F521BCC9632EE818AC63057C5474A7759CA9B6579C7E5C200218A021130EB3DAB7B88B9A5BF6D043CD458FF4C4F72DEAC3FD46175B1853466E10DCCC8384CBDDC0A844EA61643CC7696D451B5F0CF2BCEE0"),
			std::string("D10FDD21A5EE05737122E2B091B1F027201552DB9228FA23CC7B3C077CDC07683E6F1EECB17BD66DD48ABCCEFFE4A4EB0B0D17852C0B7978A1BAF7DA43635F72B23F908E3B77E42E54DAB4A04C9300932E3C65D3BA86E1CD6C52B662189031A964D24F1B02AFD02DF24766F97C5485AB43D6AC05FAC5FAF30E13704F365DC449")
		};
		HexConverter::Decode(code, 10, m_code);

		const std::vector<std::string> expected =
		{
			std::string("79E593AFE194798C43EBEF261FDC19D2"),	// acs256s
			std::string("2B33110914AEBB6B35C3A55FFAD644C6"),	// acsc256h256
			std::string("F2053066513DDBBD456DCED376E6A5AE"),	// acsc256k256
			std::string("119C95A3C72D8405114547B15328F43A"),	// acsc512h512
			std::string("EEA6CA8615E8348A04C0C452AD2DF070"),	// acsc512k512
			std::string("53E84815D2D617FE8FB665545E99BEE0")		// acsc1024k1024
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
			std::string("FD1B76949451423857666E133C372565")
		};
		HexConverter::Decode(monte, 1, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		/*lint -restore */
	}

	void ACSTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
