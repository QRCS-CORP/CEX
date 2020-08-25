#include "MCSTest.h"
#include "../CEX/MCS.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Cipher::Stream::MCS;
	using Enumeration::BlockCiphers;
	using Enumeration::BlockCipherExtensions;
	using Exception::CryptoSymmetricException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Enumeration::StreamCipherConvert;
	using Enumeration::StreamCiphers;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string MCSTest::CLASSNAME = "MCS Test";
	const std::string MCSTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the MCS stream cipher.";
	const std::string MCSTest::SUCCESS = "SUCCESS! All MCS tests have executed succesfully.";

	//~~~Constructor~~~//

	MCSTest::MCSTest()
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

	MCSTest::~MCSTest()
	{
		IntegerTools::Clear(m_code);
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string MCSTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &MCSTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string MCSTest::Run()
	{
		try
		{
			// acs standard and authenticated variants
			MCS* acs256s = new MCS(BlockCiphers::AES, StreamAuthenticators::None);
			MCS* acsc256h256 = new MCS(BlockCiphers::RHXH256, StreamAuthenticators::HMACSHA256);
			MCS* acsc256k256 = new MCS(BlockCiphers::RHXS256, StreamAuthenticators::KMAC256);
			MCS* acsc512h512 = new MCS(BlockCiphers::RHXH512, StreamAuthenticators::HMACSHA512);
			MCS* acsc512k512 = new MCS(BlockCiphers::RHXS512, StreamAuthenticators::KMAC512);
			MCS* acsc1024k1024 = new MCS(BlockCiphers::RHXS1024, StreamAuthenticators::KMAC1024);

			// stress test authentication and verification using random input and keys
			Authentication(acsc256k256);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 MAC authentication tests.."));

			// test all exception handlers for correct operation
			Exception();
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 exception handling tests.."));

			// test 2 succesive finalization calls against mac output and expected ciphertext
			Finalization(acsc256h256, m_message, m_key[0], m_nonce, m_expected[1], m_code[0], m_code[1]);
			Finalization(acsc256k256, m_message, m_key[0], m_nonce, m_expected[2], m_code[2], m_code[3]);
			Finalization(acsc512h512, m_message, m_key[1], m_nonce, m_expected[3], m_code[4], m_code[5]);
			Finalization(acsc512k512, m_message, m_key[1], m_nonce, m_expected[4], m_code[6], m_code[7]);
			Finalization(acsc1024k1024, m_message, m_key[2], m_nonce, m_expected[5], m_code[8], m_code[9]);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 known answer finalization tests."));

			// original known answer test vectors generated with this implementation
			Kat(acs256s, m_message, m_key[0], m_nonce, m_expected[0]);
			Kat(acsc256h256, m_message, m_key[0], m_nonce, m_expected[1]);
			Kat(acsc256k256, m_message, m_key[0], m_nonce, m_expected[2]);
			Kat(acsc512h512, m_message, m_key[1], m_nonce, m_expected[3]);
			Kat(acsc512k512, m_message, m_key[1], m_nonce, m_expected[4]);
			Kat(acsc1024k1024, m_message, m_key[2], m_nonce, m_expected[5]);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 known answer cipher tests.."));

			// run the monte carlo equivalency tests and compare encryption to a vector
			MonteCarlo(acs256s, m_message, m_key[0], m_nonce, m_monte);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 monte carlo tests.."));

			// compare parallel output with sequential for equality
			Parallel(acs256s);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 parallel to sequential equivalence test.."));

			// looping test of successful decryption with random keys and input
			Stress(acs256s);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 stress tests.."));

			// verify ciphertext output, decryption, and mac code generation
			Verification(acsc256h256, m_message, m_key[0], m_nonce, m_expected[1], m_code[0]);
			Verification(acsc256k256, m_message, m_key[0], m_nonce, m_expected[2], m_code[2]);
			Verification(acsc512h512, m_message, m_key[1], m_nonce, m_expected[3], m_code[4]);
			Verification(acsc512k512, m_message, m_key[1], m_nonce, m_expected[4], m_code[6]);
			Verification(acsc1024k1024, m_message, m_key[2], m_nonce, m_expected[5], m_code[8]);
			OnProgress(std::string("MCSTest: Passed MCS-256/512/1024 known answer authentication tests.."));

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
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void MCSTest::Authentication(IStreamCipher* Cipher)
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

	void MCSTest::Exception()
	{
		// test the enumeration constructors for invalid block-cipher type
		try
		{
			MCS cpr(BlockCiphers::None, StreamAuthenticators::None);

			throw TestException(std::string("Exception"), StreamCipherConvert::ToName(StreamCiphers::MCSR), std::string("Exception handling failure! -AE1"));
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
			MCS cpr(BlockCiphers::AES, StreamAuthenticators::None);
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
			MCS cpr(BlockCiphers::AES, StreamAuthenticators::None);
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
			MCS cpr(BlockCiphers::AES, StreamAuthenticators::None);
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
			MCS cpr(BlockCiphers::AES, StreamAuthenticators::None);
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

	void MCSTest::Finalization(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &MacCode1, std::vector<byte> &MacCode2)
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

	void MCSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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

	void MCSTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
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

	void MCSTest::Parallel(IStreamCipher* Cipher)
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

	void MCSTest::Stress(IStreamCipher* Cipher)
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

	void MCSTest::Verification(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected, std::vector<byte> &Mac)
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

	void MCSTest::Initialize()
	{
		/*lint -save -e417 */

		// Note: these are all original vectors and should be considered authoritative

		const std::vector<std::string> code =
		{
			// acsc256h256
			std::string("7CD65960B28F0CCEAC04DB6C7D1C21A59B50961BD3CE7CE01B9A6596A68A3D5D"),
			std::string("4AA2C8A8C3369B2F9FE01916AD98F6522B5FBF4A313D552677F9B24B5B9A6743"),
			// acsc256k256
			std::string("8AADC93F609320FFE6562082085BC3E68BC008C3F0100F6F51BBDCF2C4A1C2B1"),
			std::string("05D6349107A2CBCEB0A3F134F7AE9F78F138AE69A74234137A3787FCFBCAA1B3"),
			// acsc512h512
			std::string("E8D9CEACEBFD7168BD5BE8D41AF5876FB696D6A652E5F33D4B9ACB94BE684A982C029E8E2039AD44043629AB3F2C3A243AFD0423C8BD09EDC386669F7B3424D8"),
			std::string("38FDFC0B594612840AF3C0E8808BDF6F070FA9B313AD98278816EE253184EA8F8EA31A6F428187B1F63E8996569C0361EB0C19D4E54D590FAB2002109D225B9E"),
			// acsc512k512
			std::string("FF3B2F6A706E21626D4BCDBAD03C065F1B3060EB27DE526929559EB5E36DF63CC40B0C7210E65167EDC6A05197E7517A3EE94468CC889DAD9F0051D09C3F025F"),
			std::string("FE3F5A681744647DE913BE88F50080F3E7E1A7A8B9FEC7470C505E7F001F45BEA1DFD145ACF40F6C00FAE5F1EF5B100E150243A2CE2C7F2B25AE29394ACDC9F3"),
			// acs1024k1024
			std::string("40338C7FF3FE44D656997E246527ADA7D2EB62269D90DEB4C889A51A0D45288144AF19F0E7FD694D8C82C8E50521AB413573DEF5B1A68D3C5801F6A53683250F"
				"6A2DB68F4FDF435FCBAA3E1804968444103B2785B55D5F4BA0B45F77DF45E3E0E537A37E9617DF99FA2D285855D3C565AEE331140D47923582B37EEC42978777"),
			std::string("288B07DA17CAF1F76A2F361617F984684813B3F6D1950E8429ABCEBDE6AC73ED52374545D97BE92D64C9C595B13A57C2725CAA0ED757DA6F6158DB302EE1E527"
				"0FBEC72AF7836252993CB3AA2D40D34FF07442743AB8F53DB4255C2735376B7F6C360ED096081D262C47C0FF954A18E3C9AFB720F105CCF0270CB5FD20B6438E")
		};
		HexConverter::Decode(code, 10, m_code);

		const std::vector<std::string> expected =
		{
			std::string("81F10A87673A10B1EC8AE4714002D290"),	// acs256s
			std::string("4BA1DFF25E8BEA4928821B58BA2678D0"),	// acsc256h256
			std::string("83131264443AD7F15518D620AAD119D1"),	// acsc256k256
			std::string("D78702564AA56F77FFF871168DBCC0FA"),	// acsc512h512
			std::string("25019BA9E697ABED1C0E383E81DEF527"),	// acsc512k512
			std::string("987AF6C0BA319F497921668F06667A72")		// acsc1024k1024
		};
		HexConverter::Decode(expected, 6, m_expected);

		const std::vector<std::string> key =
		{
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(key, 3, m_key);

		const std::string message =
		{
			std::string("000102030405060708090A0B0C0D0E0F"),
		};
		HexConverter::Decode(message, m_message);

		const std::string monte =
		{
			std::string("DCE8976A4A338FFC5DC7ED1C964C050E")
		};
		HexConverter::Decode(monte, m_monte);

		const std::string nonce =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0")
		};
		HexConverter::Decode(nonce, m_nonce);

		/*lint -restore */
	}

	void MCSTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
