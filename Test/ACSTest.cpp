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

			// encrypt plain-text, writes mac to output stream
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN))
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
		const size_t CPTLEN = Message.size() + Cipher->TagSize();
		const size_t MSGLEN = Message.size();
		const size_t TAGLEN = Cipher->TagSize();
		std::vector<byte> cpt(CPTLEN * 2);
		std::vector<byte> otp(MSGLEN * 2);
		SymmetricKey kp(Key, Nonce);

		// encrypt msg 1
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF1"));
		}

		// encrypt msg 2
		Cipher->Transform(Message, 0, cpt, MSGLEN + TAGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF2"));
		}

		// decrypt msg 1
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode1, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF3"));
		}

		// decrypt msg 2
		Cipher->Transform(cpt, MSGLEN + TAGLEN, otp, MSGLEN, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, MacCode2, 0, TAGLEN))
		{
			throw TestException(std::string("Finalization: MAC output is not equal! -TF4"));
		}

		// use constant time IntUtils::Compare to verify
		if (!IntUtils::Compare(otp, 0, Message, 0, MSGLEN) || !IntUtils::Compare(otp, MSGLEN, Message, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Decrypted output does not match the input! -TF5"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Finalization: Output does not match the known answer! -TF6"));
		}
	}

	void ACSTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

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
			throw TestException(std::string("Kat: Decrypted output does not match the input! -TV1"));
		}
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
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
		std::vector<byte> cpt(MSGLEN + TAGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -TV1"));
		}

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (!IntUtils::Compare(Cipher->Tag(), 0, Mac, 0, TAGLEN))
		{
			throw TestException(std::string("Verification: MAC output is not equal! -TV2"));
		}

		if (otp != Message)
		{
			throw TestException(std::string("Verification: Decrypted output does not match the input! -TV3"));
		}

		// use constant time IntUtils::Compare to verify mac
		if (!IntUtils::Compare(cpt, 0, Expected, 0, MSGLEN))
		{
			throw TestException(std::string("Verification: Output does not match the known answer! -TV4"));
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
			std::string("81C64659947E9D0CAD8205CC233E5777AE2AA4952CC07268CE6721ED74BBAF87"),
			std::string("A691C56EFA37801BFE2A17677F08CF73869E2978C3987A32764C1DAFC0066983"),
			// acsc256k256
			std::string("55E6B609D534BAF8B58A3BE0242DE59878BAF8F43B65AC0785F1BB18C8D71977"),
			std::string("08C90CE7F59AC4024C57B29A767F7B2A635121B3074960D419F2CB4151D3C775"),
			// acsc512h512
			std::string("4E0A717DB7D2FA050001C63B35204216FFF38191626E2CF0CBACFB1F50A56A5D4B64D7E49BF4844939CA05F55126A8703679CBF65EA83CF5588D0D09250A6A3B"),
			std::string("06779682928BBEB32A574FEEE24009CF06F4D6E50C949D43880AA25FBD78B119EFF410D9939C2D473D1E6CBDF4860A551CFC1AD29C5985F2F0C259A6C5777A94"),
			// acsc512k512
			std::string("5137E65362532EB875DDEB5215A835AFE0D5C32B0B5C0DF41B5CB49F8E6242D36D1D57751F3C03A6125CFDC1EB00F50E4263948BEEC4CD43E50ABABBC6364AA7"),
			std::string("A824C2BB41BC9E91E8C2C399EC0B908F8B59AC97D80ECA3592CEC98C9C9078A9F84269F1FB2B1C7D4D6DF0D518A70F69FD1C85C58E76FF1264107DBDE1C5CC28"),
			// acs1024k1024
			std::string("C06AB80DC4DCA79DCB7CFF462C816FECFBEFD41094253BF478DF0B107A83FCDBA6AE8AE5ECC4899D5704743BDAA052B7B9C9AA4580B0C1966D9D03A2887850EF062A113BF3F5011EC0E0B64F935CF42912E1AC12A80CD8151BE4CA873E5275044BC8DCA4AE22071ED817D7C428337AB714709F3B35907E05A2EF783C551DE1B3"),
			std::string("EB009556C58B9BA35A5B44AF13E5666FC3AD179F53D691D2EFCB0116386565A2E8F988E3E5D31DCC087A3F5CF8C77A48A532B01B4FC973780680A562F2151A2D85D7193E3BFE6C6A52B289963B93596CBE9ABF186D593E273CDEBC87A6D78BC1B331E50EB6DA649DE5F2980073D815E10A808BABA08D894F4AEBAA55164B2033")
		};
		HexConverter::Decode(code, 10, m_code);

		const std::vector<std::string> expected =
		{
			std::string("79E593AFE194798C43EBEF261FDC19D2"),	// acs256s
			std::string("BA0CBCEA687D952C6D5CCD7B4643E0D5"),	// acsc256h256
			std::string("E0D76197A6CB311A569675F5C62AE165"),	// acsc256k256
			std::string("CCD1E71F1BEE4EE4A4C61114DC64E6E2"),	// acsc512h512
			std::string("DA9A8EEBC30166509FD56C25BEFD403C"),	// acsc512k512
			std::string("E41C3A8E05673DAFB5F74E6D42B79175")		// acsc1024k1024
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

	void ACSTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
