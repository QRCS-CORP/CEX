#include "ChaChaTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/ChaCha256.h"
#include "../CEX/ChaCha512.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Cipher::Symmetric::Stream::ChaCha;
	using Cipher::Symmetric::Stream::ChaCha256;
	using Cipher::Symmetric::Stream::ChaCha512;
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntUtils;
	using Utility::MemUtils;
	using Prng::SecureRandom;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ChaChaTest::DESCRIPTION = "Tests the 256 and 512 bit versions of the ChaCha stream cipher.";
	const std::string ChaChaTest::FAILURE = "ChaChaTest: Test Failure!";
	const std::string ChaChaTest::SUCCESS = "SUCCESS! All ChaCha tests have executed succesfully.";

	ChaChaTest::ChaChaTest()
		:
		m_expected(0),
		m_key(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	ChaChaTest::~ChaChaTest()
	{
	}

	const std::string ChaChaTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ChaChaTest::Progress()
	{
		return m_progressEvent;
	}

	std::string ChaChaTest::Run()
	{
		try
		{
			// Standard ChaChaPoly20

			ChaCha256* cpr256a = new ChaCha256(Enumeration::StreamAuthenticators::HMACSHA256);
			ChaCha256* cpr256b = new ChaCha256();

			Authentication(cpr256a);
			OnProgress(std::string("Passed ChaCha-256 MAC authentication tests.."));

			Exception(cpr256b);
			OnProgress(std::string("Passed ChaCha-256 exception handling tests.."));

			Parallel(cpr256b);
			OnProgress(std::string("Passed ChaCha-256 parallel to sequential equivalence test.."));

			Permutation256();
			OnProgress(std::string("Passed ChaCha-256 permutation variants equivalence test.."));

			Stress(cpr256b);
			OnProgress(std::string("Passed ChaCha-256 stress and fuzz tests.."));

			Kat(cpr256a, m_key[0], m_nonce[0], m_expected[0]);
			Kat(cpr256a, m_key[1], m_nonce[1], m_expected[1]);
			Kat(cpr256b, m_key[0], m_nonce[0], m_expected[2]);
			Kat(cpr256b, m_key[1], m_nonce[1], m_expected[3]);
			OnProgress(std::string("Passed ChaCha-256 known answer tests.."));

			delete cpr256a;
			delete cpr256b;

			// ChaChaPoly80 is the default if CEX_CHACHA512_STRONG is defined in CexConfig, or ChaChaPoly40 as alternate

			ChaCha512* cpr512a = new ChaCha512(Enumeration::StreamAuthenticators::HMACSHA256);
			ChaCha512* cpr512b = new ChaCha512();

			Authentication(cpr512a);
			OnProgress(std::string("Passed ChaCha-512 MAC authentication tests.."));

			Exception(cpr512b);
			OnProgress(std::string("Passed ChaCha-512 exception handling tests.."));

			Parallel(cpr512b);
			OnProgress(std::string("Passed ChaCha-512 parallel to sequential equivalence test.."));

			Permutation512();
			OnProgress(std::string("Passed ChaCha-512 permutation variants equivalence test.."));

			Stress(cpr512b);
			OnProgress(std::string("Passed ChaCha-512 stress and fuzz tests.."));

			Kat(cpr512a, m_key[2], m_nonce[2], m_expected[4]);
			Kat(cpr512a, m_key[3], m_nonce[3], m_expected[5]);
			Kat(cpr512b, m_key[2], m_nonce[2], m_expected[6]);
			Kat(cpr512b, m_key[3], m_nonce[3], m_expected[7]);
			OnProgress(std::string("Passed ChaCha-512 known answer tests.."));

			delete cpr512a;
			delete cpr512b;

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

	void ChaChaTest::Authentication(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t MACLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> mac(MACLEN);
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;
		size_t j;

		cpt.reserve(MAXSMP + MACLEN);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		// test large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(INPLEN + MACLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntUtils::Fill(inp, 0, INPLEN, rnd);
			IntUtils::Fill(key, 0, key.size(), rnd);
			if (nonce.size() > 0)
			{
				IntUtils::Fill(nonce, 0, nonce.size(), rnd);
			}
			SymmetricKey kp(key, nonce);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, INPLEN);
			// write mac to output stream
			Cipher->Finalize(cpt, INPLEN, MACLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, INPLEN);
			// write mac to temp array
			Cipher->Finalize(mac, 0, MACLEN);

			// use constant time IntUtils::Compare to verify mac
			if (!IntUtils::Compare(mac, 0, cpt, INPLEN, MACLEN))
			{
				throw TestException("Authentication: MAC output is not equal! -TA1");
			}

			for (j = 0; j < INPLEN; ++j)
			{
				if (inp[j] != otp[j])
				{
					throw TestException("Authentication: MAC output is not equal! -TA2");
				}
			}
		}
	}

	void ChaChaTest::Exception(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(Cipher->Name(), std::string("Exception: Exception handling failure! -TE1"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(1);
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(Cipher->Name(), std::string("Exception: Exception handling failure! -TE2"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.NonceSize());
			std::vector<byte> info(ks.InfoSize() + 1);
			SymmetricKey kp(key, nonce, info);

			Cipher->Initialize(true, kp);

			throw TestException(Cipher->Name(), std::string("Exception: Exception handling failure! -TE3"));
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
			std::vector<byte> mac(16);

			Cipher->Finalize(mac, 0, 16);

			throw TestException(Cipher->Name(), std::string("Exception: Exception handling failure! -TE4"));
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
			std::vector<byte> nonce(ks.NonceSize());
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);
			Cipher->ParallelMaxDegree(9999);

			throw TestException(Cipher->Name(), std::string("Exception: Exception handling failure! -TE6"));
		}
		catch (CryptoSymmetricCipherException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void ChaChaTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t MSGLEN = Expected.size();
		std::vector<byte> msg(MSGLEN);
		std::vector<byte> cpt(MSGLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(msg, 0, cpt, 0, MSGLEN);
		std::string tmp = "";
		HexConverter::ToString(cpt, tmp);


		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != msg)
		{
			throw TestException("Kat: Decrypted output does not match the input! -TV1");
		}
		if (cpt != Expected)
		{
			throw TestException("Kat: Output does not match the known answer! -TV2");
		}
	}

	void ChaChaTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;	
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.NonceSize());
		std::vector<byte> otp;
		Prng::SecureRandom rnd;
		size_t prlSize = Cipher->ParallelProfile().ParallelBlockSize();

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.resize(INPLEN);
			cpt2.resize(INPLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, INPLEN, rnd);
			SymmetricKey kp(key, nonce);

			Cipher->ParallelProfile().ParallelBlockSize() = Cipher->ParallelProfile().ParallelMinimumSize();

			// sequential
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, INPLEN);

			// parallel
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, INPLEN);

			if (cpt1 != cpt2)
			{
				throw TestException("Parallel: Cipher output is not equal! -TP1");
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, INPLEN);

			if (otp != inp)
			{
				throw TestException("Parallel: Cipher output is not equal! -TP2");
			}
		}

		// restore parallel block size
		Cipher->ParallelProfile().ParallelBlockSize() = prlSize;
	}

	void ChaChaTest::Permutation256()
	{
		const size_t ROUNDS = 20;
		std::array<uint, 2> counter{ 128, 1 };
		std::vector<byte> output1(64);
		std::vector<byte> output2(64);
		std::array<uint, 14> state;

		MemUtils::Clear(state, 0, state.size() * sizeof(uint));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);
		ChaCha::PermuteR20P512U(output2, 0, counter, state);

		if (output1 != output2)
		{
			throw TestException("Permutation256: Permutation output is not equal! -TP1");
		}

#if defined(__AVX__)

		std::array<uint, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output3(256);

		ChaCha::PermuteP4x512H(output3, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 256; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException("Permutation256: Permutation output is not equal! -TP2");
				}
			}
		}

#endif

#if defined(__AVX2__)

		std::array<uint, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(512);

		ChaCha::PermuteP8x512H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException("Permutation256: Permutation output is not equal! -TP3");
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<uint, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output5(1024);

		ChaCha::PermuteP16x512H(output5, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output5[i + j] != output1[j])
				{
					throw TestException("Permutation256: Permutation output is not equal! -TP4");
				}
			}
		}

#endif
	}

	void ChaChaTest::Permutation512()
	{
#if defined(CEX_CHACHA512_STRONG)
		const size_t ROUNDS = 80;
#else
		const size_t ROUNDS = 40;
#endif
		std::array<uint, 2> counter{ 128, 1 };
		std::vector<byte> output1(64);
		std::array<uint, 14> state;

		MemUtils::Clear(state, 0, state.size() * sizeof(uint));

		ChaCha::PermuteP512C(output1, 0, counter, state, ROUNDS);

#if defined(__AVX__)

		std::array<uint, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output2(256);

		ChaCha::PermuteP4x512H(output2, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 256; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output2[i + j] != output1[j])
				{
					throw TestException("Permutation512: Permutation output is not equal! -TP1");
				}
			}
		}

#endif

#if defined(__AVX2__)

		std::array<uint, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output3(512);

		ChaCha::PermuteP8x512H(output3, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException("Permutation512: Permutation output is not equal! -TP2");
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<uint, 32> counter32{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(1024);

		ChaCha::PermuteP16x512H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 64)
		{
			for (size_t j = 0; j < 64; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException("Permutation512: Permutation output is not equal! -TP3");
				}
			}
		}

#endif
	}

	void ChaChaTest::Stress(IStreamCipher* Cipher)
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
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			cpt.resize(INPLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, INPLEN, rnd);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, INPLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, INPLEN);

			if (otp != inp)
			{
				throw TestException("Stress: Transformation output is not equal! -TS1");
			}
		}
	}

	void ChaChaTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF120053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")
		};
		HexConverter::Decode(key, 4, m_key);

		const std::vector<std::string> nonce =
		{
			std::string("0D74DB42A91077DE"),
			std::string("167DE44BB21980E7"),
			std::string(""),
			std::string("0D74DB42A91077DE167DE44BB21980E7"),
		};
		HexConverter::Decode(nonce, 4, m_nonce);

		const std::vector<std::string> expected =
		{
			std::string("E11860E3406A805A956BD628702D21AC05A16859C01353D22F0B9887AD6D9AFA9F4C071B76F3499DAAC9EBEE3ACFCC745FD95510F44A96BB5EABA0CEC5AA25C4"),  //20r-256a
			std::string("55FD939C4249B56A8CD2223CE30674F8ACAD39AFEF599EB552B9796879D870DD71EAE4E6622893430A6B05EDF0F6CC96BBF8E811D8106CD850FEE0DB2A4B6D6F"),  //20r-256a
			std::string("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3"),  //20r-256b
			std::string("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99"),  //20r-256b
#if defined(CEX_CHACHA512_STRONG)
			std::string("6D958E804499212F9696E9B9848C93A8F176C420E08E0B2FA3E8F2FE0C1CBB48CBDF3342D280849C2A19ECCFE6C25440A6C8EAB2946A8271CDEEEB6EFC218C7A"),  //80r-512a
			std::string("813EF7D209F39DDC3B516F78093645F02481A8B8C48A91685B8B6D2B7097F5C86BF10541DF7BF63E90FF56602DD6BF5179A2FD5338BCC9ED75DAE8AD44A2EFFA"),  //80r-512a
			std::string("E8B7594B1C5FFBE43D52318EB1B1E9231E2DD50275C9A6E5CBF33DACED3B2EF4B2FAD30DADD96FC634EBFD4D3897DE8A0DE9D3F846CDE0AA7EA31EA08A2F444F"),  //80r-512b
			std::string("54B70E75C5B79BBFCCF88DE2B1C356EB385C05C2F3AF91EE803A5AE8396F3DDDAF8D41DF905AA242AD7F27126596A829B890B34621F5E267C1D46DA8A44BEA8B")   //80r-512b
#else
			std::string("E034BBAA34F918971573A69E9C8A187D150C7E009998B5014AAC54F02E850DCC9F1FD8A89F1C66A36976203584BD72C4780104509F3CF6DAEEAF1EED3F0BF2C4"),  //40r-512a
			std::string("6B2222DCAEEFA57678756D3DA74A3AB3A901A2F914E69B1830405730E1AE0B86A67F161C2CD5038FFBBA68C32BA197BDF51B909205CB3DA1954F1C44592C2897"),  //40r-512a
			std::string("87E9E06B911153EEF0291D1C4B5624DCEBE9D64228D30FFD56F940923531A8E8D1A9013F1957D758E0330D92977987ED45A50053B8154586D739F4CDA6D6E6DE"),  //40r-512b
			std::string("67EB972A7390E2B4971D0BBCB17F9BD8A8C135E83B9D5338B9D66426E4B8495A9B4E02BE2DE52A8FB139BDA519728AC519EEBD8F3AC2495F4088E49A2C54DDB7")   //40r-512b
#endif
		};
		HexConverter::Decode(expected, 8, m_expected);

		/*lint -restore */
	}

	void ChaChaTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}