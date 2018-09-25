#include "ThreefishTest.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"
#include "../CEX/Threefish.h"
#include "../CEX/Threefish256.h"
#include "../CEX/Threefish512.h"
#include "../CEX/Threefish1024.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Exception::CryptoSymmetricCipherException;
	using Utility::IntUtils;
	using Utility::MemUtils;
	using Prng::SecureRandom;
	using Key::Symmetric::SymmetricKey;
	using Key::Symmetric::SymmetricKeySize;
	using Cipher::Symmetric::Stream::Threefish;
	using Cipher::Symmetric::Stream::Threefish256;
	using Cipher::Symmetric::Stream::Threefish512;
	using Cipher::Symmetric::Stream::Threefish1024;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string ThreefishTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of the ThreeFish stream cipher.";
	const std::string ThreefishTest::FAILURE = "ThreefishTest: Test Failure!";
	const std::string ThreefishTest::SUCCESS = "SUCCESS! All Threefish tests have executed succesfully.";

	ThreefishTest::ThreefishTest()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	ThreefishTest::~ThreefishTest()
	{
	}

	const std::string ThreefishTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &ThreefishTest::Progress()
	{
		return m_progressEvent;
	}

	std::string ThreefishTest::Run()
	{
		try
		{
			Threefish256* cpr256a = new Threefish256(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish256* cpr256b = new Threefish256();

			Authentication(cpr256a);
			OnProgress(std::string("Passed Threefish-256 MAC authentication tests.."));

			Exception(cpr256b);
			OnProgress(std::string("Passed Threefish-256 exception handling tests.."));

			Kat(cpr256a, m_message[0], m_expected[0]);
			Kat(cpr256b, m_message[0], m_expected[1]);
			OnProgress(std::string("Passed Threefish-256 known answer tests.."));

			Parallel(cpr256b);
			OnProgress(std::string("Passed Threefish-256 parallel to sequential equivalence test.."));

			Permutation256();
			OnProgress(std::string("Passed Threefish-256 permutation variants equivalence test.."));

			Stress(cpr256b);
			OnProgress(std::string("Passed Threefish-256 stress and fuzz tests.."));

			delete cpr256a;
			delete cpr256b;

			Threefish512* cpr512a = new Threefish512(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish512* cpr512b = new Threefish512();

			Authentication(cpr512a);
			OnProgress(std::string("Passed Threefish-512 MAC authentication tests.."));

			Exception(cpr512b);
			OnProgress(std::string("Passed Threefish-512 exception handling tests.."));

			Kat(cpr512a, m_message[1], m_expected[2]);
			Kat(cpr512b, m_message[1], m_expected[3]);
			OnProgress(std::string("Passed Threefish-512 known answer tests.."));

			Parallel(cpr512b);
			OnProgress(std::string("Passed Threefish-512 parallel to sequential equivalence test.."));

			Permutation512();
			OnProgress(std::string("Passed Threefish-512 permutation variants equivalence test.."));

			Stress(cpr512b);
			OnProgress(std::string("Passed Threefish-512 stress and fuzz tests.."));

			delete cpr512a;
			delete cpr512b;

			Threefish1024* cpr1024a = new Threefish1024(Enumeration::StreamAuthenticators::HMACSHA256);
			Threefish1024* cpr1024b = new Threefish1024();

			Authentication(cpr1024a);
			OnProgress(std::string("Passed Threefish-1024 MAC authentication tests.."));

			Exception(cpr1024b);
			OnProgress(std::string("Passed Threefish-1024 exception handling tests.."));

			Kat(cpr1024a, m_message[2], m_expected[4]);
			Kat(cpr1024b, m_message[2], m_expected[5]);
			OnProgress(std::string("Passed Threefish-1024 known answer tests.."));

			Parallel(cpr1024b);
			OnProgress(std::string("Passed Threefish-1024 parallel to sequential equivalence test.."));

			Permutation1024();
			OnProgress(std::string("Passed Threefish-1024 permutation variants equivalence test.."));

			Stress(cpr1024b);
			OnProgress(std::string("Passed Threefish-1024 stress and fuzz tests.."));

			delete cpr1024a;
			delete cpr1024b;

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

	void ThreefishTest::Authentication(IStreamCipher* Cipher)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t MACLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> mac(MACLEN);
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;
		size_t j;
		size_t k;

		cpt.reserve(MAXSMP + MACLEN);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		// test-1: compare large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(INPLEN + MACLEN);
			inp.resize(INPLEN);
			otp.resize(INPLEN);

			IntUtils::Fill(key, 0, key.size(), rnd);
			IntUtils::Fill(inp, 0, INPLEN, rnd);
			SymmetricKey kp(key);

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
				throw TestException("Authentication: MAC output is not equal! -TA2");
			}

			for (j = 0; j < INPLEN; ++j)
			{
				if (inp[j] != otp[j])
				{
					throw TestException("Authentication: MAC output is not equal! -TA3");
				}
			}
		}
	}

	void ThreefishTest::Exception(IStreamCipher* Cipher)
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
			SymmetricKey kp(key);

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

	void ThreefishTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		const size_t MSGLEN = Message.size();
		std::vector<byte> cpt(MSGLEN);
		std::vector<byte> key(ks.KeySize(), 0x80);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(key);

		// encrypt
		Cipher->Initialize(true, kp);
		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		// decrypt
		Cipher->Initialize(false, kp);
		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException("Kat: Decrypted output does not match the input! -TV1");
		}
		if (cpt != Expected)
		{
			throw TestException("Kat: Output does not match the known answer! -TV2");
		}
	}

	void ThreefishTest::Parallel(IStreamCipher* Cipher)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> otp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> iv(ks.NonceSize());
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
			SymmetricKey kp(key);

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

	void ThreefishTest::Permutation256()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 4> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 4> state1;
		std::array<ulong, 4> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 4, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 4 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 4 * sizeof(ulong));

		Threefish::PemuteP256C(key, counter, tweak, state1, 72);
		Threefish::PemuteR72P256U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException("Permutation256: Permutation output is not equal! -TP1");
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 16> state3;

		MemUtils::Clear(state3, 0, 16 * sizeof(ulong));

		Threefish::PemuteP4x256H(key, counter8, tweak, state3, 72);

		for (size_t i = 0; i < 16; i += 4)
		{
			for (size_t j = 0; j < 4; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException("Permutation256: Permutation output is not equal! -TP2");
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 32> state4;

		MemUtils::Clear(state4, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter16, tweak, state4, 72);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException("Permutation256: Permutation output is not equal! -TP3");
				}
			}
		}

#endif
	}

	void ThreefishTest::Permutation512()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 8> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 8> state1;
		std::array<ulong, 8> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 8, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 8 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 8 * sizeof(ulong));

		Threefish::PemuteP512C(key, counter, tweak, state1, 96);
		Threefish::PemuteR96P512U(key, counter, tweak, state2);

		if (state1 != state2)
		{
			throw TestException("Permutation512: Permutation output is not equal! -TP1");
		}

#if defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 32> state3;

		MemUtils::Clear(state3, 0, 32 * sizeof(ulong));

		Threefish::PemuteP4x512H(key, counter8, tweak, state3, 96);

		for (size_t i = 0; i < 32; i += 8)
		{
			for (size_t j = 0; j < 8; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException("Permutation512: Permutation output is not equal! -TP2");
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 64> state4;

		MemUtils::Clear(state4, 0, 64 * sizeof(ulong));

		Threefish::PemuteP8x512H(key, counter16, tweak, state4, 96);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException("Permutation512: Permutation output is not equal! -TP3");
				}
			}
		}

#endif

	}

	void ThreefishTest::Permutation1024()
	{
		std::array<ulong, 2> counter{ 128, 1 };
		std::array<ulong, 16> key;
		std::array<ulong, 2> tweak;
		std::array<ulong, 16> state1;
		std::array<ulong, 16> state2;
		SecureRandom rnd;

		IntUtils::Fill(key, 0, 16, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 16 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 16 * sizeof(ulong));

		Threefish::PemuteR120P1024U(key, counter, tweak, state2);
		Threefish::PemuteP1024C(key, counter, tweak, state1, 120);

		if (state1 != state2)
		{
			throw TestException("Permutation1024: Permutation output is not equal! -TP1");
		}

#if defined(__AVX2__)
		
		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::array<ulong, 64> state3;

		MemUtils::Clear(state3, 0, 64 * sizeof(ulong));

		Threefish::PemuteP4x1024H(key, counter8, tweak, state3, 120);

		for (size_t i = 0; i < 64; i += 16)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state3[i + j] != state1[j])
				{
					throw TestException("Permutation1024: Permutation output is not equal! -TP2");
				}
			}
		}

#endif

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::array<ulong, 128> state4;

		MemUtils::Clear(state4, 0, 128 * sizeof(ulong));

		Threefish::PemuteP8x1024H(key, counter16, tweak, state4, 120);

		for (size_t i = 0; i < 128; ++i)
		{
			for (size_t j = 0; j < 16; ++j)
			{
				if (state4[i + j] != state1[j])
				{
					throw TestException("Permutation1024: Permutation output is not equal! -TP3");
				}
			}
		}

#endif

	}

	void ThreefishTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());

		Key::Symmetric::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
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
			SymmetricKey kp(key);

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

	void ThreefishTest::Initialize()
	{
		/*lint -save -e417 */

		const std::vector<std::string> message =
		{
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180")
		};
		HexConverter::Decode(message, 3, m_message);

		const std::vector<std::string> expected =
		{
			std::string("53B70C933BAD75B831BDC0361F8DAEAB0A8679C9E462E735FEED9E1132A0509E"),
			std::string("CDB81BAE0714AE3B9ED4CC4C353C3715D3A7A66FE2AB2A863AC8A33B2986AE1B"),
			std::string("A73C74354C4BD1593F78D7DF3E072C4F0FC6CCBF112A4A6F1C8BF71F7E362696C62DC709C1AB7A4AA9CFACDA0ED2C3A2AE6C0B29693C18AB7E6354F4F0AA3783"),
			std::string("8800F977F11DA6981A3386406CD901B4A1637F415AD999947E1DA1878877C8F58ECB88E534CA025678DD28CAFBBAEFFC8703A47F6FF18C54D2CAA5D56583304B"),
			std::string("704A256A35D34F86C42D7714FCB2AA8D606B5685DB3F3275CF92726534C204AE89D58632A6F9931E0FDF976632A812317646A878B5928A2F4FD3F73174CB00C8AC1279B46E04F910F4DD9570174CEE8F78177F92955827E592DB1D98AE75F4AF2F57F81AE0599623F45664AC3C0F22DE2FA79492EF7C547878DEEAC513C05549"),
			std::string("F1F17FAE937F7B6F9FAB7B9218D06D66503D24E7037176498122F4392AFC8871F655DCDDBAD16EF444D5F72CC77DED724984FE9D24286052570B59D0639EAB0C8E7A444EDEA2B5A3E491A2C1ED9DE2C9F97AF61F2C74DC56A184BAF5CA5E0482BF0323BC20A3CA6995E5687C3D1AF9A03E9B1D0451D7F300256D75668C2E04D7")
		};
		HexConverter::Decode(expected, 6, m_expected);

		/*lint -restore */
	}

	void ThreefishTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
