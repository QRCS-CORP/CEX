#include "AsymmetricSpeedTest.h"
#include "../CEX/BlockCipherFromName.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/McEliece.h"
#include "../CEX/MPKCKeyPair.h"
#include "../CEX/PrngFromName.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RLWEKeyPair.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	const std::string AsymmetricSpeedTest::DESCRIPTION = "Asymmetric Cipher and Signature Scheme Speed Tests.";
	const std::string AsymmetricSpeedTest::FAILURE = "FAILURE! ";
	const std::string AsymmetricSpeedTest::MESSAGE = "COMPLETE! Asymmetric Speed tests have executed succesfully.";

	AsymmetricSpeedTest::AsymmetricSpeedTest()
		:
		m_progressEvent()
	{
	}

	AsymmetricSpeedTest::~AsymmetricSpeedTest()
	{
	}

	const std::string AsymmetricSpeedTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AsymmetricSpeedTest::Progress()
	{
		return m_progressEvent;
	}

	std::string AsymmetricSpeedTest::Run()
	{
		try
		{
			std::string itrCnt = TestUtils::ToString(DEF_TEST_ITER);
			IPrng* rngPtr = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
			IBlockCipher* sycPtr = Helper::BlockCipherFromName::GetInstance(Enumeration::BlockCiphers::Rijndael);

			OnProgress(std::string("### Asymmetric Cipher Speed Tests in sequential and parallel modes:"));
			OnProgress("");

			// RingLWE
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using RingLWE Q12289N1024***"));
			RlweGenerateLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false, rngPtr, sycPtr);
			OnProgress(std::string("***Parallel: Generating " + itrCnt + " Keypairs using RingLWE Q12289N1024***"));
			RlweGenerateLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, true, rngPtr, sycPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using RingLWE Q12289N1024 / GCM(AES256)***"));
			RlweEncryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false, rngPtr, sycPtr);
			OnProgress(std::string("***Parallel: Encrypting " + itrCnt + " messages using RingLWE Q12289N1024 / GCM(AES256)***"));
			RlweEncryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, true, rngPtr, sycPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using RingLWE Q12289N1024 / GCM(AES256)***"));
			RlweDecryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false, rngPtr, sycPtr);

			// McEliece
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using McEliece M12T62***"));
			MpkcGenerateLoop(MPKCParams::M12T62, DEF_TEST_ITER, rngPtr, sycPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using McEliece M12T62 / GCM(AES256)***"));
			MpkcEncryptLoop(MPKCParams::M12T62, DEF_TEST_ITER, rngPtr, sycPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using McEliece M12T62 / GCM(AES256)***"));
			MpkcDecryptLoop(MPKCParams::M12T62, DEF_TEST_ITER, rngPtr, sycPtr);

			delete sycPtr;
			delete rngPtr;

			return MESSAGE;
		}
		catch (std::exception const &ex)
		{
			return FAILURE + " : " + ex.what();
		}
		catch (...)
		{
			return FAILURE + " : Unknown Error";
		}
	}

	void AsymmetricSpeedTest::MpkcGenerateLoop(MPKCParams Params, size_t Loops, IPrng* Rng, IBlockCipher* Cipher)
	{
		Cipher::Asymmetric::McEliece::McEliece asyCpr(Params, Rng, Cipher);
		Key::Asymmetric::IAsymmetricKeyPair* kp = nullptr;

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			kp = asyCpr.Generate();
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MpkcEncryptLoop(MPKCParams Params, size_t Loops, IPrng* Rng, IBlockCipher* Cipher)
	{
		Cipher::Asymmetric::McEliece::McEliece asyCpr(Params, Rng, Cipher);
		Key::Asymmetric::IAsymmetricKeyPair* kp;
		kp = asyCpr.Generate();
		asyCpr.Initialize(true, kp);
		std::vector<byte> msg(32);
		Rng->GetBytes(msg);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Encrypt(msg);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MpkcDecryptLoop(MPKCParams Params, size_t Loops, IPrng* Rng, IBlockCipher* Cipher)
	{
		Cipher::Asymmetric::McEliece::McEliece asyCpr(Params, Rng, Cipher);
		Key::Asymmetric::IAsymmetricKeyPair* kp;
		kp = asyCpr.Generate();

		std::vector<byte> enc;
		std::vector<byte> dec;
		std::vector<byte> msg(32);
		Rng->GetBytes(msg);

		asyCpr.Initialize(true, kp);
		enc = asyCpr.Encrypt(msg);
		asyCpr.Initialize(false, kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			dec = asyCpr.Decrypt(enc);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Decrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " derypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweGenerateLoop(RLWEParams Params, size_t Loops, bool Parallel, IPrng* Rng, IBlockCipher* Cipher)
	{
		Cipher::Asymmetric::RLWE::RingLWE asyCpr(Params, Rng, Cipher, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp = nullptr;

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			kp = asyCpr.Generate();
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweEncryptLoop(RLWEParams Params, size_t Loops, bool Parallel, IPrng* Rng, IBlockCipher* Cipher)
	{
		std::vector<byte> cpt;
		std::vector<byte> msg(32);
		Rng->GetBytes(msg);
		Cipher::Asymmetric::RLWE::RingLWE asyCpr(Params, Rng, Cipher, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp = asyCpr.Generate();
		asyCpr.Initialize(true, kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			cpt = asyCpr.Encrypt(msg);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweDecryptLoop(RLWEParams Params, size_t Loops, bool Parallel, IPrng* Rng, IBlockCipher* Cipher)
	{
		std::vector<byte> cpt;
		Cipher::Asymmetric::RLWE::RingLWE asyCpr(Params, Rng, Cipher, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp = asyCpr.Generate();
		asyCpr.Initialize(true, kp);
		std::vector<byte> msg(32);
		Rng->GetBytes(msg);
		cpt = asyCpr.Encrypt(msg);
		asyCpr.Initialize(false , kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			msg = asyCpr.Decrypt(cpt);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Decrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " decrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	uint64_t AsymmetricSpeedTest::GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)Count;

		return (uint64_t)(sze / sec);
	}

	void AsymmetricSpeedTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}