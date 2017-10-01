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

	std::string AsymmetricSpeedTest::Run()
	{
		try
		{
			std::string itrCnt = TestUtils::ToString(DEF_TEST_ITER);

			OnProgress(std::string("### Asymmetric Cipher Speed Tests in sequential and parallel modes:"));
			OnProgress("");

			// RingLWE
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using RingLWE Q12289N1024***"));
			RlweGenerateLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false);
			OnProgress(std::string("***Parallel: Generating " + itrCnt + " Keypairs using RingLWE Q12289N1024***"));
			RlweGenerateLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, true);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using RingLWE Q12289N1024***"));
			RlweEncryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false);
			OnProgress(std::string("***Parallel: Encrypting " + itrCnt + " messages using RingLWE Q12289N1024***"));
			RlweEncryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, true);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using RingLWE Q12289N1024***"));
			RlweDecryptLoop(RLWEParams::Q12289N1024, DEF_TEST_ITER, false);

			// McEliece
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using McEliece M12T62***"));
			MpkcGenerateLoop(MPKCParams::M12T62, DEF_TEST_ITER);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using McEliece M12T62 / GCM(AES256)***"));
			MpkcEncryptLoop(MPKCParams::M12T62, DEF_TEST_ITER);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using McEliece M12T62 / GCM(AES256)***"));
			MpkcDecryptLoop(MPKCParams::M12T62, DEF_TEST_ITER);

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

	void AsymmetricSpeedTest::MpkcGenerateLoop(MPKCParams Params, size_t Loops)
	{
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		Cipher::Symmetric::Block::IBlockCipher* symcpr = Helper::BlockCipherFromName::GetInstance(Enumeration::BlockCiphers::Rijndael);
		Cipher::Asymmetric::McEliece::McEliece asycpr(Params, rng, symcpr);
		Key::Asymmetric::IAsymmetricKeyPair* kp;

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			kp = asycpr.Generate();

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MpkcEncryptLoop(MPKCParams Params, size_t Loops)
	{
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		Cipher::Symmetric::Block::IBlockCipher* symcpr = Helper::BlockCipherFromName::GetInstance(Enumeration::BlockCiphers::AHX);
		Cipher::Asymmetric::McEliece::McEliece asycpr(Params, rng, symcpr);
		Key::Asymmetric::IAsymmetricKeyPair* kp;
		kp = asycpr.Generate();
		asycpr.Initialize(true, kp);
		std::vector<byte> msg(32);
		rng->GetBytes(msg);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			asycpr.Encrypt(msg);

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MpkcDecryptLoop(MPKCParams Params, size_t Loops)
	{
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		Cipher::Symmetric::Block::IBlockCipher* symcpr = Helper::BlockCipherFromName::GetInstance(Enumeration::BlockCiphers::AHX);
		Cipher::Asymmetric::McEliece::McEliece asycpr(Params, rng, symcpr);
		Key::Asymmetric::IAsymmetricKeyPair* kp;
		kp = asycpr.Generate();

		std::vector<byte> msg(32);
		std::vector<byte> enc;
		std::vector<byte> dec;
		rng->GetBytes(msg);

		asycpr.Initialize(true, kp);
		enc = asycpr.Encrypt(msg);
		asycpr.Initialize(false, kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			dec = asycpr.Decrypt(enc);

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Decrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " derypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweGenerateLoop(RLWEParams Params, size_t Loops, bool Parallel)
	{
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		Digest::IDigest* dgt = Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA256, false);
		Cipher::Asymmetric::RLWE::RingLWE cpr(Params, rng, dgt, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp;

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			kp = cpr.Generate();

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweEncryptLoop(RLWEParams Params, size_t Loops, bool Parallel)
	{
		std::vector<byte> sk1(0);
		std::vector<byte> msgB;
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR);
		Digest::IDigest* dgt = Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA256, false);
		Cipher::Asymmetric::RLWE::RingLWE cpr(Params, rng, dgt, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp = cpr.Generate();
		cpr.Initialize(true, kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			msgB = cpr.Encrypt(sk1);

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweDecryptLoop(RLWEParams Params, size_t Loops, bool Parallel)
	{
		std::vector<byte> sk1;
		std::vector<byte> msgB;
		Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR);
		Digest::IDigest* dgt = Helper::DigestFromName::GetInstance(Enumeration::Digests::SHA256, false);
		Cipher::Asymmetric::RLWE::RingLWE cpr(Params, rng, dgt, Parallel);
		Key::Asymmetric::IAsymmetricKeyPair* kp = cpr.Generate();
		Key::Asymmetric::RLWEPrivateKey* pri = (Key::Asymmetric::RLWEPrivateKey*)kp->PrivateKey();
		cpr.Initialize(true, kp);

		msgB = cpr.Encrypt(sk1);
		cpr.Initialize(false , kp);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
			sk1 = cpr.Decrypt(msgB);

		uint64_t dur = TestUtils::GetTimeMs64() - start;

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