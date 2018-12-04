#include "AsymmetricSpeedTest.h"
#include "../CEX/BlockCipherFromName.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/IAsymmetricKeyPair.h"
#include "../CEX/McEliece.h"
#include "../CEX/MPKCKeyPair.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/MLWEKeyPair.h"
#include "../CEX/NTRU.h"
#include "../CEX/NTRUKeyPair.h"
#include "../CEX/PrngFromName.h"
#include "../CEX/RingLWE.h"
#include "../CEX/RLWEKeyPair.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Enumeration::Prngs;
	using Enumeration::Providers;
	using Key::Asymmetric::IAsymmetricKeyPair;
	using Key::Asymmetric::MLWEKeyPair;
	using Key::Asymmetric::MPKCKeyPair;
	using Key::Asymmetric::NTRUKeyPair;
	using Key::Asymmetric::RLWEKeyPair;
	using Cipher::Asymmetric::MPKC::McEliece;
	using Cipher::Asymmetric::MLWE::ModuleLWE;
	using Cipher::Asymmetric::NTRU::NTRU;
	using Cipher::Asymmetric::RLWE::RingLWE;

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
			IPrng* rngPtr = Helper::PrngFromName::GetInstance(Prngs::BCR, Providers::CSP);

			OnProgress(std::string("### Asymmetric Cipher Speed Tests in sequential and parallel modes:"));
			OnProgress(std::string(""));

			// RingLWE
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using RingLWE RLWES1Q12289N1024***"));
			RlweGenerateLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using RingLWE RLWES1Q12289N1024***"));
			RlweEncryptLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using RingLWE RLWES1Q12289N1024***"));
			RlweDecryptLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngPtr);

			// McEliece
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using McEliece MPKCS1M12T62***"));
			MpkcGenerateLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using McEliece MPKCS1M12T62***"));
			MpkcEncryptLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using McEliece MPKCS1M12T62***"));
			MpkcDecryptLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

			// ModuleLWE
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using ModuleLWE MLWES3Q7681N256***"));
			MlweGenerateLoop(MLWEParameters::MLWES3Q7681N256, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using ModuleLWE MLWES3Q7681N256***"));
			MlweEncryptLoop(MLWEParameters::MLWES3Q7681N256, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using ModuleLWE MLWES3Q7681N256***"));
			MlweDecryptLoop(MLWEParameters::MLWES3Q7681N256, DEF_TEST_ITER, rngPtr);

			// NTRU
			OnProgress(std::string("***Sequential: Generating " + itrCnt + " Keypairs using NTRU NTRUS1LQ4591N761***"));
			MpkcGenerateLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Encrypting " + itrCnt + " messages using NTRU NTRUS1LQ4591N761***"));
			MpkcEncryptLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

			OnProgress(std::string("***Sequential: Decrypting " + itrCnt + " messages using NTRU NTRUS1LQ4591N761***"));
			MpkcDecryptLoop(MPKCParameters::MPKCS1M12T62, DEF_TEST_ITER, rngPtr);

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

	void AsymmetricSpeedTest::MlweDecryptLoop(MLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		ModuleLWE asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());
		asyCpr.Encapsulate(cpt, sec1);
		asyCpr.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Decapsulate(cpt, sec2);
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

	void AsymmetricSpeedTest::MlweEncryptLoop(MLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		ModuleLWE asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Encapsulate(cpt, sec);
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

	void AsymmetricSpeedTest::MlweGenerateLoop(MLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		ModuleLWE asyCpr(Params, Rng);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			MLWEKeyPair* kp = reinterpret_cast<MLWEKeyPair*>(asyCpr.Generate());
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MpkcDecryptLoop(MPKCParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		McEliece asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());
		asyCpr.Encapsulate(cpt, sec1);
		asyCpr.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Decapsulate(cpt, sec2);
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

	void AsymmetricSpeedTest::MpkcEncryptLoop(MPKCParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		McEliece asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Encapsulate(cpt, sec);
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

	void AsymmetricSpeedTest::MpkcGenerateLoop(MPKCParameters Params, size_t Loops, IPrng* Rng)
	{
		McEliece asyCpr(Params, Rng);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			MPKCKeyPair* kp = reinterpret_cast<MPKCKeyPair*>(asyCpr.Generate());
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::NtruDecryptLoop(NTRUParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		NTRU asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());
		asyCpr.Encapsulate(cpt, sec1);
		asyCpr.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Decapsulate(cpt, sec2);
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

	void AsymmetricSpeedTest::NtruEncryptLoop(NTRUParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		NTRU asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Encapsulate(cpt, sec);
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

	void AsymmetricSpeedTest::NtruGenerateLoop(NTRUParameters Params, size_t Loops, IPrng* Rng)
	{
		NTRU asyCpr(Params, Rng);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			NTRUKeyPair* kp = reinterpret_cast<NTRUKeyPair*>(asyCpr.Generate());
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::RlweDecryptLoop(RLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		RingLWE asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());
		asyCpr.Encapsulate(cpt, sec1);
		asyCpr.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Decapsulate(cpt, sec2);
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

	void AsymmetricSpeedTest::RlweEncryptLoop(RLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		RingLWE asyCpr(Params, Rng);
		IAsymmetricKeyPair* kp;

		kp = asyCpr.Generate();
		asyCpr.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asyCpr.Encapsulate(cpt, sec);
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

	void AsymmetricSpeedTest::RlweGenerateLoop(RLWEParameters Params, size_t Loops, IPrng* Rng)
	{
		RingLWE asyCpr(Params, Rng);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			RLWEKeyPair* kp = reinterpret_cast<RLWEKeyPair*>(asyCpr.Generate());
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

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
