#include "AsymmetricSpeedTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/BlockCipherFromName.h"
#include "../CEX/DigestFromName.h"
#include "../CEX/Dilithium.h"
#include "../CEX/McEliece.h"
#include "../CEX/ModuleLWE.h"
#include "../CEX/NTRU.h"
#include "../CEX/PrngFromName.h"
#include "../CEX/RingLWE.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHAKE.h"
#include "../CEX/Sphincs.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Asymmetric::Sign::DLM::Dilithium;
	using Asymmetric::Encrypt::MPKC::McEliece;
	using Asymmetric::Encrypt::MLWE::ModuleLWE;
	using Asymmetric::Encrypt::NTRU::NTRU;
	using Enumeration::Prngs;
	using Enumeration::Providers;
	using Asymmetric::Encrypt::RLWE::RingLWE;
	using Kdf::SHAKE;
	using Asymmetric::Sign::SPX::Sphincs;

	const std::string AsymmetricSpeedTest::CLASSNAME = "AsymmetricSpeedTest";
	const std::string AsymmetricSpeedTest::DESCRIPTION = "Asymmetric Cipher and Signature Scheme Speed Tests.";
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
			std::string ctr = TestUtils::ToString(DEF_TEST_ITER);
			Prngs rngType = Prngs::BCR;

			// RingLWE
			OnProgress(std::string("***Generating " + ctr + " Keypairs using RingLWE RLWES1Q12289N1024***"));
			RlweGenerateLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Encrypting " + ctr + " messages using RingLWE RLWES1Q12289N1024***"));
			RlweEncryptLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Decrypting " + ctr + " messages using RingLWE RLWES1Q12289N1024***"));
			RlweDecryptLoop(RLWEParameters::RLWES1Q12289N1024, DEF_TEST_ITER, rngType);

			// McEliece
			OnProgress(std::string("***Generating " + ctr + " Keypairs using McEliece MPKCS1N4096T62***"));
			MpkcGenerateLoop(MPKCParameters::MPKCS1N4096T62, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Encrypting " + ctr + " messages using McEliece MPKCS1N4096T62***"));
			MpkcEncryptLoop(MPKCParameters::MPKCS1N4096T62, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Decrypting " + ctr + " messages using McEliece MPKCS1N4096T62***"));
			MpkcDecryptLoop(MPKCParameters::MPKCS1N4096T62, DEF_TEST_ITER, rngType);

			// ModuleLWE
			OnProgress(std::string("***Generating " + ctr + " Keypairs using ModuleLWE MLWES2Q3329N256***"));
			MlweGenerateLoop(MLWEParameters::MLWES2Q3329N256, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Encrypting " + ctr + " messages using ModuleLWE MLWES2Q3329N256***"));
			MlweEncryptLoop(MLWEParameters::MLWES2Q3329N256, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Decrypting " + ctr + " messages using ModuleLWE MLWES2Q3329N256***"));
			MlweDecryptLoop(MLWEParameters::MLWES2Q3329N256, DEF_TEST_ITER, rngType);

			// NTRU
			OnProgress(std::string("***Generating " + ctr + " Keypairs using NTRU NTRUS1LQ4591N761***"));
			NtruGenerateLoop(NTRUParameters::NTRUS1LQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Encrypting " + ctr + " messages using NTRU NTRUS1LQ4591N761***"));
			NtruEncryptLoop(NTRUParameters::NTRUS1LQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Decrypting " + ctr + " messages using NTRU NTRUS1LQ4591N761***"));
			NtruDecryptLoop(NTRUParameters::NTRUS1LQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Generating " + ctr + " Keypairs using NTRU NTRUS2SQ4591N761***"));
			NtruGenerateLoop(NTRUParameters::NTRUS2SQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Encrypting " + ctr + " messages using NTRU NTRUS2SQ4591N761***"));
			NtruEncryptLoop(NTRUParameters::NTRUS2SQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Decrypting " + ctr + " messages using NTRU NTRUS2SQ4591N761***"));
			NtruDecryptLoop(NTRUParameters::NTRUS2SQ4591N761, DEF_TEST_ITER, rngType);

			OnProgress(std::string("### Asymmetric Signature Scheme Speed Tests:"));
			OnProgress(std::string(""));

			// Dilithium
			OnProgress(std::string("***Generating " + ctr + " Keypairs using Dilithium DLMS2N256Q8380417***"));
			DlmGenerateLoop(DilithiumParameters::DLMS2N256Q8380417, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Signing " + ctr + " messages using Dilithium DLMS2N256Q8380417***"));
			DlmSignLoop(DilithiumParameters::DLMS2N256Q8380417, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Verifying " + ctr + " messages using Dilithium DLMS2N256Q8380417***"));
			DlmVerifyLoop(DilithiumParameters::DLMS2N256Q8380417, DEF_TEST_ITER, rngType);

			OnProgress(std::string("### Asymmetric Cipher Speed Tests in sequential and parallel modes:"));
			OnProgress(std::string(""));

			// SPHINCS+
			OnProgress(std::string("***Generating " + ctr + " Keypairs using SPHINCS+ SPXS128F256***"));
			SpxGenerateLoop(SphincsParameters::SPXS128F256, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Signing " + ctr + " messages using SPHINCS+ SPXS128F256***"));
			SpxSignLoop(SphincsParameters::SPXS128F256, DEF_TEST_ITER, rngType);

			OnProgress(std::string("***Verifying " + ctr + " messages using SPHINCS+ SPXS128F256***"));
			SpxVerifyLoop(SphincsParameters::SPXS128F256, DEF_TEST_ITER, rngType);

			return MESSAGE;
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

	void AsymmetricSpeedTest::DlmGenerateLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType)
	{
		Dilithium asySgn(Params, PrngType);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asySgn.Generate();
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

	void AsymmetricSpeedTest::DlmSignLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> msg(32);
		std::vector<byte> sig(0);
		Dilithium asySgn(Params, PrngType);
		AsymmetricKeyPair* kp = asySgn.Generate();
		asySgn.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asySgn.Sign(msg, sig);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Signed " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " signed per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::DlmVerifyLoop(DilithiumParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		Dilithium asySgn(Params, PrngType);
		AsymmetricKeyPair* kp = asySgn.Generate();
		asySgn.Initialize(kp->PrivateKey());
		asySgn.Sign(msg1, sig);
		asySgn.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asySgn.Verify(sig, msg2);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Verified " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " verified per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::MlweDecryptLoop(MLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		ModuleLWE asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::MlweEncryptLoop(MLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		ModuleLWE asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::MlweGenerateLoop(MLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		ModuleLWE asyCpr(Params, PrngType);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asyCpr.Generate();
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

	void AsymmetricSpeedTest::MpkcDecryptLoop(MPKCParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		McEliece asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::MpkcEncryptLoop(MPKCParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		McEliece asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::MpkcGenerateLoop(MPKCParameters Params, size_t Loops, Prngs PrngType)
	{
		McEliece asyCpr(Params, PrngType);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asyCpr.Generate();
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

	void AsymmetricSpeedTest::NtruDecryptLoop(NTRUParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		NTRU asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::NtruEncryptLoop(NTRUParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		NTRU asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::NtruGenerateLoop(NTRUParameters Params, size_t Loops, Prngs PrngType)
	{
		NTRU asyCpr(Params, PrngType);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asyCpr.Generate();
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

	void AsymmetricSpeedTest::RlweDecryptLoop(RLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		RingLWE asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::RlweEncryptLoop(RLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		RingLWE asyCpr(Params, PrngType);
		AsymmetricKeyPair* kp;

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

	void AsymmetricSpeedTest::RlweGenerateLoop(RLWEParameters Params, size_t Loops, Prngs PrngType)
	{
		RingLWE asyCpr(Params, PrngType);
		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asyCpr.Generate();
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

	void AsymmetricSpeedTest::SpxGenerateLoop(SphincsParameters Params, size_t Loops, Prngs PrngType)
	{
		Sphincs asySgn(Params, PrngType);

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			AsymmetricKeyPair* kp = asySgn.Generate();
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

	void AsymmetricSpeedTest::SpxSignLoop(SphincsParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> msg(32, 0x80);
		std::vector<byte> sig(0);
		Sphincs asySgn(Params, PrngType);
		AsymmetricKeyPair* kp = asySgn.Generate();
		asySgn.Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asySgn.Sign(msg, sig);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;
		msg.clear();
		sig.clear();

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Signed " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " signed per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::SpxVerifyLoop(SphincsParameters Params, size_t Loops, Prngs PrngType)
	{
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		Sphincs asySgn(Params, PrngType);
		AsymmetricKeyPair* kp = asySgn.Generate();
		asySgn.Initialize(kp->PrivateKey());
		asySgn.Sign(msg1, sig);
		asySgn.Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			asySgn.Verify(sig, msg2);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(Loops);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Loops));
		std::string resp = std::string("Verified " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " verified per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	uint64_t AsymmetricSpeedTest::GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)Count;

		return (uint64_t)(sze / sec);
	}

	void AsymmetricSpeedTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
