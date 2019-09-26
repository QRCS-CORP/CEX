#include "AsymmetricSpeedTest.h"
#include "../CEX/AsymmetricKey.h"
#include "../CEX/AsymmetricKeyPair.h"
#include "../CEX/AsymmetricCipherFromName.h"
#include "../CEX/AsymmetricSignerFromName.h"
#include "../CEX/IAsymmetricCipher.h"
#include "../CEX/IAsymmetricSigner.h"
#include "../CEX/IntegerTools.h"

namespace Test
{
	using Asymmetric::AsymmetricKey;
	using Asymmetric::AsymmetricKeyPair;
	using Helper::AsymmetricCipherFromName;
	using Helper::AsymmetricSignerFromName;
	using Asymmetric::Encrypt::IAsymmetricCipher;
	using Asymmetric::Sign::IAsymmetricSigner;
	using Utility::IntegerTools;

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
			const std::string TSTITR = IntegerTools::ToString(TEST_ITERATIONS);

			// Test the asymmetric ciphers
			OnProgress(std::string("### Asymmetric Cipher Speed Tests:"));
			OnProgress(std::string(""));

			// NewHope
			OnProgress(std::string("***NewHope Generating " + TSTITR + " Keypairs using parameter RLWES1Q12289N1024***"));
			CipherGenerateLoop(AsymmetricCiphers::NewHope, AsymmetricParameters::RLWES1Q12289N1024);

			OnProgress(std::string("***NewHope Encrypting " + TSTITR + " messages using parameter RLWES1Q12289N1024***"));
			CipherEncryptLoop(AsymmetricCiphers::NewHope, AsymmetricParameters::RLWES1Q12289N1024);

			OnProgress(std::string("***NewHope Decrypting " + TSTITR + " messages using parameter RLWES1Q12289N1024***"));
			CipherDecryptLoop(AsymmetricCiphers::NewHope, AsymmetricParameters::RLWES1Q12289N1024);

			// McEliece
			OnProgress(std::string("***McEliece Generating " + TSTITR + " Keypairs using parameter MPKCS1N4096T62***"));
			CipherGenerateLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS1N4096T62);

			OnProgress(std::string("***McEliece Encrypting " + TSTITR + " messages using parameter MPKCS1N4096T62***"));
			CipherEncryptLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS1N4096T62);

			OnProgress(std::string("***McEliece Decrypting " + TSTITR + " messages using parameter MPKCS1N4096T62***"));
			CipherDecryptLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS1N4096T62);

			// Kyber
			OnProgress(std::string("***Kyber Generating " + TSTITR + " Keypairs using parameter MLWES2Q3329N256***"));
			CipherGenerateLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::MLWES2Q3329N256);

			OnProgress(std::string("***Kyber Encrypting " + TSTITR + " messages using parameter MLWES2Q3329N256***"));
			CipherEncryptLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::MLWES2Q3329N256);

			OnProgress(std::string("***Kyber Decrypting " + TSTITR + " messages using parameter MLWES2Q3329N256***"));
			CipherDecryptLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::MLWES2Q3329N256);

			// NTRU-Prime
			OnProgress(std::string("***NTRU-SPrime Generating " + TSTITR + " Keypairs using parameter NTRUS2SQ4591N761***"));
			CipherGenerateLoop(AsymmetricCiphers::NTRUPrime, AsymmetricParameters::NTRUS1SQ4621N653);

			OnProgress(std::string("***NTRU-SPrime Encrypting " + TSTITR + " messages using parameter NTRUS2SQ4591N761***"));
			CipherEncryptLoop(AsymmetricCiphers::NTRUPrime, AsymmetricParameters::NTRUS1SQ4621N653);

			OnProgress(std::string("***NTRU-SPrime Decrypting " + TSTITR + " messages using parameter NTRUS2SQ4591N761***"));
			CipherDecryptLoop(AsymmetricCiphers::NTRUPrime, AsymmetricParameters::NTRUS1SQ4621N653);

			// Signature schemes
			OnProgress(std::string("### Asymmetric Signature Scheme Speed Tests:"));
			OnProgress(std::string(""));

			// Dilithium
			OnProgress(std::string("***Dilithium Generating " + TSTITR + " Keypairs using parameter DLTMS2N256Q8380417***"));
			SignerGenerateLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS2N256Q8380417);

			OnProgress(std::string("***Dilithium Signing " + TSTITR + " messages using parameter DLTMS2N256Q8380417***"));
			SignerSignLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS2N256Q8380417);

			OnProgress(std::string("***Dilithium Verifying " + TSTITR + " messages using parameter DLTMS2N256Q8380417***"));
			SignerVerifyLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS2N256Q8380417);

			// Rainbow
			OnProgress(std::string("***Rainbow Generating " + TSTITR + " Keypairs using parameter RNBWS1S128SHAKE256***"));
			SignerGenerateLoop(AsymmetricSigners::Rainbow, AsymmetricParameters::RNBWS1S128SHAKE256);

			OnProgress(std::string("***Rainbow Signing " + TSTITR + " messages using parameter RNBWS1S128SHAKE256***"));
			SignerSignLoop(AsymmetricSigners::Rainbow, AsymmetricParameters::RNBWS1S128SHAKE256);

			OnProgress(std::string("***Rainbow Verifying " + TSTITR + " messages using parameter RNBWS1S128SHAKE256***"));
			SignerVerifyLoop(AsymmetricSigners::Rainbow, AsymmetricParameters::RNBWS1S128SHAKE256);

			// SPHINCS+
			OnProgress(std::string("***SPHINCS+ Generating " + TSTITR + " Keypairs using parameter SPXPS1S128SHAKE***"));
			SignerGenerateLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE);

			OnProgress(std::string("***SPHINCS+ Signing " + TSTITR + " messages using parameter SPXPS1S128SHAKE***"));
			SignerSignLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE);

			OnProgress(std::string("***SPHINCS+ Verifying " + TSTITR + " messages using parameter SPXPS1S128SHAKE***"));
			SignerVerifyLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE);

			// XMSS
			OnProgress(std::string("***XMSS Generating " + TSTITR + " Keypairs using parameter XMSSSHA256H10***"));
			SignerGenerateLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA256H10);

			OnProgress(std::string("***XMSS Signing " + TSTITR + " messages using parameter XMSSSHA256H10***"));
			SignerSignLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA256H10);

			OnProgress(std::string("***XMSS Verifying " + TSTITR + " messages using parameter XMSSSHA256H10***"));
			SignerVerifyLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA256H10);

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

	//~~~Ciphers~~~//

	void AsymmetricSpeedTest::CipherDecryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec1(32);
		std::vector<byte> sec2(32);
		AsymmetricKeyPair* kp;
		IAsymmetricCipher* pcpr;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);
		kp = pcpr->Generate();
		pcpr->Initialize(kp->PublicKey());
		pcpr->Encapsulate(cpt, sec1);
		pcpr->Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			pcpr->Decapsulate(cpt, sec2);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Decrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " derypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::CipherEncryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters)
	{
		std::vector<byte> cpt(0);
		std::vector<byte> sec(32);
		AsymmetricKeyPair* kp;
		IAsymmetricCipher* pcpr;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);
		kp = pcpr->Generate();
		pcpr->Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			pcpr->Encapsulate(cpt, sec);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		delete kp;

		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::CipherGenerateLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters)
	{
		uint64_t start = TestUtils::GetTimeMs64();
		IAsymmetricCipher* pcpr;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			AsymmetricKeyPair* kp = pcpr->Generate();
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	//~~~Signature Schemes~~~//

	void AsymmetricSpeedTest::SignerGenerateLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters)
	{
		uint64_t start = TestUtils::GetTimeMs64();
		IAsymmetricSigner* psnr;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			AsymmetricKeyPair* kp = psnr->Generate();
			delete kp;
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;

		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::SignerSignLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters)
	{
		std::vector<byte> msg(32);
		std::vector<byte> sig(0);
		IAsymmetricSigner* psnr;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);
		AsymmetricKeyPair* kp = psnr->Generate();
		psnr->Initialize(kp->PrivateKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			psnr->Sign(msg, sig);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Signed " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " signed per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::SignerVerifyLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters)
	{
		std::vector<byte> msg1(32);
		std::vector<byte> msg2(0);
		std::vector<byte> sig(0);
		IAsymmetricSigner* psnr;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);
		AsymmetricKeyPair* kp = psnr->Generate();
		psnr->Initialize(kp->PrivateKey());
		psnr->Sign(msg1, sig);
		psnr->Initialize(kp->PublicKey());

		uint64_t start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < TEST_ITERATIONS; ++i)
		{
			psnr->Verify(sig, msg2);
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		std::string nlen = TestUtils::ToString(TEST_ITERATIONS);
		std::string secs = TestUtils::ToString((double)dur / 1000.0);
		std::string ksec = TestUtils::ToString(GetUnitsPerSecond(dur, TEST_ITERATIONS));
		std::string resp = std::string("Verified " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " verified per second");

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
