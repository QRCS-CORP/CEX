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
	using Tools::IntegerTools;

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
			const std::string TSTITRF = IntegerTools::ToString(TEST_ITERATIONSF);
			const std::string TSTITRL = IntegerTools::ToString(TEST_ITERATIONSL);

			// Test the asymmetric ciphers
			OnProgress(std::string("### Asymmetric Cipher Speed Tests:"));
			OnProgress(std::string(""));

			// Kyber
			OnProgress(std::string("***Kyber Generating " + TSTITRF + " Keypairs using parameter KYBERS53168***"));
			CipherGenerateLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::KYBERS53168, TEST_ITERATIONSF);

			OnProgress(std::string("***Kyber Encrypting " + TSTITRF + " messages using parameter KYBERS53168***"));
			CipherEncryptLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::KYBERS53168, TEST_ITERATIONSF);

			OnProgress(std::string("***Kyber Decrypting " + TSTITRF + " messages using parameter KYBERS53168***"));
			CipherDecryptLoop(AsymmetricCiphers::Kyber, AsymmetricParameters::KYBERS53168, TEST_ITERATIONSF);

			// McEliece
			OnProgress(std::string("***McEliece Generating " + TSTITRL + " Keypairs using parameter MPKCS3N4608T96***"));
			CipherGenerateLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS3N4608T96, TEST_ITERATIONSL);

			OnProgress(std::string("***McEliece Encrypting " + TSTITRL + " messages using parameter MPKCS3N4608T96***"));
			CipherEncryptLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS3N4608T96, TEST_ITERATIONSL);

			OnProgress(std::string("***McEliece Decrypting " + TSTITRL + " messages using parameter MPKCS3N4608T96***"));
			CipherDecryptLoop(AsymmetricCiphers::McEliece, AsymmetricParameters::MPKCS3N4608T96, TEST_ITERATIONSL);

			// Signature schemes //
			OnProgress(std::string("### Asymmetric Signature Scheme Speed Tests:"));
			OnProgress(std::string(""));

			// Dilithium
			OnProgress(std::string("***Dilithium Generating " + TSTITRL + " Keypairs using parameter DLTMS3P4016***"));
			SignerGenerateLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS3P4016, TEST_ITERATIONSF);

			OnProgress(std::string("***Dilithium Signing " + TSTITRL + " messages using parameter DLTMS3P4016***"));
			SignerSignLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS3P4016, TEST_ITERATIONSF);

			OnProgress(std::string("***Dilithium Verifying " + TSTITRL + " messages using parameter DLTMS3P4016***"));
			SignerVerifyLoop(AsymmetricSigners::Dilithium, AsymmetricParameters::DLTMS3P4016, TEST_ITERATIONSF);

			// SPHINCS+
			OnProgress(std::string("***SPHINCS+ Generating " + TSTITRL + " Keypairs using parameter SPXPS1S128SHAKE***"));
			SignerGenerateLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE, TEST_ITERATIONSL);

			OnProgress(std::string("***SPHINCS+ Signing " + TSTITRL + " messages using parameter SPXPS1S128SHAKE***"));
			SignerSignLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE, TEST_ITERATIONSL);

			OnProgress(std::string("***SPHINCS+ Verifying " + TSTITRL + " messages using parameter SPXPS1S128SHAKE***"));
			SignerVerifyLoop(AsymmetricSigners::SphincsPlus, AsymmetricParameters::SPXPS1S128SHAKE, TEST_ITERATIONSL);

			// XMSS
			OnProgress(std::string("***XMSS Generating " + TSTITRL + " Keypairs using parameter XMSSSHA2256H10***"));
			SignerGenerateLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA2256H10, TEST_ITERATIONSL);

			OnProgress(std::string("***XMSS Signing " + TSTITRL + " messages using parameter XMSSSHA2256H10***"));
			SignerSignLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA2256H10, TEST_ITERATIONSL);

			OnProgress(std::string("***XMSS Verifying " + TSTITRL + " messages using parameter XMSSSHA2256H10***"));
			SignerVerifyLoop(AsymmetricSigners::XMSS, AsymmetricParameters::XMSSSHA2256H10, TEST_ITERATIONSL);

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

	void AsymmetricSpeedTest::CipherDecryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations)
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec1(32);
		std::vector<uint8_t> sec2(32);
		AsymmetricKeyPair* kp;
		IAsymmetricCipher* pcpr;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);
		kp = pcpr->Generate();
		pcpr->Initialize(kp->PublicKey());
		pcpr->Encapsulate(cpt, sec1);
		pcpr->Initialize(kp->PrivateKey());

		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			pcpr->Decapsulate(cpt, sec2);
		}

		dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Decrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " derypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::CipherEncryptLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations)
	{
		std::vector<uint8_t> cpt(0);
		std::vector<uint8_t> sec(32);
		AsymmetricKeyPair* kp;
		IAsymmetricCipher* pcpr;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);
		kp = pcpr->Generate();
		pcpr->Initialize(kp->PublicKey());
		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			pcpr->Encapsulate(cpt, sec);
		}

		dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Encrypted " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " encrypted per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::CipherGenerateLoop(AsymmetricCiphers CipherType, AsymmetricParameters Parameters, size_t Iterations)
	{
		IAsymmetricCipher* pcpr;
		AsymmetricKeyPair* kp;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		pcpr = AsymmetricCipherFromName::GetInstance(CipherType, Parameters);
		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			kp = pcpr->Generate();
			delete kp;
		}

		dur = TestUtils::GetTimeMs64() - start;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	//~~~Signature Schemes~~~//

	void AsymmetricSpeedTest::SignerGenerateLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations)
	{
		IAsymmetricSigner* psnr;
		AsymmetricKeyPair* kp;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);
		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			kp = psnr->Generate();
			delete kp;
		}

		dur = TestUtils::GetTimeMs64() - start;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Generated " + nlen + " keypairs in " + secs + " seconds, avg. " + ksec + " generated per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::SignerSignLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations)
	{
		std::vector<uint8_t> msg(32);
		std::vector<uint8_t> sig(0);
		IAsymmetricSigner* psnr;
		AsymmetricKeyPair* kp;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);
		kp = psnr->Generate();
		psnr->Initialize(kp->PrivateKey());

		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			psnr->Sign(msg, sig);
		}

		dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Signed " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " signed per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	void AsymmetricSpeedTest::SignerVerifyLoop(AsymmetricSigners SignerType, AsymmetricParameters Parameters, size_t Iterations)
	{
		std::vector<uint8_t> msg1(32);
		std::vector<uint8_t> msg2(0);
		std::vector<uint8_t> sig(0);
		IAsymmetricSigner* psnr;
		AsymmetricKeyPair* kp;
		std::string nlen;
		std::string secs;
		std::string ksec;
		std::string resp;
		uint64_t dur;
		uint64_t start;
		size_t i;

		psnr = AsymmetricSignerFromName::GetInstance(SignerType, Parameters);
		kp = psnr->Generate();
		psnr->Initialize(kp->PrivateKey());
		psnr->Sign(msg1, sig);
		psnr->Initialize(kp->PublicKey());

		start = TestUtils::GetTimeMs64();

		for (i = 0; i < Iterations; ++i)
		{
			psnr->Verify(sig, msg2);
		}

		dur = TestUtils::GetTimeMs64() - start;
		delete kp;
		nlen = TestUtils::ToString(Iterations);
		secs = TestUtils::ToString(static_cast<double>(dur) / 1000.0);
		ksec = TestUtils::ToString(GetUnitsPerSecond(dur, Iterations));
		resp = std::string("Verified " + nlen + " messages in " + secs + " seconds, avg. " + ksec + " verified per second");

		OnProgress(resp);
		OnProgress(std::string(""));
	}

	uint64_t AsymmetricSpeedTest::GetUnitsPerSecond(uint64_t DurationTicks, uint64_t Count)
	{
		double sec;
		double sze;

		sec = static_cast<double>(DurationTicks) / 1000.0;
		sze = static_cast<double>(Count);

		return static_cast<uint64_t>(sze / sec);
	}

	void AsymmetricSpeedTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
