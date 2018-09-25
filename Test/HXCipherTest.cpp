#include "HXCipherTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/CTR.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string HXCipherTest::DESCRIPTION = "HX Cipher Known Answer Monte Carlo Tests.";
	const std::string HXCipherTest::FAILURE = "FAILURE! ";
	const std::string HXCipherTest::SUCCESS = "SUCCESS! HX tests have executed succesfully.";

	HXCipherTest::HXCipherTest()
		:
		m_iv(16),
		m_key(3),
		m_progressEvent(),
		m_rhxExp(0),
		m_shxExp(0)
	{
	}

	HXCipherTest::~HXCipherTest()
	{
	}

	const std::string HXCipherTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HXCipherTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HXCipherTest::Run()
	{
		try
		{
			Initialize();

			Common::CpuDetect detect;
#if defined(__AVX__)
			if (detect.AESNI())
			{
				// AES-256
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::None, m_key[0], m_rhxExp[0]);
				// original vectors: each variation of RHX/RSX with 256, 512, and 1024bit keys
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF256, m_key[0], m_rhxExp[1]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF256, m_key[1], m_rhxExp[2]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF256, m_key[2], m_rhxExp[3]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF512, m_key[0], m_rhxExp[4]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF512, m_key[1], m_rhxExp[5]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::HKDF512, m_key[2], m_rhxExp[6]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, m_key[0], m_rhxExp[7]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, m_key[1], m_rhxExp[8]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE256, m_key[2], m_rhxExp[9]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512, m_key[0], m_rhxExp[10]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512, m_key[1], m_rhxExp[11]);
				CipherMonteCarlo(BlockCiphers::AHX, BlockCipherExtensions::SHAKE512, m_key[2], m_rhxExp[12]);
				OnProgress(std::string("AHX: Passed AES-NI Monte Carlo tests.."));
			}
#endif
			// AES-256
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::None, m_key[0], m_rhxExp[0]);
			// original vectors: each variation of RHX/RSX with 256, 512, and 1024bit keys
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, m_key[0], m_rhxExp[1]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, m_key[1], m_rhxExp[2]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF256, m_key[2], m_rhxExp[3]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF512, m_key[0], m_rhxExp[4]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF512, m_key[1], m_rhxExp[5]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::HKDF512, m_key[2], m_rhxExp[6]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, m_key[0], m_rhxExp[7]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, m_key[1], m_rhxExp[8]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE256, m_key[2], m_rhxExp[9]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE512, m_key[0], m_rhxExp[10]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE512, m_key[1], m_rhxExp[11]);
			CipherMonteCarlo(BlockCiphers::RHX, BlockCipherExtensions::SHAKE512, m_key[2], m_rhxExp[12]);
			OnProgress(std::string("RHX: Passed RHX Monte Carlo tests.."));

			// Serpent-256
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::None, m_key[0], m_shxExp[0]);
			// original vectors: each variation of SHX/SSX with 256, 512, and 1024bit keys
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, m_key[0], m_shxExp[1]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, m_key[1], m_shxExp[2]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF256, m_key[2], m_shxExp[3]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF512, m_key[0], m_shxExp[4]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF512, m_key[1], m_shxExp[5]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::HKDF512, m_key[2], m_shxExp[6]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, m_key[0], m_shxExp[7]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, m_key[1], m_shxExp[8]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE256, m_key[2], m_shxExp[9]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE512, m_key[0], m_shxExp[10]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE512, m_key[1], m_shxExp[11]);
			CipherMonteCarlo(BlockCiphers::SHX, BlockCipherExtensions::SHAKE512, m_key[2], m_shxExp[12]);
			OnProgress(std::string("SHX: Passed SHX Monte Carlo tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void HXCipherTest::Initialize()
	{
		const std::vector<std::string> rhxexp =
		{
			std::string("EC5318C99B2793CA7AAFB87572E89DF7"),	// AES-256, standard
			std::string("5D9B6A94A84FF1F5E689AA07FD5C1C70"),	// RHX-256, HKDF(SHA2-256)
			std::string("DB808E5E524C8FDC6D8E01DAE6A6FC71"),	// RHX-512, HKDF(SHA2-256)
			std::string("C71779C21E3E5FD2046C16E78056120C"),	// RHX-1024, HKDF(SHA2-256)
			std::string("B58A8E4EACB6B4E49D5B1963B74D2775"),	// RHX-256, HKDF(SHA2-512)
			std::string("3C46444E9147B06C782EFD5E1EEAD120"),	// RHX-512, HKDF(SHA2-512)
			std::string("32E1F4B36C32466145577242A204D8FD"),	// RHX-1024, HKDF(SHA2-512)
			std::string("9379BEF8BB0564D96973DB9DF78AF406"),	// RSX-256, SHAKE-256
			std::string("71CB91605EC660A6A15CCDBB35C9F687"),	// RSX-512, SHAKE-256
			std::string("C8D1E9B796CDB3D05042B486ABE3168E"),	// RSX-1024, SHAKE-256
			std::string("236164000060515719FC1B5546E6AA1F"),	// RSX-256, SHAKE-512
			std::string("E2336FC624B0F016405CDC51B705ED22"),	// RSX-512, SHAKE-512
			std::string("58DB186CB703320081804FB45491C9CC")		// RSX-1024, SHAKE-512
		};
		HexConverter::Decode(rhxexp, 13, m_rhxExp);

		// Note: kat change with serpent move from BE to LE format
		const std::vector<std::string> shxexp =
		{
			std::string("5780E642D6775957E708CC7452D13D96"),	// Serpent-256, standard
			std::string("915174F04D2737CDD6B50C0656947C53"),	// SHX-256, HKDF(SHA2-256)
			std::string("CB410DFE0FF2B1FCA909226CAC9DCFFB"),	// SHX-512, HKDF(SHA2-256)
			std::string("C9370CE846BF22EEDF07C00000B7138D"),	// SHX-1024, HKDF(SHA2-256)
			std::string("2D87BD93CB72180BAE8A87A4D4D4E1A1"),	// SHX-256, HKDF(SHA2-512)
			std::string("510C8D4A37F63451ADE7ADE065C9A3B9"),	// SHX-512, HKDF(SHA2-512)
			std::string("462E1C16A76523F72FB26DA55E44BA8B"),	// SHX-1024, HKDF(SHA2-512)
			std::string("E5DFFAB57E0D5EA8FB681D5E29AAD30E"),	// SSX-256, SHAKE-256
			std::string("8E942EDD99ECC873266EF7EBBE9205F7"),	// SSX-512, SHAKE-256
			std::string("DE41CF2FB799AFA26170050A432B327E"),	// SSX-1024, SHAKE-256
			std::string("54AC04306DD24526A01E2B54FA16A4E9"),	// SSX-256, SHAKE-512
			std::string("34057F5A6C4F48E284FC977640135787"),	// SSX-512, SHAKE-512
			std::string("66BA4CFB7419013ABE1B5EB53B6912FE")		// SSX-1024, SHAKE-512
		};
		HexConverter::Decode(shxexp, 13, m_shxExp);

		m_key[0].resize(32);
		m_key[1].resize(64);
		m_key[2].resize(128);

		for (byte i = 0; i < 128; i++)
		{
			if (i < 16)
			{
				m_iv[i] = i;
			}
			if (i < 32)
			{
				m_key[0][i] = i;
			}
			if (i < 64)
			{
				m_key[1][i] = i;
			}

			m_key[2][i] = i;
		}
	}

	void HXCipherTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void HXCipherTest::CipherMonteCarlo(Enumeration::BlockCiphers BlockCipherType, Enumeration::BlockCipherExtensions CipherExtensionType, std::vector<byte> &Key, std::vector<byte> &Expected)
	{
		std::vector<byte> inp(16, 128);
		std::vector<byte> otp(16, 0);
		std::vector<byte> dec(16, 128);

		Key::Symmetric::SymmetricKey kp(Key, m_iv);
		Mode::CTR cpr1(BlockCipherType, CipherExtensionType);

		cpr1.Initialize(true, kp);
		MonteCarloEncrypt(&cpr1, inp, otp);

		if (otp != Expected)
		{
			throw TestException("RHX: Failed encryption test!");
		}

		cpr1.Initialize(false, kp);
		MonteCarloDecrypt(&cpr1, inp, otp);

		if (otp != dec)
		{
			throw TestException("RHX: Failed encryption test!");
		}
	}

	void HXCipherTest::MonteCarloDecrypt(ICipherMode* Cipher, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		for (size_t i = 0; i < MONTECARLO_ROUNDS; ++i)
		{
			Cipher->Transform(Output, 0, Input, 0, Output.size());
			std::memcpy(Output.data(), Input.data(), Output.size());
		}
	}

	void HXCipherTest::MonteCarloEncrypt(ICipherMode* Cipher, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		for (size_t i = 0; i < MONTECARLO_ROUNDS; ++i)
		{
			Cipher->Transform(Input, 0, Output, 0, Output.size());
			std::memcpy(Input.data(), Output.data(), Output.size());
		}
	}
}
