#include "HXCipherTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/CTR.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"
#include "../CEX/SHX.h"
#include "../CEX/THX.h"
#include "../CEX/SHA512.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string HXCipherTest::DESCRIPTION = "HX Cipher Known Answer Monte Carlo Tests.";
	const std::string HXCipherTest::FAILURE = "FAILURE! ";
	const std::string HXCipherTest::SUCCESS = "SUCCESS! HX tests have executed succesfully.";

	HXCipherTest::HXCipherTest()
		:
		m_iv(16),
		m_key(128),
		m_key2(64),
		m_progressEvent(),
		m_rhxExpected(0),
		m_shxExpected(0),
		m_thxExpected(0)
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
				AHXMonteCarlo();
				OnProgress(std::string("AHX: Passed AES-NI Monte Carlo tests.."));
			}
#endif
			RHXMonteCarlo();
			OnProgress(std::string("RHX: Passed RHX Monte Carlo tests.."));
			SHXMonteCarlo();
			OnProgress(std::string("SHX: Passed SHX Monte Carlo tests.."));
			THXMonteCarlo();
			OnProgress(std::string("THX: Passed THX Monte Carlo tests.."));

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
			std::string("A36E01F66404B6AF9ED09EA6E4FAAFF2"),	// hkdf extended 14 rounds  old: 2ac5dd436cb2a1c976b25a1edaf1f650
			std::string("43B4418A1D0B32AEFF34DF0C189556C4"),	// hkdf extended 22 rounds  old: 497bef5ccb4faee957b7946705c3dc10
			std::string("05E57D29A9F646D840C070ED3A17DA53")	// standard 512 key, 22 rounds  old: same
		};
		HexConverter::Decode(rhxexp, 3, m_rhxExpected);

		// Note: kat change with serpent move from BE to LE format
		const std::vector<std::string> shxexp =
		{
			std::string("B47CC603A10D3C41D93BB98352611635"),	// hkdf extended 32 rounds  old: da87958d7644a9409d39bf8abb1f68a5
			std::string("EB0942FC83099A30835B479BDE4BCF31"),	// hkdf extended 40 rounds  old: 631cfb750c1dccd2af8509af8eed9ee6
			std::string("71C6C606B65798621DD19FA0F5E7ACB0")	// standard 512 key, 40 rounds  old: same
		};
		HexConverter::Decode(shxexp, 3, m_shxExpected);

		const std::vector<std::string> thxexp =
		{
			std::string("B8EE1FEC4B6CAF2607A84B52934FD3D3"),	// hkdf extended 16 rounds  old: 0b97de0f11367d25ad45d3293072e2bb
			std::string("1870B32752892A6857F798751A8CC5FD"),	// hkdf extended 20 rounds  old: e0ec1b5807ed879a88a18244237e8bad
			std::string("32626075C43A30A56AA4CC5DDBF58179")	// standard 512 key, 20 rounds  old: same
		};
		HexConverter::Decode(thxexp, 3, m_thxExpected);

		for (byte i = 0; i < m_key.size(); i++)
		{
			m_key[i] = i;
		}
		for (byte i = 0; i < m_key2.size(); i++)
		{
			m_key2[i] = i;
		}
		for (byte i = 0; i < m_iv.size(); i++)
		{
			m_iv[i] = i;
		}
	}

	void HXCipherTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

#if defined(__AVX__)
	void HXCipherTest::AHXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// AHX, 14 rounds
		{
			Digest::SHA512 digest;
			AHX* eng = new AHX(&digest, 14);
			//std::vector<byte> info(eng->DistributionCodeMax(), 0);
			//eng->DistributionCode() = info;
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[0])
			{
				throw TestException("AHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("AHX: Failed decryption test!");
			}
		}
		// AHX, 22 rounds
		{
			Digest::SHA512 digest;
			AHX* eng = new AHX(&digest, 22);
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[1])
			{
				throw TestException("AHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("AHX: Failed decryption test!");
			}
		}

		// AHX, 22 rounds, standard key schedule
		{
			AHX* eng = new AHX();
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key2, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[2])
			{
				throw TestException("AHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("AHX: Failed decryption test!");
			}
		}
	}
#endif

	void HXCipherTest::RHXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// RHX, 14 rounds
		{
			Digest::SHA512 digest;
			RHX* eng = new RHX(&digest, 14);
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}
			if (outBytes != m_rhxExpected[0])
			{
				throw TestException("RHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("RHX: Failed decryption test!");
			}
		}
		// RHX, 22 rounds
		{
			Digest::SHA512 digest;
			RHX* eng = new RHX(&digest, 22);
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[1])
			{
				throw TestException("RHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("RHX: Failed decryption test!");
			}
		}

		// RHX, 22 rounds, standard key schedule
		{
			RHX* eng = new RHX();
			Mode::CTR cipher(eng);
			Key::Symmetric::SymmetricKey k(m_key2, m_iv);
			cipher.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[2])
			{
				throw TestException("RHX: Failed encryption test!");
			}

			cipher.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("RHX: Failed decryption test!");
			}
		}
	}

	void HXCipherTest::SHXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// SHX, 32 rounds
		{
			Digest::SHA512 digest;
			SHX* eng = new SHX(&digest, 32);
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[0])
			{
				throw TestException("SHX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("SHX: Failed decryption test!");
			}
		}
		// SHX, 40 rounds
		{
			Digest::SHA512 digest;
			SHX* eng = new SHX(&digest, 40);
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[1])
			{
				throw TestException("SHX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("SHX: Failed decryption test!");
			}
		}
		// SHX, 32 rounds, standard key schedule
		{
			SHX* eng = new SHX();
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key2, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[2])
			{
				throw TestException("SHX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("SHX: Failed decryption test!");
			}
		}
	}

	void HXCipherTest::THXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// THX, 16 rounds
		{
			Digest::SHA512 digest;
			THX* eng = new THX(&digest, 16);
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[0])
			{
				throw TestException("THX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("THX: Failed decryption test!");
			}
		}
		// THX, 20 rounds
		{
			Digest::SHA512 digest;
			THX* eng = new THX(&digest, 20);
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[1])
			{
				throw TestException("THX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("THX: Failed decryption test!");
			}
		}
		// THX, 20 rounds, standard key schedule
		{
			THX* eng = new THX(Digests::None, 20);
			Mode::CTR engine(eng);
			Key::Symmetric::SymmetricKey k(m_key2, m_iv);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, 0, outBytes, 0, outBytes.size());
				std::memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[2])
			{
				throw TestException("THX: Failed encryption test!");
			}

			engine.Initialize(false, k);

			for (size_t i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, 0, inpBytes, 0, outBytes.size());
				std::memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
			{
				throw TestException("THX: Failed decryption test!");
			}
		}
	}
}