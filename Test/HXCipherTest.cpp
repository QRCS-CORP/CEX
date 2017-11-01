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
		const char* rhxEncoded[3] =
		{
			("a36e01f66404b6af9ed09ea6e4faaff2"),	// hkdf extended 14 rounds  old: 2ac5dd436cb2a1c976b25a1edaf1f650
			("43b4418a1d0b32aeff34df0c189556c4"),	// hkdf extended 22 rounds  old: 497bef5ccb4faee957b7946705c3dc10
			("05e57d29a9f646d840c070ed3a17da53")	// standard 512 key, 22 rounds  old: same
		};
		HexConverter::Decode(rhxEncoded, 3, m_rhxExpected);

		// Note: kat change with serpent move from BE to LE format
		const char* shxEncoded[3] =
		{
			("b47cc603a10d3c41d93bb98352611635"),	// hkdf extended 32 rounds  old: da87958d7644a9409d39bf8abb1f68a5
			("eb0942fc83099a30835b479bde4bcf31"),	// hkdf extended 40 rounds  old: 631cfb750c1dccd2af8509af8eed9ee6
			("71c6c606b65798621dd19fa0f5e7acb0")	// standard 512 key, 40 rounds  old: same
		};
		HexConverter::Decode(shxEncoded, 3, m_shxExpected);

		const char* thxEncoded[3] =
		{
			("b8ee1fec4b6caf2607a84b52934fd3d3"),	// hkdf extended 16 rounds  old: 0b97de0f11367d25ad45d3293072e2bb
			("1870b32752892a6857f798751a8cc5fd"),	// hkdf extended 20 rounds  old: e0ec1b5807ed879a88a18244237e8bad
			("32626075c43a30a56aa4cc5ddbf58179")	// standard 512 key, 20 rounds  old: same
		};
		HexConverter::Decode(thxEncoded, 3, m_thxExpected);

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