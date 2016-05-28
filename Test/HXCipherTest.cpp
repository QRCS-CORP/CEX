#include "HXCipherTest.h"
#include "CTR.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"
#include "SHA512.h"

#if defined(AESNI_AVAILABLE)
#include "AHX.h"
#endif

namespace Test
{
	std::string HXCipherTest::Run()
	{
		try
		{
			Initialize();
#if defined(AESNI_AVAILABLE)
			AHXMonteCarlo();
			OnProgress("AHX: Passed AES-NI Monte Carlo tests..");
#endif
			RHXMonteCarlo();
			OnProgress("RHX: Passed RHX Monte Carlo tests..");
			SHXMonteCarlo();
			OnProgress("SHX: Passed SHX Monte Carlo tests..");
			THXMonteCarlo();
			OnProgress("THX: Passed THX Monte Carlo tests..");

			return SUCCESS;
		}
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void HXCipherTest::Initialize()
	{
		const char* rhxEncoded[4] =
		{
			("2ac5dd436cb2a1c976b25a1edaf1f650"),	// hkdf extended 14 rounds
			("497bef5ccb4faee957b7946705c3dc10"),	// hkdf extended 22 rounds 
			("05e57d29a9f646d840c070ed3a17da53"),	// standard 512 key, 22 rounds
			("46af483df6bbaf9e3a0aa8c182011752bb8bab6f2ebc4cd424407994f6ff6534")	// standard 512 key, 22 rounds, 32 byte block
		};
		HexConverter::Decode(rhxEncoded, 4, m_rhxExpected);

		const char* shxEncoded[3] =
		{
			("6f4309f375cad2e65fcfa28091ceed17"),	// hkdf extended 32 rounds
			("9dcd48706592211eb48d659b9df8824f"),	// hkdf extended 40 rounds
			("9c41b8c6fba7154b95afc7c8a5449687")	// standard 512 key, 40 rounds
		};
		HexConverter::Decode(shxEncoded, 3, m_shxExpected);

		const char* thxEncoded[3] =
		{
			("0b97de0f11367d25ad45d3293072e2bb"),	// hkdf extended 16 rounds
			("e0ec1b5807ed879a88a18244237e8bad"),	// hkdf extended 20 rounds
			("32626075c43a30a56aa4cc5ddbf58179")	// standard 512 key, 20 rounds
		};
		HexConverter::Decode(thxEncoded, 3, m_thxExpected);

		for (unsigned int i = 0; i < m_key.size(); i++)
			m_key[i] = (byte)i;
		for (unsigned int i = 0; i < m_key2.size(); i++)
			m_key2[i] = (byte)i;
		for (unsigned int i = 0; i < m_iv.size(); i++)
			m_iv[i] = (byte)i;
	}

	void HXCipherTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}

	void HXCipherTest::AHXMonteCarlo()
	{
#if defined(AESNI_AVAILABLE)
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// AHX, 14 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::AHX* eng = new CEX::Cipher::Symmetric::Block::AHX(&digest, 14);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}
			if (outBytes != m_rhxExpected[0])
				throw std::string("AHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("AHX: Failed decryption test!");
		}
		// AHX, 22 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::AHX* eng = new CEX::Cipher::Symmetric::Block::AHX(&digest, 22);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[1])
				throw std::string("AHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("AHX: Failed decryption test!");
		}

		// AHX, 22 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::AHX* eng = new CEX::Cipher::Symmetric::Block::AHX(22);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key2, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[2])
				throw std::string("AHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("AHX: Failed decryption test!");
		}
#endif
	}

	void HXCipherTest::RHXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// RHX, 14 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX(&digest, 14, 16);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}
			if (outBytes != m_rhxExpected[0])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("RHX: Failed decryption test!");
		}
		// RHX, 22 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX(&digest, 22, 16);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[1])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("RHX: Failed decryption test!");
		}

		// RHX, 22 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX(16, 22);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key2, m_iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[2])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("RHX: Failed decryption test!");
		}

		// RHX, 22 rounds, 32 byte block, standard key schedule
		{
			inpBytes.resize(32);
			outBytes.resize(32);
			decBytes.resize(32);
			std::vector<byte> iv(32);

			for (unsigned int i = 0; i < iv.size(); i++)
				iv[i] = (byte)i;

			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX(32, 22);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(m_key2, iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_rhxExpected[3])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("RHX: Failed decryption test!");
		}
	}

	void HXCipherTest::SHXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// SHX, 32 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::SHX* eng = new CEX::Cipher::Symmetric::Block::SHX(&digest, 32);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[0])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("SHX: Failed decryption test!");
		}
		// SHX, 40 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::SHX* eng = new CEX::Cipher::Symmetric::Block::SHX(&digest, 40);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[1])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("SHX: Failed decryption test!");
		}
		// SHX, 40 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::SHX* eng = new CEX::Cipher::Symmetric::Block::SHX(40);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key2, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_shxExpected[2])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("SHX: Failed decryption test!");
		}
	}

	void HXCipherTest::THXMonteCarlo()
	{
		std::vector<byte> inpBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);

		// THX, 16 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::THX* eng = new CEX::Cipher::Symmetric::Block::THX(&digest, 16);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[0])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("THX: Failed decryption test!");
		}
		// THX, 20 rounds
		{
			CEX::Digest::SHA512 digest;
			CEX::Cipher::Symmetric::Block::THX* eng = new CEX::Cipher::Symmetric::Block::THX(&digest, 20);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[1])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("THX: Failed decryption test!");
		}
		// THX, 20 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::THX* eng = new CEX::Cipher::Symmetric::Block::THX(20);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(m_key2, m_iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], outBytes.size());
			}

			if (outBytes != m_thxExpected[2])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], outBytes.size());
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("THX: Failed decryption test!");
		}
	}
}