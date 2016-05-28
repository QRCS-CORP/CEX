#include "HXCipherTest.h"
#include "CTR.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"
#include "SHA512.h"

namespace Test
{
	std::string HXCipherTest::Run()
	{
		try
		{
			Initialize();

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
		const char* rhxEncoded[3] =
		{
			("2ac5dd436cb2a1c976b25a1edaf1f650"),	// hkdf extended 14 rounds
			("497bef5ccb4faee957b7946705c3dc10"),	// hkdf extended 22 rounds 
			("05e57d29a9f646d840c070ed3a17da53")	// standard 512 key, 22 rounds
		};
		HexConverter::Decode(rhxEncoded, 3, _rhxExpected);

		const char* shxEncoded[3] =
		{
			("6f4309f375cad2e65fcfa28091ceed17"),	// hkdf extended 32 rounds
			("9dcd48706592211eb48d659b9df8824f"),	// hkdf extended 40 rounds
			("9c41b8c6fba7154b95afc7c8a5449687")	// standard 512 key, 40 rounds
		};
		HexConverter::Decode(shxEncoded, 3, _shxExpected);

		const char* thxEncoded[3] =
		{
			("0b97de0f11367d25ad45d3293072e2bb"),	// hkdf extended 16 rounds
			("e0ec1b5807ed879a88a18244237e8bad"),	// hkdf extended 20 rounds
			("32626075c43a30a56aa4cc5ddbf58179")	// standard 512 key, 20 rounds
		};
		HexConverter::Decode(thxEncoded, 3, _thxExpected);

		for (unsigned int i = 0; i < _key.size(); i++)
			_key[i] = (byte)i;
		for (unsigned int i = 0; i < _key2.size(); i++)
			_key2[i] = (byte)i;
		for (unsigned int i = 0; i < _iv.size(); i++)
			_iv[i] = (byte)i;
	}

	void HXCipherTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
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
			CEX::Common::KeyParams k(_key, _iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}
			if (outBytes != _rhxExpected[0])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
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
			CEX::Common::KeyParams k(_key, _iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _rhxExpected[1])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("RHX: Failed decryption test!");
		}

		// RHX, 22 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX(16, 22);
			CEX::Cipher::Symmetric::Block::Mode::CTR cipher(eng);
			CEX::Common::KeyParams k(_key2, _iv);
			cipher.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _rhxExpected[2])
				throw std::string("RHX: Failed encryption test!");

			cipher.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				cipher.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
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
			CEX::Common::KeyParams k(_key, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _shxExpected[0])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
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
			CEX::Common::KeyParams k(_key, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _shxExpected[1])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("SHX: Failed decryption test!");
		}
		// SHX, 40 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::SHX* eng = new CEX::Cipher::Symmetric::Block::SHX(40);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(_key2, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _shxExpected[2])
				throw std::string("SHX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
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
			CEX::Common::KeyParams k(_key, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _thxExpected[0])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
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
			CEX::Common::KeyParams k(_key, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _thxExpected[1])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("THX: Failed decryption test!");
		}
		// THX, 20 rounds, standard key schedule
		{
			CEX::Cipher::Symmetric::Block::THX* eng = new CEX::Cipher::Symmetric::Block::THX(20);
			CEX::Cipher::Symmetric::Block::Mode::CTR engine(eng);
			CEX::Common::KeyParams k(_key2, _iv);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(inpBytes, outBytes);
				memcpy(&inpBytes[0], &outBytes[0], 16);
			}

			if (outBytes != _thxExpected[2])
				throw std::string("THX: Failed encryption test!");

			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 100; i++)
			{
				engine.Transform(outBytes, inpBytes);
				memcpy(&outBytes[0], &inpBytes[0], 16);
			}
			delete eng;

			if (outBytes != decBytes)
				throw std::string("THX: Failed decryption test!");
		}
	}
}
