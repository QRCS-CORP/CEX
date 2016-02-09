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
		const char* rhxEncoded[2] =
		{
			("531c234dfda625dc69eb31c86d895636"),	// 14 rounds
			("841c351399beef66939367b551bf7a2f")	// 22 rounds
		};
		HexConverter::Decode(rhxEncoded, 2, _rhxExpected);

		const char* shxEncoded[2] =
		{
			("e814f2bb7c55974020820d7f294b6bb0"),	// 32 rounds
			("96e3a5d177fd1b46efc976bdc4d54e44")	// 40 rounds
		};
		HexConverter::Decode(shxEncoded, 2, _shxExpected);

		const char* thxEncoded[2] =
		{
			("e97a3d1a8b61b0a939a3b95397f9b97a"),	// 16 rounds
			("00ee8bc0cb127f5af682872266a4f57f")	// 20 rounds
		};
		HexConverter::Decode(thxEncoded, 2, _thxExpected);

		for (unsigned int i = 0; i < _key.size(); i++)
			_key[i] = (byte)i;
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
	}
}