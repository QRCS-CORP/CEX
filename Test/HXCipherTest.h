#ifndef _CEXTEST_HXCIPHERTEST_H
#define _CEXTEST_HXCIPHERTEST_H

#include "ITest.h"
#include "KeyParams.h"
#include "CTR.h"
#include "RHX.h"
#include "SHX.h"
#include "THX.h"

namespace Test
{
	using namespace CEX::Cipher::Symmetric::Block;
	using CEX::Cipher::Symmetric::Block::Mode::CTR;
	using CEX::Common::KeyParams;
	using CEX::Digest::SHA512;

	/// <summary>
	/// HX Cipher Known Answer Monte Carlo Tests.
	/// <para>Vectors generated from the CEX .Net version.</para>
	/// </summary>
	class HXCipherTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "HX Cipher Known Answer Monte Carlo Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! HX tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<std::vector<byte>> _rhxExpected;
		std::vector<std::vector<byte>> _shxExpected;
		std::vector<std::vector<byte>> _thxExpected;
		std::vector<byte> _key;
		std::vector<byte> _iv;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compares known answer HX Cipher vectors for equality
		/// </summary>
		HXCipherTest()
			:
			_key(192, 0),
			_iv(16,0)
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
				_key[i] = i;
			for (unsigned int i = 0; i < _iv.size(); i++)
				_iv[i] = i;
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~HXCipherTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
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

	private:
		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}

		void RHXMonteCarlo()
		{
			std::vector<byte> inpBytes(16, 0);
			std::vector<byte> outBytes(16, 0);
			std::vector<byte> decBytes(16, 0);

			// RHX, 14 rounds
			{
				SHA512 digest;
				RHX* eng = new RHX(&digest, 14, 16);
				CTR cipher(eng);
				KeyParams k(_key, _iv);
				cipher.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					cipher.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}
				if (outBytes != _rhxExpected[0])
					throw std::string("RHX: Failed encryption test!");

				cipher.Initialize(false, k);

				for (int i = 0; i != 100; i++)
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
				SHA512 digest;
				RHX* eng = new RHX(&digest, 22, 16);
				CTR cipher(eng);
				KeyParams k(_key, _iv);
				cipher.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					cipher.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}

				if (outBytes != _rhxExpected[1])
					throw std::string("RHX: Failed encryption test!");

				cipher.Initialize(false, k);

				for (int i = 0; i != 100; i++)
				{
					cipher.Transform(outBytes, inpBytes);
					memcpy(&outBytes[0], &inpBytes[0], 16);
				}
				delete eng;

				if (outBytes != decBytes)
					throw std::string("RHX: Failed decryption test!");
			}
		}

		void SHXMonteCarlo()
		{
			std::vector<byte> inpBytes(16, 0);
			std::vector<byte> outBytes(16, 0);
			std::vector<byte> decBytes(16, 0);

			// SHX, 32 rounds
			{
				SHA512 digest;
				SHX* eng = new SHX(&digest, 32);
				CTR engine(eng);
				KeyParams k(_key, _iv);
				engine.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}

				if (outBytes != _shxExpected[0])
					throw std::string("SHX: Failed encryption test!");

				engine.Initialize(false, k);

				for (int i = 0; i != 100; i++)
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
				SHA512 digest;
				SHX* eng = new SHX(&digest, 40);
				CTR engine(eng);
				KeyParams k(_key, _iv);
				engine.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}

				if (outBytes != _shxExpected[1])
					throw std::string("SHX: Failed encryption test!");

				engine.Initialize(false, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(outBytes, inpBytes);
					memcpy(&outBytes[0], &inpBytes[0], 16);
				}
				delete eng;

				if (outBytes != decBytes)
					throw std::string("SHX: Failed decryption test!");
			}
		}

		void THXMonteCarlo()
		{
			std::vector<byte> inpBytes(16, 0);
			std::vector<byte> outBytes(16, 0);
			std::vector<byte> decBytes(16, 0);

			// THX, 16 rounds
			{
				SHA512 digest;
				THX* eng = new THX(&digest, 16);
				CTR engine(eng);
				KeyParams k(_key, _iv);
				engine.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}

				if (outBytes != _thxExpected[0])
					throw std::string("THX: Failed encryption test!");

				engine.Initialize(false, k);

				for (int i = 0; i != 100; i++)
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
				SHA512 digest;
				THX* eng = new THX(&digest, 20);
				CTR engine(eng);
				KeyParams k(_key, _iv);
				engine.Initialize(true, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(inpBytes, outBytes);
					memcpy(&inpBytes[0], &outBytes[0], 16);
				}

				if (outBytes != _thxExpected[1])
					throw std::string("THX: Failed encryption test!");

				engine.Initialize(false, k);

				for (int i = 0; i != 100; i++)
				{
					engine.Transform(outBytes, inpBytes);
					memcpy(&outBytes[0], &inpBytes[0], 16);
				}
				delete eng;

				if (outBytes != decBytes)
					throw std::string("THX: Failed decryption test!");
			}
		}
	};
}

#endif
