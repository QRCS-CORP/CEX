#ifndef _CEXTEST_CMACTEST_H
#define _CEXTEST_CMACTEST_H

#include "ITest.h"
#include "CMAC.h"
#include "RHX.h"

namespace Test
{
	using CEX::Mac::CMAC;
	using CEX::Cipher::Symmetric::Block::RHX;

	/// <summary>
	/// HMAC implementation vector comparison tests.
	/// <para>Using vectors from Rfc 4493:
	/// <see href="http://tools.ietf.org/html/rfc4493"/></para>
	/// </summary>
	class CMACTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CMAC Known Answer Test Vectors for 128/192/256 bit Keys.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All CMAC tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<std::vector<byte>> _expected;
		std::vector<std::vector<byte>> _input;
		std::vector<std::vector<byte>> _keys;

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
		/// Compares known answer CMAC vectors for equality
		/// </summary>
		CMACTest()
		{
			const char* keysEncoded[3] =
			{
				("2b7e151628aed2a6abf7158809cf4f3c"),
				("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
				("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
			};
			HexConverter::Decode(keysEncoded, 3, _keys);

			const char* inputEncoded[4] =
			{
				(""),
				("6bc1bee22e409f96e93d7e117393172a"),
				("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
				("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
			};
			HexConverter::Decode(inputEncoded, 4, _input);

			const char* expectedEncoded[12] =
			{
				("bb1d6929e95937287fa37d129b756746"),
				("070a16b46b4d4144f79bdd9dd04a287c"),
				("dfa66747de9ae63030ca32611497c827"),
				("51f0bebf7e3b9d92fc49741779363cfe"),
				("d17ddf46adaacde531cac483de7a9367"),
				("9e99a7bf31e710900662f65e617c5184"),
				("8a1de5be2eb31aad089a82e6ee908b0e"),
				("a1d5df0eed790f794d77589659f39a11"),
				("028962f61b7bf89efc6b551f4667d983"),
				("28a7023f452e8f82bd4bf28d8c37c35c"),
				("aaf3d8f1de5640c232f5b169b9c911e6"),
				("e1992190549f6ed5696a2c056c315410")
			};
			HexConverter::Decode(expectedEncoded, 12, _expected);
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~CMACTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareVector(_keys[0], _input[0], _expected[0]);
				CompareVector(_keys[0], _input[1], _expected[1]);
				CompareVector(_keys[0], _input[2], _expected[2]);
				CompareVector(_keys[0], _input[3], _expected[3]);
				OnProgress("Passed 128 bit key vector tests..");
				CompareVector(_keys[1], _input[0], _expected[4]);
				CompareVector(_keys[1], _input[1], _expected[5]);
				CompareVector(_keys[1], _input[2], _expected[6]);
				CompareVector(_keys[1], _input[3], _expected[7]);
				OnProgress("Passed 192 bit key vector tests..");
				CompareVector(_keys[2], _input[0], _expected[8]);
				CompareVector(_keys[2], _input[1], _expected[9]);
				CompareVector(_keys[2], _input[2], _expected[10]);
				CompareVector(_keys[2], _input[3], _expected[11]);
				OnProgress("Passed 256 bit key vector tests..");
				CompareAccess(_keys[2]);
				OnProgress("Passed DoFinal/ComputeHash methods output comparison..");

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
		void CompareAccess(std::vector<byte> &Key)
		{
			RHX* eng = new RHX();
			std::vector<byte> iv(eng->BlockSize());
			CMAC mac(eng, 128);

			mac.Initialize(Key, iv);
			std::vector<byte> input(64);
			mac.BlockUpdate(input, 0, input.size());
			std::vector<byte> hash1(16);
			mac.DoFinal(hash1, 0);
			std::vector<byte> hash2(16);
			mac.ComputeMac(input, hash2);
			delete eng;

			if (hash1 != hash2)
				throw std::string("CMAC is not equal!");
		}

		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected)
		{
			std::vector<byte> hash(16);
			RHX* eng = new RHX();
			std::vector<byte> iv(eng->BlockSize());
			CMAC mac(eng, 128);

			mac.Initialize(Key, iv);
			mac.BlockUpdate(Input, 0, Input.size());
			mac.DoFinal(hash, 0);
			delete eng;

			if (Expected != hash)
				throw std::string("CMAC is not equal!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif