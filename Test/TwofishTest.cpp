#include "TwofishTest.h"
#include "../CEX/THX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	std::string TwofishTest::Run()
	{
		using namespace TestFiles::Counterpane;

		try
		{
			Initialize();

			std::vector<byte> cip(16, 0);
			std::vector<byte> key(16, 0);

			// vector tests //
			// 128 bit keys
			std::string cipStr;
			TestUtils::Read(TWOFISHCTEXT128, cipStr);

			std::string keyStr;
			TestUtils::Read(TWOFISHKEY128, keyStr);

			for (unsigned int i = 0; i < keyStr.size(); i += 32)
			{
				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(i, 32), key);

				// vector comparison
				CompareVector(key, m_plainText, cip);
			}
			OnProgress("TwofishTest: Passed Twofish 128 bit key vector tests..");

			// 192 bit keys
			TestUtils::Read(TWOFISHCTEXT192, cipStr);
			TestUtils::Read(TWOFISHKEY192, keyStr);

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 48)
			{
				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 48), key);

				// vector comparison
				CompareVector(key, m_plainText, cip);
			}
			OnProgress("TwofishTest: Passed Twofish 192 bit key vector tests..");

			// 256 bit keys
			TestUtils::Read(TWOFISHCTEXT256, cipStr);
			TestUtils::Read(TWOFISHKEY256, keyStr);

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 64)
			{
				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 64), key);

				// vector comparison
				CompareVector(key, m_plainText, cip);
			}
			OnProgress("TwofishTest: Passed Twofish 256 bit key vector tests..");

			// monte carlo tests: //
			// encrypt 10,000 rounds each
			key.resize(16, 0);
			std::vector<byte> output;

			HexConverter::Decode("282BE7E4FA1FBDC29661286F1F310B7E", output);
			// 128 key
			CompareMonteCarlo(key, m_plainText, output);
			OnProgress("TwofishTest: Passed 10,000 round 128 bit key Monte Carlo encryption test..");

			// 192 key
			key.resize(24, 0);
			HexConverter::Decode("9AB71D7F280FF79F0D135BBD5FAB7E37", output);
			CompareMonteCarlo(key, m_plainText, output);
			OnProgress("TwofishTest: Passed 10,000 round 192 bit key Monte Carlo encryption test..");

			// 256 key
			key.resize(32, 0);
			HexConverter::Decode("04F2F36CA927AE506931DE8F78B2513C", output);
			CompareMonteCarlo(key, m_plainText, output);
			OnProgress("TwofishTest: Passed 10,000 round 256 bit key Monte Carlo encryption test..");

			// decrypt 10,000 rounds
			key.resize(16, 0);
			HexConverter::Decode("21D3F7F6724513946B72CFAE47DA2EED", output);
			// 128 key
			CompareMonteCarlo(key, m_plainText, output, false);
			OnProgress("TwofishTest: Passed 10,000 round 128 bit key Monte Carlo decryption test..");

			// 192 key
			key.resize(24, 0);
			HexConverter::Decode("B4582FA55072FCFEF538F39072F234A9", output);
			CompareMonteCarlo(key, m_plainText, output, false);
			OnProgress("TwofishTest: Passed 10,000 round 192 bit key Monte Carlo decryption test..");

			// 256 key
			key.resize(32, 0);
			HexConverter::Decode("BC7D078C4872063869DEAB891FB42761", output);
			CompareMonteCarlo(key, m_plainText, output, false);
			OnProgress("TwofishTest: Passed 10,000 round 256 bit key Monte Carlo decryption test..");

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void TwofishTest::CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, bool Encrypt, unsigned int Count)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		memcpy(&outBytes[0], &Input[0], outBytes.size());
		THX engine;

		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(Encrypt, k);

		for (unsigned int i = 0; i < Count; i++)
			engine.Transform(outBytes, outBytes);

		if (outBytes != Output)
			throw std::exception("Twofish MonteCarlo: Arrays are not equal!");
	}

	void TwofishTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		THX tfx;
		Key::Symmetric::SymmetricKey k(Key);

		tfx.Initialize(true, k);
		tfx.EncryptBlock(Input, outBytes);

		if (outBytes != Output)
			throw std::exception("Twofish Vector: Encrypted arrays are not equal!");

		tfx.Initialize(false, k);
		tfx.Transform(Output, outBytes);

		if (outBytes != Input)
			throw std::exception("Twofish Vector: Decrypted arrays are not equal!");
	}

	void TwofishTest::Initialize()
	{
		HexConverter::Decode("00000000000000000000000000000000", m_plainText);
	}

	void TwofishTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}