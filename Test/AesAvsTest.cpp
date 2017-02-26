#include "AesAvsTest.h"
#include "../CEX/AHX.h"
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	std::string AesAvsTest::Run()
	{
		using namespace TestFiles::AESAVS;

		std::vector<byte> plainText;
		HexConverter::Decode("00000000000000000000000000000000", plainText);
		std::vector<byte> key;
		std::vector<byte> cipherText;

		try
		{
			std::string data;
			Test::TestUtils::Read(AESAVSKEY128, data);

			for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				std::string istr = data.substr(i, 32);
				std::string jstr = data.substr(j, 32);

				HexConverter::Decode(istr, key);
				HexConverter::Decode(jstr, cipherText);
				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 128 bit key vectors test..");

			Test::TestUtils::Read(AESAVSKEY192, data);

			for (unsigned int i = 0, j = 48; i < data.size(); i += 80, j += 80)
			{
				HexConverter::Decode(data.substr(i, 48), key);
				HexConverter::Decode(data.substr(j, 32), cipherText);

				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 192 bit key vectors test..");

			Test::TestUtils::Read(AESAVSKEY256, data);

			for (unsigned int i = 0, j = 64; i < data.size(); i += 96, j += 96)
			{
				HexConverter::Decode(data.substr(i, 64), key);
				HexConverter::Decode(data.substr(j, 32), cipherText);

				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 256 bit key vectors test..");

			HexConverter::Decode("00000000000000000000000000000000", key);
			Test::TestUtils::Read(AESAVSPTEXT128, data);

			for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 128 bit plain-text vectors test..");

			HexConverter::Decode("000000000000000000000000000000000000000000000000", key);
			Test::TestUtils::Read(AESAVSPTEXT192, data);

			for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 192 bit plain-text vectors test..");

			HexConverter::Decode("0000000000000000000000000000000000000000000000000000000000000000", key);
			Test::TestUtils::Read(AESAVSPTEXT256, data);

			for (unsigned int i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

				if (m_testNI)
					CompareVectorNI(key, plainText, cipherText);
				else
					CompareVector(key, plainText, cipherText);
			}
			OnProgress("AesAvsTest: Passed 256 bit plain-text vectors test.. 960/960 vectors passed");

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

	void AesAvsTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);

		RHX engine;
		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::exception("AESAVS: Encrypted arrays are not equal!");
	}

	void AesAvsTest::CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);

		AHX engine;
		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::exception("AESAVS: AES-NI Encrypted arrays are not equal!");
	}

	void AesAvsTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}