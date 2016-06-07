#include "AesAvsTest.h"
#include "../CEX/RHX.h"
#if defined(AESNI_AVAILABLE)
#include "../CEX/AHX.h"
#endif

namespace Test
{
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
			Test::TestUtils::Read(keyvect128, data);

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

			Test::TestUtils::Read(keyvect192, data);

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

			Test::TestUtils::Read(keyvect256, data);

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
			Test::TestUtils::Read(plainvect128, data);

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
			Test::TestUtils::Read(plainvect192, data);

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
			Test::TestUtils::Read(plainvect256, data);

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
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void AesAvsTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);

		CEX::Cipher::Symmetric::Block::RHX engine;
		CEX::Common::KeyParams k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::string("AESAVS: Encrypted arrays are not equal!");
	}

	void AesAvsTest::CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
#if defined(AESNI_AVAILABLE)
		std::vector<byte> outBytes(Input.size(), 0);

		CEX::Cipher::Symmetric::Block::AHX engine;
		CEX::Common::KeyParams k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::string("AESAVS: AES-NI Encrypted arrays are not equal!");
#endif
	}

	void AesAvsTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}