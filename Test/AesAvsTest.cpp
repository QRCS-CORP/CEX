#include "AesAvsTest.h"
#if defined(__AVX__)
#	include "../CEX/AHX.h"
#endif
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string AesAvsTest::DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
	const std::string AesAvsTest::FAILURE = "FAILURE: ";
	const std::string AesAvsTest::SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";

	AesAvsTest::AesAvsTest(bool TestNI)
		:
		m_progressEvent(),
		m_testNI(TestNI)
	{
	}

	AesAvsTest::~AesAvsTest()
	{
	}

	const std::string AesAvsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AesAvsTest::Progress()
	{
		return m_progressEvent;
	}

	std::string AesAvsTest::Run()
	{
		using namespace TestFiles::AESAVS;

		std::vector<byte> plainText;
		HexConverter::Decode("00000000000000000000000000000000", plainText);
		std::vector<byte> key;
		std::vector<byte> cipherText;

		try
		{
			std::string data = "";
			TestUtils::Read(AESAVSKEY128, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				std::string istr = data.substr(i, 32);
				std::string jstr = data.substr(j, 32);

				HexConverter::Decode(istr, key);
				HexConverter::Decode(jstr, cipherText);
#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
				}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 128 bit key vectors test.."));

			data = "";
			TestUtils::Read(AESAVSKEY192, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 48; i < data.size(); i += 80, j += 80)
			{
				HexConverter::Decode(data.substr(i, 48), key);
				HexConverter::Decode(data.substr(j, 32), cipherText);

#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
				}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 192 bit key vectors test.."));

			data = "";
			TestUtils::Read(AESAVSKEY256, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 64; i < data.size(); i += 96, j += 96)
			{
				HexConverter::Decode(data.substr(i, 64), key);
				HexConverter::Decode(data.substr(j, 32), cipherText);

#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
				}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 256 bit key vectors test.."));

			HexConverter::Decode("00000000000000000000000000000000", key);
			data = "";
			TestUtils::Read(AESAVSPTEXT128, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
				}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 128 bit plain-text vectors test.."));

			HexConverter::Decode("000000000000000000000000000000000000000000000000", key);
			data = "";
			TestUtils::Read(AESAVSPTEXT192, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
			}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 192 bit plain-text vectors test.."));

			HexConverter::Decode("0000000000000000000000000000000000000000000000000000000000000000", key);
			data = "";
			TestUtils::Read(AESAVSPTEXT256, data);
			if (data.size() == 0)
			{
				throw TestException("Could not find the test file!");
			}

			for (size_t i = 0, j = 32; i < data.size(); i += 64, j += 64)
			{
				HexConverter::Decode(data.substr(i, 32), plainText);
				HexConverter::Decode(data.substr(j, 32), cipherText);

#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(key, plainText, cipherText);
				}
				else
#endif
				{
					CompareVector(key, plainText, cipherText);
				}
			}
			OnProgress(std::string("AesAvsTest: Passed 256 bit plain-text vectors test.. 960/960 vectors passed"));

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

	void AesAvsTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);

		RHX engine;
		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
		{
			throw TestException("AESAVS: Encrypted arrays are not equal!");
		}
	}

#if defined(__AVX__)
	void AesAvsTest::CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);

		AHX engine;
		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
		{
			throw TestException("AESAVS: AES-NI Encrypted arrays are not equal!");
		}
	}
#endif

	void AesAvsTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}