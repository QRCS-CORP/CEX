#include "AesFipsTest.h"
#include "../CEX/RHX.h"
#if defined(AESNI_AVAILABLE)
#	include "../CEX/AHX.h"
#endif

namespace Test
{
	std::string AesFipsTest::Run()
	{
		try
		{
			Initialize();

			for (unsigned int i = 0; i < 12; i++)
			{
				if (m_testNI)
					CompareVectorNI(m_keys[i], m_plainText[i], m_cipherText[i]);
				else
					CompareVector(m_keys[i], m_plainText[i], m_cipherText[i]);
			}

			OnProgress("AesFipsTest: Passed FIPS 197 Monte Carlo tests..");

			for (unsigned int i = 12; i < m_plainText.size(); i++)
			{
				if (m_testNI)
					CompareMonteCarloNI(m_keys[i], m_plainText[i], m_cipherText[i]);
				else
					CompareMonteCarlo(m_keys[i], m_plainText[i], m_cipherText[i]);
			}

			OnProgress("AesFipsTest: Passed Extended Monte Carlo tests..");

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

	void AesFipsTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		CEX::Cipher::Symmetric::Block::RHX engine(16);
		CEX::Common::KeyParams k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::string("AesFipsTest: AES: Encrypted arrays are not equal!");

		engine.Initialize(false, k);
		engine.Transform(Output, outBytes);

		if (outBytes != Input)
			throw std::string("AesFipsTest: AES: Decrypted arrays are not equal!");
	}

	void AesFipsTest::CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
#if defined(AESNI_AVAILABLE)
		std::vector<byte> outBytes(Input.size(), 0);

		CEX::Cipher::Symmetric::Block::AHX engine;
		CEX::Common::KeyParams k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw std::string("AesFipsTest: AES: Encrypted arrays are not equal!");

		engine.Initialize(false, k);
		engine.Transform(Output, outBytes);

		if (outBytes != Input)
			throw std::string("AesFipsTest: AES: Decrypted arrays are not equal!");
#endif
	}

	void AesFipsTest::CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		memcpy(&outBytes[0], &Input[0], outBytes.size());
		{
			CEX::Cipher::Symmetric::Block::RHX engine(16);
			CEX::Common::KeyParams k(Key);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 10000; i++)
				engine.Transform(outBytes, outBytes);
		}

		if (outBytes != Output)
			throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");

		{
			CEX::Cipher::Symmetric::Block::RHX engine(16);
			CEX::Common::KeyParams k(Key);
			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 10000; i++)
				engine.Transform(outBytes, outBytes);
		}

		if (outBytes != Input)
			throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
	}

	void AesFipsTest::CompareMonteCarloNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
#if defined(AESNI_AVAILABLE)
		std::vector<byte> outBytes(Input.size(), 0);
		memcpy(&outBytes[0], &Input[0], outBytes.size());
		{
			CEX::Cipher::Symmetric::Block::AHX engine;
			CEX::Common::KeyParams k(Key);
			engine.Initialize(true, k);

			for (unsigned int i = 0; i != 10000; i++)
				engine.Transform(outBytes, outBytes);
		}

		if (outBytes != Output)
			throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");

		{
			CEX::Cipher::Symmetric::Block::AHX engine;
			CEX::Common::KeyParams k(Key);
			engine.Initialize(false, k);

			for (unsigned int i = 0; i != 10000; i++)
				engine.Transform(outBytes, outBytes);
		}

		if (outBytes != Input)
			throw std::string("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
#endif
	}

	void AesFipsTest::Initialize()
	{
		const char* keysEncoded[24] =
		{
			// fips
			("80000000000000000000000000000000"),
			("00000000000000000000000000000080"),
			("000000000000000000000000000000000000000000000000"),
			("0000000000000000000000000000000000000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("00000000000000000000000000000080"),
			("000000000000000000000000000000000000000000000000"),
			("0000000000000000000000000000000000000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("00000000000000000000000000000080"),
			("000000000000000000000000000000000000000000000000"),
			("0000000000000000000000000000000000000000000000000000000000000000"),
			// gladman
			("00000000000000000000000000000000"),
			("5F060D3716B345C253F6749ABAC10917"),
			("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			("00000000000000000000000000000000"),
			("5F060D3716B345C253F6749ABAC10917"),
			("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			("00000000000000000000000000000000"),
			("5F060D3716B345C253F6749ABAC10917"),
			("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};
		HexConverter::Decode(keysEncoded, 24, m_keys);

		const char* plainTextEncoded[24] =
		{
			("00000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("355F697E8B868B65B25A04E18D782AFA"),
			("F3F6752AE8D7831138F041560631B114"),
			("C737317FE0846F132B23C8C2A672CE22"),
			("00000000000000000000000000000000"),
			("355F697E8B868B65B25A04E18D782AFA"),
			("F3F6752AE8D7831138F041560631B114"),
			("C737317FE0846F132B23C8C2A672CE22"),
			("00000000000000000000000000000000"),
			("355F697E8B868B65B25A04E18D782AFA"),
			("F3F6752AE8D7831138F041560631B114"),
			("C737317FE0846F132B23C8C2A672CE22")
		};
		HexConverter::Decode(plainTextEncoded, 24, m_plainText);

		const char* cipherTextEncoded[24] =
		{
			("0EDD33D3C621E546455BD8BA1418BEC8"),
			("172AEAB3D507678ECAF455C12587ADB7"),
			("6CD02513E8D4DC986B4AFE087A60BD0C"),
			("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			("0EDD33D3C621E546455BD8BA1418BEC8"),
			("172AEAB3D507678ECAF455C12587ADB7"),
			("6CD02513E8D4DC986B4AFE087A60BD0C"),
			("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			("0EDD33D3C621E546455BD8BA1418BEC8"),
			("172AEAB3D507678ECAF455C12587ADB7"),
			("6CD02513E8D4DC986B4AFE087A60BD0C"),
			("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			("C34C052CC0DA8D73451AFE5F03BE297F"),
			("ACC863637868E3E068D2FD6E3508454A"),
			("77BA00ED5412DFF27C8ED91F3C376172"),
			("E58B82BFBA53C0040DC610C642121168"),
			("C34C052CC0DA8D73451AFE5F03BE297F"),
			("ACC863637868E3E068D2FD6E3508454A"),
			("77BA00ED5412DFF27C8ED91F3C376172"),
			("E58B82BFBA53C0040DC610C642121168"),
			("C34C052CC0DA8D73451AFE5F03BE297F"),
			("ACC863637868E3E068D2FD6E3508454A"),
			("77BA00ED5412DFF27C8ED91F3C376172"),
			("E58B82BFBA53C0040DC610C642121168")
		};
		HexConverter::Decode(cipherTextEncoded, 24, m_cipherText);
	}

	void AesFipsTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}