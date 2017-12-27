#include "AesFipsTest.h"
#if defined(__AVX__)
#	include "../CEX/AHX.h"
#endif
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string AesFipsTest::DESCRIPTION = "NIST AES specification FIPS 197 Known Answer Tests.";
	const std::string AesFipsTest::FAILURE = "FAILURE! ";
	const std::string AesFipsTest::SUCCESS = "SUCCESS! AES tests have executed succesfully.";

	AesFipsTest::AesFipsTest(bool TestNI)
		:
		m_cipherText(0),
		m_keys(0),
		m_plainText(0),
		m_progressEvent(),
		m_testNI(TestNI)
	{
	}

	AesFipsTest::~AesFipsTest()
	{
	}

	const std::string AesFipsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AesFipsTest::Progress()
	{
		return m_progressEvent;
	}

	std::string AesFipsTest::Run()
	{
		try
		{
			Initialize();

			for (size_t i = 0; i < 12; i++)
			{
#if defined(__AVX__)
				if (m_testNI)
				{
					CompareVectorNI(m_keys[i], m_plainText[i], m_cipherText[i]);
				}
				else
#endif
				{
					CompareVector(m_keys[i], m_plainText[i], m_cipherText[i]);
				}
			}

			OnProgress(std::string("AesFipsTest: Passed FIPS 197 Monte Carlo tests.."));

			for (size_t i = 12; i < m_plainText.size(); i++)
			{
#if defined(__AVX__)
				if (m_testNI)
				{
					CompareMonteCarloNI(m_keys[i], m_plainText[i], m_cipherText[i]);
				}
				else
#endif
				{
					CompareMonteCarlo(m_keys[i], m_plainText[i], m_cipherText[i]);
				}
			}

			OnProgress(std::string("AesFipsTest: Passed Extended Monte Carlo tests.."));

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

	void AesFipsTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		RHX engine;
		Key::Symmetric::SymmetricKey k(Key);
		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
		{
			throw TestException("AesFipsTest: AES: Encrypted arrays are not equal!");
		}

		engine.Initialize(false, k);
		engine.Transform(Output, outBytes);

		if (outBytes != Input)
		{
			throw TestException("AesFipsTest: AES: Decrypted arrays are not equal!");
		}
	}

#if defined(__AVX__)
	void AesFipsTest::CompareVectorNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		AHX engine;
		Key::Symmetric::SymmetricKey k(Key);

		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
		{
			throw TestException("AesFipsTest: AES: Encrypted arrays are not equal!");
		}

		engine.Initialize(false, k);
		engine.Transform(Output, outBytes);

		if (outBytes != Input)
		{
			throw TestException("AesFipsTest: AES: Decrypted arrays are not equal!");
		}
	}
#endif

	void AesFipsTest::CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		std::memcpy(&outBytes[0], &Input[0], outBytes.size());

		{
			RHX engine;
			Key::Symmetric::SymmetricKey k(Key);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 10000; i++)
			{
				engine.Transform(outBytes, outBytes);
			}
		}

		if (outBytes != Output)
		{
			throw TestException("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
		}

		{
			RHX engine;
			Key::Symmetric::SymmetricKey k(Key);
			engine.Initialize(false, k);

			for (size_t i = 0; i != 10000; i++)
			{
				engine.Transform(outBytes, outBytes);
			}
		}

		if (outBytes != Input)
		{
			throw TestException("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
		}
	}

#if defined(__AVX__)
	void AesFipsTest::CompareMonteCarloNI(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		std::memcpy(&outBytes[0], &Input[0], outBytes.size());
		{
			AHX engine;
			Key::Symmetric::SymmetricKey k(Key);
			engine.Initialize(true, k);

			for (size_t i = 0; i != 10000; i++)
			{
				engine.Transform(outBytes, outBytes);
			}
		}

		if (outBytes != Output)
		{
			throw TestException("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
		}

		{
			AHX engine;
			Key::Symmetric::SymmetricKey k(Key);
			engine.Initialize(false, k);

			for (size_t i = 0; i != 10000; i++)
			{
				engine.Transform(outBytes, outBytes);
			}
		}

		if (outBytes != Input)
		{
			throw TestException("AesFipsTest: AES MonteCarlo: Arrays are not equal!");
		}
	}
#endif

	void AesFipsTest::Initialize()
	{
		const std::vector<std::string> keys =
		{
			// fips
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000080"),
			std::string("000000000000000000000000000000000000000000000000"),
			std::string("0000000000000000000000000000000000000000000000000000000000000000"),
			// gladman
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386"),
			std::string("00000000000000000000000000000000"),
			std::string("5F060D3716B345C253F6749ABAC10917"),
			std::string("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114"),
			std::string("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")
		};
		HexConverter::Decode(keys, 24, m_keys);

		const std::vector<std::string> plainText =
		{
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("80000000000000000000000000000000"),
			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22"),
			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22"),
			std::string("00000000000000000000000000000000"),
			std::string("355F697E8B868B65B25A04E18D782AFA"),
			std::string("F3F6752AE8D7831138F041560631B114"),
			std::string("C737317FE0846F132B23C8C2A672CE22")
		};
		HexConverter::Decode(plainText, 24, m_plainText);

		const std::vector<std::string> cipherText =
		{
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			std::string("0EDD33D3C621E546455BD8BA1418BEC8"),
			std::string("172AEAB3D507678ECAF455C12587ADB7"),
			std::string("6CD02513E8D4DC986B4AFE087A60BD0C"),
			std::string("DDC6BF790C15760D8D9AEB6F9A75FD4E"),
			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168"),
			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168"),
			std::string("C34C052CC0DA8D73451AFE5F03BE297F"),
			std::string("ACC863637868E3E068D2FD6E3508454A"),
			std::string("77BA00ED5412DFF27C8ED91F3C376172"),
			std::string("E58B82BFBA53C0040DC610C642121168")
		};
		HexConverter::Decode(cipherText, 24, m_cipherText);
	}

	void AesFipsTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}