#include "RijndaelTest.h"
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string RijndaelTest::DESCRIPTION = "Rijndael Known Answer Tests.";
	const std::string RijndaelTest::FAILURE = "FAILURE! ";
	const std::string RijndaelTest::SUCCESS = "SUCCESS! Rijndael tests have executed succesfully.";

	RijndaelTest::RijndaelTest()
		:
		m_cipherText(0),
		m_keys(0),
		m_plainText(0),
		m_progressEvent()
	{
	}

	RijndaelTest::~RijndaelTest()
	{
	}

	std::string RijndaelTest::Run()
	{
		try
		{
			Initialize();

			for (unsigned int i = 0; i < m_plainText.size(); ++i)
				CompareVector(m_keys[i], m_plainText[i], m_cipherText[i]);

			OnProgress(std::string("RijndaelTest : Passed Gladman 128bit block Rijndael tests.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void RijndaelTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		std::vector<byte> outBytes2(Input.size(), 0);
		RHX engine(Digests::None, 14);
		Key::Symmetric::SymmetricKey k(Key);

		engine.Initialize(true, k);
		engine.Transform(Input, outBytes);

		if (outBytes != Output)
			throw TestException("RijndaelTest: Encrypted arrays are not equal!");

		engine.Initialize(false, k);
		engine.Transform(Output, outBytes);

		if (outBytes != Input)
			throw TestException("RijndaelTest: Decrypted arrays are not equal!");
	}

	void RijndaelTest::Initialize()
	{
		const char* keysEncoded[4] =
		{
			("80000000000000000000000000000000"),
			("00000000000000000000000000000080"),
			("000000000000000000000000000000000000000000000000"),
			("0000000000000000000000000000000000000000000000000000000000000000")
		};
		HexConverter::Decode(keysEncoded, 4, m_keys);

		const char* plainTextEncoded[4] =
		{
			("00000000000000000000000000000000"),
			("00000000000000000000000000000000"),
			("80000000000000000000000000000000"),
			("80000000000000000000000000000000")
		};
		HexConverter::Decode(plainTextEncoded, 4, m_plainText);

		const char* cipherTextEncoded[4] =
		{
			("0EDD33D3C621E546455BD8BA1418BEC8"),
			("172AEAB3D507678ECAF455C12587ADB7"),
			("6CD02513E8D4DC986B4AFE087A60BD0C"),
			("DDC6BF790C15760D8D9AEB6F9A75FD4E")
		};
		HexConverter::Decode(cipherTextEncoded, 4, m_cipherText);
	}

	void RijndaelTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}