#include "PBKDF2Test.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"
#include "../CEX/PBKDF2.h"

namespace Test
{
	std::string PBKDF2Test::Run()
	{
		try
		{
			Initialize();

			CEX::Digest::SHA256* eng256 = new CEX::Digest::SHA256();
			CompareVector(eng256, m_output[0]);
			delete eng256;
			OnProgress("PBKDF2Test: Passed 256 bit vectors test..");

			CEX::Digest::SHA512* eng512 = new CEX::Digest::SHA512();
			CompareVector(eng512, m_output[1]);
			delete eng512;
			OnProgress("PBKDF2Test: Passed 512 bit vectors test..");

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

	void PBKDF2Test::CompareVector(CEX::Digest::IDigest* Engine, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(1024);
		size_t keySize = Engine->BlockSize();
		std::vector<byte> salt(keySize);
		CEX::Generator::PBKDF2 gen(Engine, 100);

		for (unsigned int i = 0; i < salt.size(); i++)
			salt[i] = (byte)i;

		gen.Initialize(salt);
		gen.Generate(outBytes);

		while (outBytes.size() > 32)
			outBytes = TestUtils::Reduce(outBytes);

		if (outBytes != Output)
			throw std::string("PBKDF2: Values are not equal!");
	}

	void PBKDF2Test::Initialize()
	{
		const char* outputEncoded[2] =
		{
			("a2ab21c1ffd7455f76924b8be3ebb43bc03c591e8d309fc87a8a2483bf4c52d3"),
			("cc46b9de43b3e3eac0685e5f945458e5da835851645c520f9c8edc91a5da28ee")
		};
		HexConverter::Decode(outputEncoded, 2, m_output);
	}

	void PBKDF2Test::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}