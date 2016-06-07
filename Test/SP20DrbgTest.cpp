#include "SP20DrbgTest.h"
#include "../CEX/SP20Drbg.h"

namespace Test
{
	std::string SP20DrbgTest::Run()
	{
		try
		{
			Initialize();

			CompareVector(24, m_output128);
			OnProgress("SP20Drbg: Passed 128bit vector comparison tests..");
			CompareVector(40, m_output256);
			OnProgress("SP20Drbg: Passed 256bit vector comparison tests..");

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

	void SP20DrbgTest::CompareVector(unsigned int KeySize, std::vector<byte> Expected)
	{
		std::vector<byte> key(KeySize);
		std::vector<byte> output(1024);

		for (unsigned int i = 0; i < KeySize; i++)
			key[i] = (byte)i;

		CEX::Generator::SP20Drbg spd(20);
		spd.Initialize(key);
		spd.Generate(output);

		while (output.size() > 32)
			output = TestUtils::Reduce(output);

		if (output != Expected)
			throw std::string("SP20Drbg: Failed comparison test!");
	}

	void SP20DrbgTest::Initialize()
	{
		HexConverter::Decode("0323103b248efe859cd4ca57559a1c4aa4f9320635bac3807d93b7bcfbad14d1", m_output128);
		HexConverter::Decode("d00b46e37495862e642c35be3a1149a8562ee50cdafe3a5f4b26a5c579a45c36", m_output256);
	}

	void SP20DrbgTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}