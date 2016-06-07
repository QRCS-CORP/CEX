#include "CTRDrbgTest.h"
#include "../CEX/CTRDrbg.h"
#include "../CEX/RHX.h"

namespace Test
{
	std::string CTRDrbgTest::Run()
	{
		try
		{
			Initialize();
			CompareVector(m_output);
			OnProgress("CTRDrbg: Passed vector comparison tests..");

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

	void CTRDrbgTest::CompareVector(std::vector<byte> Expected)
	{
		CEX::Cipher::Symmetric::Block::RHX* eng = new CEX::Cipher::Symmetric::Block::RHX();
		CEX::Generator::CTRDrbg ctd(eng);
		unsigned int ksze = 48;
		std::vector<byte> key(ksze);
		std::vector<byte> output(1024);

		for (unsigned int i = 0; i < ksze; i++)
			key[i] = (byte)i;

		ctd.Initialize(key);
		ctd.Generate(output);
		delete eng;

		while (output.size() > 32)
			output = TestUtils::Reduce(output);

		if (output != Expected)
			throw std::string("CTRDrbg: Failed comparison test!");
	}

	void CTRDrbgTest::Initialize()
	{
		HexConverter::Decode("b621dbd634714c11d9e72953d580474b37780e36b74edbd5c4b3a506e5a41018", m_output);
	}

	void CTRDrbgTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}