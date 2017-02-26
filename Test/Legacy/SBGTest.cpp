#include "SBGTest.h"
#include "../CEX/KeyParams.h"
#include "../CEX/Salsa20.h"
#include "../CEX/SBG.h"

namespace Test
{
	std::string SBGTest::Run()
	{
		try
		{
			CompareOutput();
			OnProgress("SBG: Passed output comparison tests..");

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

	void SBGTest::CompareOutput()
	{
		unsigned int ksze = 40;
		std::vector<byte> output1(1024);

		std::vector<byte> gkey(ksze);
		for (unsigned int i = 0; i < ksze; i++)
			gkey[i] = (byte)i;

		Drbg::SBG drbg;
		drbg.Initialize(gkey);
		drbg.Generate(output1);

		std::vector<byte> input(1024, 0);
		std::vector<byte> output2(1024);
		std::vector<byte> key(32);
		std::vector<byte> iv(8);
		memcpy(&iv[0], &gkey[0], 8);
		memcpy(&key[0], &gkey[8], 32);

		Common::KeyParams kp(key, iv);
		Cipher::Symmetric::Stream::Salsa20 cpr;
		cpr.Initialize(kp);
		cpr.Transform(input, output2);

		if (output1 != output2)
			throw std::string("SBG: Failed comparison test!");
	}

	void SBGTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}