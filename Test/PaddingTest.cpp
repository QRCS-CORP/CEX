#include "PaddingTest.h"
#include "../CEX/CSP.h"
#include "../CEX/ISO7816.h"
#include "../CEX/PKCS7.h"
#include "../CEX/TBC.h"
#include "../CEX/X923.h"

namespace Test
{
	const std::string PaddingTest::DESCRIPTION = "Cipher Padding output Tests.";
	const std::string PaddingTest::FAILURE = "FAILURE! ";
	const std::string PaddingTest::SUCCESS = "SUCCESS! Cipher Padding tests have executed succesfully.";

	PaddingTest::PaddingTest()
		:
		m_progressEvent()
	{
	}

	PaddingTest::~PaddingTest()
	{
	}

	std::string PaddingTest::Run()
	{
		try
		{
			CompareOutput(new Padding::ISO7816());
			OnProgress(std::string("PaddingTest: Passed ISO7816 comparison tests.."));
			CompareOutput(new Padding::PKCS7());
			OnProgress(std::string("PaddingTest: Passed PKCS7 comparison tests.."));
			CompareOutput(new Padding::TBC());
			OnProgress(std::string("PaddingTest: Passed TBC comparison tests.."));
			CompareOutput(new Padding::X923());
			OnProgress(std::string("PaddingTest: Passed X923 comparison tests.."));

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

	void PaddingTest::CompareOutput(Padding::IPadding* Padding)
	{
		CEX::Provider::CSP rng;
		std::vector<byte> fill(16);
		rng.GetBytes(fill);
		const unsigned int BLOCK = 16;

		for (unsigned int i = 0; i < BLOCK; i++)
		{
			std::vector<byte> data(BLOCK);
			// fill with rand
			if (i > 0)
				memcpy(&data[0], &fill[0], BLOCK - i);

			// pad array
			Padding->AddPadding(data, i);
			// verify length
			unsigned int len = (unsigned int)Padding->GetPaddingLength(data);
			if (len == 0 && i != 0)
				throw TestException("PaddingTest: Failed the padding value return check!");
			else if (i != 0 && len != BLOCK - i)
				throw TestException("PaddingTest: Failed the padding value return check!");

			// test offset method
			if (i > 0 && i < 15)
			{
				len = (unsigned int)Padding->GetPaddingLength(data, i);

				if (len == 0 && i != 0)
					throw TestException("PaddingTest: Failed the padding value return check!");
				else if (i != 0 && len != BLOCK - i)
					throw TestException("PaddingTest: Failed the offset padding value return check!");
			}
		}

		delete Padding;
	}

	void PaddingTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}