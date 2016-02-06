#include "PaddingTest.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

namespace Test
{
	std::string PaddingTest::Run()
	{
		try
		{
			CompareOutput(new CEX::Cipher::Symmetric::Block::Padding::ISO7816());
			OnProgress("PaddingTest: Passed ISO7816 comparison tests..");
			CompareOutput(new CEX::Cipher::Symmetric::Block::Padding::PKCS7());
			OnProgress("PaddingTest: Passed PKCS7 comparison tests..");
			CompareOutput(new CEX::Cipher::Symmetric::Block::Padding::TBC());
			OnProgress("PaddingTest: Passed TBC comparison tests..");
			CompareOutput(new CEX::Cipher::Symmetric::Block::Padding::X923());
			OnProgress("PaddingTest: Passed X923 comparison tests..");

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

	void PaddingTest::CompareOutput(CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding)
	{
		CEX::Seed::CSPRsg rng;
		std::vector<byte> fill(16);
		rng.GetBytes(fill);
		const unsigned int BLOCK = 16;

		for (int i = 0; i < BLOCK; i++)
		{
			std::vector<byte> data(BLOCK);
			// fill with rand
			if (i > 0)
				memcpy(&data[0], &fill[0], BLOCK - i);

			// pad array
			Padding->AddPadding(data, i);
			// verify length
			unsigned int len = Padding->GetPaddingLength(data);
			if (len == 0 && i != 0)
				throw std::string("PaddingTest: Failed the padding value return check!");
			else if (i != 0 && len != BLOCK - i)
				throw std::string("PaddingTest: Failed the padding value return check!");

			// test offset method
			if (i > 0 && i < 15)
			{
				len = Padding->GetPaddingLength(data, i);

				if (len == 0 && i != 0)
					throw std::string("PaddingTest: Failed the padding value return check!");
				else if (i != 0 && len != BLOCK - i)
					throw std::string("PaddingTest: Failed the offset padding value return check!");
			}
		}

		delete Padding;
	}

	void PaddingTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}