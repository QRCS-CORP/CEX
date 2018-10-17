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

	//~~~Constructor~~~//

	PaddingTest::PaddingTest()
		:
		m_progressEvent()
	{
	}

	PaddingTest::~PaddingTest()
	{
	}

	//~~~Accessors~~~//

	const std::string PaddingTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &PaddingTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string PaddingTest::Run()
	{
		using namespace Padding;

		try
		{
			ISO7816* pad1 = new ISO7816();
			Compare(pad1);
			delete pad1;
			OnProgress(std::string("PaddingTest: Passed ISO7816 comparison tests.."));

			PKCS7* pad2 = new PKCS7();
			Compare(pad2);
			delete pad2;
			OnProgress(std::string("PaddingTest: Passed PKCS7 comparison tests.."));

			TBC* pad3 = new TBC();
			Compare(pad3);
			delete pad3;
			OnProgress(std::string("PaddingTest: Passed TBC comparison tests.."));

			X923* pad4 = new X923();
			Compare(pad4);
			delete pad4;
			OnProgress(std::string("PaddingTest: Passed X923 comparison tests.."));

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

	void PaddingTest::Compare(Padding::IPadding* Padding)
	{
		const size_t MSGBLK = 16;
		std::vector<byte> fill(MSGBLK);
		CEX::Provider::CSP rng;

		rng.Generate(fill);

		for (size_t i = 0; i < MSGBLK; i++)
		{
			std::vector<byte> msg(MSGBLK);
			// fill with rand
			if (i > 0)
			{
				std::memcpy(msg.data(), fill.data(), MSGBLK - i);
			}

			// pad array
			Padding->AddPadding(msg, i);
			// verify length
			size_t len = Padding->GetPaddingLength(msg);

			if (len == 0 && i != 0)
			{
				throw TestException(std::string("PaddingTest: Failed the padding value return check! -PC1"));
			}
			else if (i != 0 && len != MSGBLK - i)
			{
				throw TestException(std::string("PaddingTest: Failed the padding value return check! -PC2"));
			}

			// test offset method
			if (i > 0 && i < MSGBLK - 1)
			{
				len = Padding->GetPaddingLength(msg, i);

				if (len == 0 && i != 0)
				{
					throw TestException(std::string("PaddingTest: Failed the padding value return check! -PC3"));
				}
				else if (i != 0 && len != MSGBLK - i)
				{
					throw TestException(std::string("PaddingTest: Failed the offset padding value return check! -PC4"));
				}
			}
		}
	}

	//~~~Private Functions~~~//

	void PaddingTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
