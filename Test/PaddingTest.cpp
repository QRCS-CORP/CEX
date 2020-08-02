#include "PaddingTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/ESP.h"
#include "../CEX/PKCS7.h"
#include "../CEX/X923.h"
#include "../CEX/ZeroOne.h"

namespace Test
{
	using CEX::Prng::SecureRandom;

	const std::string PaddingTest::CLASSNAME = "PaddingTest";
	const std::string PaddingTest::DESCRIPTION = "Cipher Padding output Tests.";
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
			ESP* pad1 = new ESP();
			Kat(pad1);
			delete pad1;
			OnProgress(std::string("PaddingTest: Passed ESP comparison tests.."));

			PKCS7* pad2 = new PKCS7();
			Kat(pad2);
			delete pad2;
			OnProgress(std::string("PaddingTest: Passed PKCS7 comparison tests.."));

			X923* pad3 = new X923();
			Kat(pad3);
			delete pad3;
			OnProgress(std::string("PaddingTest: Passed X923 comparison tests.."));

			ZeroOne* pad4 = new ZeroOne();
			Kat(pad4);
			delete pad4;
			OnProgress(std::string("PaddingTest: Passed Zeroes and Ones comparison tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void PaddingTest::Kat(Padding::IPadding* Padding)
	{
		const size_t MSGBLK = 16;
		std::vector<byte> fill(MSGBLK * 2);
		std::vector<byte> msg1(0);
		std::vector<byte> msg2(0);
		SecureRandom gen;
		size_t i;
		size_t len;

		gen.Generate(fill);

		for (i = 0; i < MSGBLK; i++)
		{
			msg1.clear();
			msg1.resize(MSGBLK);

			// fill with rand
			if (i > 0)
			{
				std::memcpy(msg1.data(), fill.data(), MSGBLK - i);
			}

			// pad array
			Padding->AddPadding(msg1, i, msg1.size());
			// verify length
			len = Padding->GetBlockLength(msg1);

			if (len == 0 && i != 0)
			{
				throw TestException(std::string("Kat"), Padding->Name(), std::string("Failed the padding value return check! -PC1"));
			}
			else if (i != 0 && len != i)
			{
				throw TestException(std::string("Kat"), Padding->Name(), std::string("Failed the padding value return check! -PC2"));
			}
			else
			{
				// misra
			}

			// test offset method
			if (i > 0 && i < MSGBLK - 1)
			{
				msg2.clear();
				msg2.resize(MSGBLK + i);
				std::memcpy(msg2.data() + i, fill.data(), MSGBLK - i);

				Padding->AddPadding(msg2, i, MSGBLK + i);

				len = Padding->GetBlockLength(msg2, i, MSGBLK + i);

				if (len == 0 && i != 0)
				{
					throw TestException(std::string("Kat"), Padding->Name(), std::string("Failed the padding value return check! -PC3"));
				}
				else if (i != 0 && len != i)
				{
					throw TestException(std::string("Kat"), Padding->Name(), std::string("Failed the offset padding value return check! -PC4"));
				}
				else
				{
					// misra
				}
			}
		}
	}

	//~~~Private Functions~~~//

	void PaddingTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
