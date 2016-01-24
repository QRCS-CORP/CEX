#ifndef _CEXTEST_PADDINGTEST_H
#define _CEXTEST_PADDINGTEST_H

#include "ITest.h"
#include "IPadding.h"
#include "ISO7816.h"
#include "PKCS7.h"
#include "TBC.h"
#include "X923.h"

namespace Test
{
	using CEX::Seed::CSPRsg;
	using namespace CEX::Cipher::Symmetric::Block::Padding;

	/// <summary>
	/// Tests each Padding mode for valid output
	/// </summary>
	class PaddingTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Cipher Padding output Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! Cipher Padding tests have executed succesfully.";

		TestEventHandler _progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compares padding modes for valid output
		/// </summary>
		PaddingTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~PaddingTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareOutput(new ISO7816());
				OnProgress("PaddingTest: Passed ISO7816 comparison tests..");
				CompareOutput(new PKCS7());
				OnProgress("PaddingTest: Passed PKCS7 comparison tests..");
				CompareOutput(new TBC());
				OnProgress("PaddingTest: Passed TBC comparison tests..");
				CompareOutput(new X923());
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

	private:
		void CompareOutput(IPadding* Padding)
		{
			CSPRsg rng;
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

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
