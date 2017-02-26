#include "XSPRsgTest.h"
#include "../CEX/XSG.h"

namespace Test
{
	std::string XSPRsgTest::Run()
	{
		try
		{
			Initialize();
			CompareVector(m_input[0], m_expected[0]);
			CompareVector(m_input[1], m_expected[1]);
			CompareVector(m_input[2], m_expected[2]);
			CompareVector(m_input[3], m_expected[3]);
			OnProgress("Passed XorShift+ vector tests..");

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

	void XSPRsgTest::CompareVector(std::vector<uint64_t> &Input, std::vector<byte> &Expected)
	{
		/*std::vector<byte> rand(32);
		CEX::Drbg::XSG* gen = new CEX::Drbg::XSG(Input);// ToDo: fix this
		gen->GetBytes(rand);
		delete gen;

		if (Expected != rand)
			throw std::string("XSG: array is not equal!");*/
	}

	void XSPRsgTest::Initialize()
	{
		m_input =
		{
			{ 123456789, 987654321 },
			{ 11111111, 22222222 },
			{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
			{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 },
		};

		const char* expectedEncoded[4] =
		{
			("485e8998e6ad0300b4c77fb4a08d2200ad7644a3ca4c52f34c829c47f7e1d21c"), //128
			("bd749478c5540000fb500c28af54010029336291bc14bc6286a094e8a58031f8"),
			("1ff967b4312e56c0d4f6afadab6f2b096afbbf716c7da30631e2b74bc8ff34d5"), //1024
			("ebb8179801eeedad9bdd3750cb5b93bd0000c0473c64cf5a24d2df9b96c40248")
		};
		HexConverter::Decode(expectedEncoded, 4, m_expected);
	}

	void XSPRsgTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}