#include "XSPRsgTest.h"

namespace Test
{
	std::string XSPRsgTest::Run()
	{
		try
		{
			Initialize();

			CompareVector(_input[0], _expected[0]);
			CompareVector(_input[1], _expected[1]);
			CompareVector(_input[2], _expected[2]);
			CompareVector(_input[3], _expected[3]);
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
		std::vector<byte> rand(32);
		XSPRsg* gen = new XSPRsg(Input);
		gen->GetBytes(rand);
		delete gen;

		if (Expected != rand)
			throw std::string("XSPRsg: array is not equal!");
	}

	void XSPRsgTest::Initialize()
	{
		_input =
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
		HexConverter::Decode(expectedEncoded, 4, _expected);
	}

	void XSPRsgTest::OnProgress(char* Data)
	{
		_progressEvent(Data);
	}
}