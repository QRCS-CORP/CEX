#include "MemUtilsTest.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Utility::MemUtils;

	const std::string MemUtilsTest::DESCRIPTION = "MemUtils test; tests output and speed of parallelized memory functions.";
	const std::string MemUtilsTest::FAILURE = "FAILURE! ";
	const std::string MemUtilsTest::SUCCESS = "SUCCESS! All MemUtils tests have executed succesfully.";

	MemUtilsTest::MemUtilsTest()
		:
		m_progressEvent()
	{
	}

	MemUtilsTest::~MemUtilsTest()
	{
	}

	const std::string MemUtilsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &MemUtilsTest::Progress()
	{
		return m_progressEvent;
	}

	std::string MemUtilsTest::Run()
	{
		try
		{
			UtilsCompare();
			OnProgress(std::string("MemUtilsTest: Passed output comparison tests.."));

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

	void MemUtilsTest::UtilsCompare()
	{
		Prng::SecureRandom rng;
		//~~~COPY~~~//
		// block copy
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = rng.NextUInt32(10000, 100);
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::Copy(input, 0, output, 0, inpSze);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// 128 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::COPY128(input, 0, output, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// 256 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::COPY256(input, 0, output, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// 512 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::COPY512(input, 0, output, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// byte to ulong
		for (size_t i = 0; i < 100; ++i)
		{
			ulong inpVal = rng.NextUInt64(1000000, 100);
			std::vector<byte> output(8);
			MemUtils::CopyFromValue(inpVal, output, 0, 8);
			ulong cmpVal = 0;
			MemUtils::CopyToValue(output, 0, cmpVal, 8);

			if (cmpVal != inpVal)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		//~~~CLEAR~~~//
		// block clear
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = rng.NextUInt32(10000, 100);
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::Clear(input, 0, inpSze);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}


		// clear 128
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::CLEAR128(input, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// clear 256
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::CLEAR256(input, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// clear 512
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			std::vector<byte> input = rng.GetBytes(inpSze);
			std::vector<byte> output(input.size());
			MemUtils::CLEAR512(input, 0);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		//~~~SET~~~//
		// block set
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = rng.NextUInt32(10000, 100);
			std::vector<byte> input(inpSze);
			std::vector<byte> output(inpSze);
			std::memset(&input[0], (byte)0xff, inpSze);
			MemUtils::SetValue(output, 0, inpSze, (byte)0xff);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// memset 128
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemUtils::SETVAL128(output, 0, val);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// memset 256
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemUtils::SETVAL256(output, 0, val);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}

		// memset 512
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemUtils::SETVAL512(output, 0, val);

			if (input != output)
			{
				throw TestException("CompareOutput: byte comparison failed!");
			}
		}
	}

	void MemUtilsTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
