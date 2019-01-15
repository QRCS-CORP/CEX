#include "MemUtilsTest.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Utility::MemoryTools;

	const std::string MemUtilsTest::CLASSNAME = "MemUtilsTest";
	const std::string MemUtilsTest::DESCRIPTION = "MemoryTools test; tests output and speed of parallelized memory functions.";
	const std::string MemUtilsTest::SUCCESS = "SUCCESS! All MemoryTools tests have executed succesfully.";

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
			Evaluate();
			OnProgress(std::string("MemUtilsTest: Passed output comparison tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void MemUtilsTest::Evaluate()
	{
		Prng::SecureRandom rng;
		//~~~COPY~~~//
		// block copy
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = rng.NextUInt32(10000, 100);
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::Copy(input, 0, output, 0, inpSze);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("Copy"), std::string("Byte comparison failed! -ME1"));
			}
		}

		// 128 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::COPY128(input, 0, output, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY128"), std::string("Byte comparison failed! -ME2"));
			}
		}

		// 256 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::COPY256(input, 0, output, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY256"), std::string("Byte comparison failed! -ME3"));
			}
		}

		// 512 block
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::COPY512(input, 0, output, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY512"), std::string("Byte comparison failed! -ME4"));
			}
		}

		// byte to ulong
		for (size_t i = 0; i < 100; ++i)
		{
			ulong inpVal = rng.NextUInt64(1000000, 100);
			std::vector<byte> output(8);
			MemoryTools::CopyFromValue(inpVal, output, 0, 8);
			ulong cmpVal = 0;
			MemoryTools::CopyToValue(output, 0, cmpVal, 8);

			if (cmpVal != inpVal)
			{
				throw TestException(std::string("Evaluate"), std::string("CopyToValue"), std::string("Byte comparison failed! -ME5"));
			}
		}

		//~~~CLEAR~~~//
		// block clear
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = rng.NextUInt32(10000, 100);
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::Clear(input, 0, inpSze);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("Clear"), std::string("Evaluate: Byte comparison failed! -ME6"));
			}
		}


		// clear 128
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::CLEAR128(input, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR128"), std::string("Byte comparison failed! -ME7"));
			}
		}

		// clear 256
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::CLEAR256(input, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR256"), std::string("Byte comparison failed! -ME8"));
			}
		}

		// clear 512
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			std::vector<byte> input = rng.Generate(inpSze);
			std::vector<byte> output(input.size());
			MemoryTools::CLEAR512(input, 0);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR512"), std::string("Byte comparison failed! -ME9"));
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
			MemoryTools::SetValue(output, 0, inpSze, (byte)0xff);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("SetValue"), std::string("Byte comparison failed! -ME10"));
			}
		}

		// memset 128
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 16;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemoryTools::SETVAL128(output, 0, val);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("SETVAL128"), std::string("Byte comparison failed! -ME11"));
			}
		}

		// memset 256
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 32;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemoryTools::SETVAL256(output, 0, val);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("SETVAL256"), std::string("Byte comparison failed! -ME12"));
			}
		}

		// memset 512
		for (size_t i = 0; i < 100; ++i)
		{
			uint inpSze = 64;
			byte val = (byte)rng.NextInt16(255, 1);
			std::vector<byte> input(inpSze, val);
			std::vector<byte> output(input.size());
			MemoryTools::SETVAL512(output, 0, val);

			if (input != output)
			{
				throw TestException(std::string("Evaluate"), std::string("SETVAL512"), std::string("Byte comparison failed! -ME13"));
			}
		}
	}

	void MemUtilsTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
