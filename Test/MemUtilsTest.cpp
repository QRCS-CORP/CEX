#include "MemUtilsTest.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using Tools::MemoryTools;

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
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void MemUtilsTest::Evaluate()
	{
		std::vector<uint8_t> inp;
		std::vector<uint8_t> otp;
		uint64_t cmpval;
		uint64_t inpval;
		size_t i;
		uint32_t inplen;
		uint8_t val;

		Prng::SecureRandom rng;

		//~~~COPY~~~//
		// block copy
		inplen = rng.NextUInt32(10000, 100);
		inp = rng.Generate(inplen);
		otp.resize(inp.size());

		for (i = 0; i < 100; ++i)
		{
			MemoryTools::Copy(inp, 0, otp, 0, inplen);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("Copy"), std::string("Byte comparison failed! -ME1"));
			}
		}

		// 128 block
		inplen = 16;
		inp = rng.Generate(inplen);
		otp.resize(inp.size());

		for (i = 0; i < 100; ++i)
		{
			MemoryTools::COPY128(inp, 0, otp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY128"), std::string("Byte comparison failed! -ME2"));
			}
		}

		// 256 block
		inplen = 32;
		inp = rng.Generate(inplen);
		otp.resize(inp.size());

		for (i = 0; i < 100; ++i)
		{
			MemoryTools::COPY256(inp, 0, otp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY256"), std::string("Byte comparison failed! -ME3"));
			}
		}

		// 512 block
		inplen = 64;
		inp = rng.Generate(inplen);
		otp.resize(inp.size());

		for (i = 0; i < 100; ++i)
		{
			MemoryTools::COPY512(inp, 0, otp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("COPY512"), std::string("Byte comparison failed! -ME4"));
			}
		}

		// uint8_t to uint64_t

		for (i = 0; i < 100; ++i)
		{
			inpval = rng.NextUInt64(1000000, 100);
			otp.resize(8);
			MemoryTools::CopyFromValue(inpval, otp, 0, 8);
			cmpval = 0;
			MemoryTools::CopyToValue(otp, 0, cmpval, 8);

			if (cmpval != inpval)
			{
				throw TestException(std::string("Evaluate"), std::string("CopyToValue"), std::string("Byte comparison failed! -ME5"));
			}
		}

		//~~~CLEAR~~~//
		// block clear
		for (i = 0; i < 100; ++i)
		{
			inplen = rng.NextUInt32(10000, 100);
			inp = rng.Generate(inplen);
			otp.clear();
			otp.resize(inp.size());
			MemoryTools::Clear(inp, 0, inplen);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("Clear"), std::string("Evaluate: Byte comparison failed! -ME6"));
			}
		}


		// clear 128
		for (i = 0; i < 100; ++i)
		{
			inplen = 16;
			inp = rng.Generate(inplen);
			otp.clear();
			otp.resize(inp.size());
			MemoryTools::CLEAR128(inp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR128"), std::string("Byte comparison failed! -ME7"));
			}
		}

		// clear 256
		for (i = 0; i < 100; ++i)
		{
			inplen = 32;
			inp = rng.Generate(inplen);
			otp.clear();
			otp.resize(inp.size());
			MemoryTools::CLEAR256(inp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR256"), std::string("Byte comparison failed! -ME8"));
			}
		}

		// clear 512
		for (i = 0; i < 100; ++i)
		{
			inplen = 64;
			inp = rng.Generate(inplen);
			otp.clear();
			otp.resize(inp.size());
			MemoryTools::CLEAR512(inp, 0);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("CLEAR512"), std::string("Byte comparison failed! -ME9"));
			}
		}

		//~~~SET~~~//
		// block set
		for (i = 0; i < 100; ++i)
		{
			inplen = rng.NextUInt32(10000, 100);
			inp.clear();
			inp.resize(inplen);
			otp.resize(inplen);
			std::memset(&inp[0], 0xFF, inplen);
			MemoryTools::SetValue(otp, 0, inplen, 0xFF);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("SetValue"), std::string("Byte comparison failed! -ME10"));
			}
		}
		
		// memset 128
		for (i = 0; i < 100; ++i)
		{
			inplen = 16;
			val = static_cast<uint8_t>(rng.NextInt16(255, 1));
			inp.clear();
			inp.resize(inplen, val);
			otp.resize(inp.size());
			MemoryTools::SETVAL128(otp, 0, val);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("SETVAL128"), std::string("Byte comparison failed! -ME11"));
			}
		}

		// memset 256
		for (i = 0; i < 100; ++i)
		{
			inplen = 32;
			val = static_cast<uint8_t>(rng.NextInt16(255, 1));
			inp.clear();
			inp.resize(inplen, val);
			otp.resize(inp.size());
			MemoryTools::SETVAL256(otp, 0, val);

			if (inp != otp)
			{
				throw TestException(std::string("Evaluate"), std::string("SETVAL256"), std::string("Byte comparison failed! -ME12"));
			}
		}

		// memset 512
		for (i = 0; i < 100; ++i)
		{
			inplen = 64;
			val = static_cast<uint8_t>(rng.NextInt16(255, 1));
			inp.clear();
			inp.resize(inplen, val);
			otp.resize(inp.size());
			MemoryTools::SETVAL512(otp, 0, val);

			if (inp != otp)
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
