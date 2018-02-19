#include "UtilityTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	using Utility::IntUtils;

	const std::string UtilityTest::DESCRIPTION = "Utility test; tests various math helper functions.";
	const std::string UtilityTest::FAILURE = "FAILURE! ";
	const std::string UtilityTest::SUCCESS = "SUCCESS! All Utility tests have executed succesfully.";

	UtilityTest::UtilityTest()
		:
		m_progressEvent()
	{
	}

	UtilityTest::~UtilityTest()
	{
	}

	const std::string UtilityTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &UtilityTest::Progress()
	{
		return m_progressEvent;
	}

	std::string UtilityTest::Run()
	{
		try
		{
			EndianConversions();
			OnProgress(std::string("UtilityTest: Passed endian conversion tests.."));
			//OperationsCheck();
			//OnProgress(std::string("UtilityTest: Passed mathematical operations tests.."));
			RotationCheck();
			OnProgress(std::string("UtilityTest: Passed integer rotation tests.."));

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

	void UtilityTest::EndianConversions()
	{
		Prng::SecureRandom rnd;

		// test integer conversions
		std::vector<byte>bbe16(2);
		std::vector<byte>rbe16(2);
		rnd.GetBytes(bbe16);
		ushort be16 = IntUtils::BeBytesTo16(bbe16, 0);
		IntUtils::Be16ToBytes(be16, rbe16, 0);

		if (bbe16 != rbe16)
		{
			throw TestException("UtilityTest: BE16 Integer to array conversion has failed!");
		}

		std::vector<byte>bbe32(4);
		std::vector<byte>rbe32(4);
		rnd.GetBytes(bbe32);
		uint be32 = IntUtils::BeBytesTo32(bbe32, 0);
		IntUtils::Be32ToBytes(be32, rbe32, 0);

		if (bbe32 != rbe32)
		{
			throw TestException("UtilityTest: BE32 Integer to array conversion has failed!");
		}

		std::vector<byte>bbe64(8);
		std::vector<byte>rbe64(8);
		rnd.GetBytes(bbe64);
		ulong be64 = IntUtils::BeBytesTo64(bbe64, 0);
		IntUtils::Be64ToBytes(be64, rbe64, 0);

		if (bbe64 != rbe64)
		{
			throw TestException("UtilityTest: BE64 Integer to array conversion has failed!");
		}

		std::vector<byte>ble16(2);
		std::vector<byte>rle16(2);
		rnd.GetBytes(ble16);
		ushort le16 = IntUtils::LeBytesTo16(ble16, 0);
		IntUtils::Le16ToBytes(le16, rle16, 0);

		if (ble16 != rle16)
		{
			throw TestException("UtilityTest: LE16 Integer to array conversion has failed!");
		}

		std::vector<byte>ble32(4);
		std::vector<byte>rle32(4);
		rnd.GetBytes(ble32);
		uint le32 = IntUtils::LeBytesTo32(ble32, 0);
		IntUtils::Le32ToBytes(le32, rle32, 0);

		if (ble32 != rle32)
		{
			throw TestException("UtilityTest: LE32 Integer to array conversion has failed!");
		}

		std::vector<byte>ble64(8);
		std::vector<byte>rle64(8);
		rnd.GetBytes(ble64);
		ulong le64 = IntUtils::LeBytesTo64(ble64, 0);
		IntUtils::Le64ToBytes(le64, rle64, 0);

		if (ble64 != rle64)
		{
			throw TestException("UtilityTest: LE64 Integer to array conversion has failed!");
		}

		// test block conversions

		std::vector<ushort>inp16(256);
		std::vector<byte>otp16(512);
		std::vector<ushort>ret16(256);
		rnd.Fill(inp16, 0, inp16.size());

		IntUtils::BeToBlock(inp16, 0, otp16, 0, otp16.size());
		IntUtils::BlockToBe(otp16, 0, ret16, 0, otp16.size());

		if (ret16 != inp16)
		{
			throw TestException("UtilityTest: BE16 block conversion has failed!");
		}

		otp16.clear();
		otp16.resize(512);
		ret16.clear();
		ret16.resize(256);

		IntUtils::LeToBlock(inp16, 0, otp16, 0, otp16.size());
		IntUtils::BlockToLe(otp16, 0, ret16, 0, otp16.size());

		if (ret16 != inp16)
		{
			throw TestException("UtilityTest: LE16 block conversion has failed!");
		}

		std::vector<uint>inp32(128);
		std::vector<byte>otp32(512);
		std::vector<uint>ret32(128);
		rnd.Fill(inp32, 0, inp32.size());

		IntUtils::BeToBlock(inp32, 0, otp32, 0, otp32.size());
		IntUtils::BlockToBe(otp32, 0, ret32, 0, otp32.size());

		if (ret32 != inp32)
		{
			throw TestException("UtilityTest: BE32 block conversion has failed!");
		}

		otp32.clear();
		otp32.resize(512);
		ret32.clear();
		ret32.resize(128);

		IntUtils::LeToBlock(inp32, 0, otp32, 0, otp32.size());
		IntUtils::BlockToLe(otp32, 0, ret32, 0, otp32.size());

		if (ret32 != inp32)
		{
			throw TestException("UtilityTest: LE32 block conversion has failed!");
		}

		std::vector<ulong>inp64(64);
		std::vector<byte>otp64(512);
		std::vector<ulong>ret64(64);
		rnd.Fill(inp64, 0, inp64.size());

		IntUtils::BeToBlock(inp64, 0, otp64, 0, otp64.size());
		IntUtils::BlockToBe(otp64, 0, ret64, 0, otp64.size());

		if (ret64 != inp64)
		{
			throw TestException("UtilityTest: BE64 block conversion has failed!");
		}

		otp64.clear();
		otp64.resize(512);
		ret64.clear();
		ret64.resize(64);

		IntUtils::LeToBlock(inp64, 0, otp64, 0, otp64.size());
		IntUtils::BlockToLe(otp64, 0, ret64, 0, otp64.size());

		if (ret64 != inp64)
		{
			throw TestException("UtilityTest: LE64 block conversion has failed!");
		}
	}

	void UtilityTest::OperationsCheck()
	{
		// TODO: complete this once library is stable
	}

	void UtilityTest::RotationCheck()
	{
		Prng::SecureRandom rnd;
		uint x32 = rnd.NextUInt32();

		for (uint i = 0; i < 32; ++i)
		{
			uint y = IntUtils::RotL32(x32, i);
			uint z = rol(x32, i);

			if (y != z)
			{
				throw TestException("UtilityTest: 32bit left rotation has failed!");
			}
		}

		for (uint i = 0; i < 32; ++i)
		{
			uint y = IntUtils::RotR32(x32, i);
			uint z = ror(x32, i);

			if (y != z)
			{
				throw TestException("UtilityTest: 32bit right rotation has failed!");
			}
		}

		ulong x64 = rnd.NextUInt64();

		for (uint i = 0; i < 64; ++i)
		{
			ulong y = IntUtils::RotL64(x64, i);
			ulong z = rol(x64, i);

			if (y != z)
			{
				throw TestException("UtilityTest: 64bit left rotation has failed!");
			}
		}

		for (uint i = 0; i < 64; ++i)
		{
			ulong y = IntUtils::RotR64(x64, i);
			ulong z = ror(x64, i);

			if (y != z)
			{
				throw TestException("UtilityTest: 64bit right rotation has failed!");
			}
		}
	}

	void UtilityTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
