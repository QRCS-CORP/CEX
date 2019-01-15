 #include "UtilityTest.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/IntegerTools.h"

namespace Test
{
	using Utility::IntegerTools;

	const std::string UtilityTest::CLASSNAME = "UtilityTest";
	const std::string UtilityTest::DESCRIPTION = "Utility test; tests various math helper functions.";
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
			Conversions();
			OnProgress(std::string("UtilityTest: Passed endian conversion tests.."));
			//Operations();
			//OnProgress(std::string("UtilityTest: Passed mathematical operations tests.."));
			Rotation();
			OnProgress(std::string("UtilityTest: Passed integer rotation tests.."));

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

	void UtilityTest::Conversions()
	{
		Prng::SecureRandom gen;

		// test integer conversions
		std::vector<byte>bbe16(2);
		std::vector<byte>rbe16(2);
		gen.Generate(bbe16);
		ushort be16 = IntegerTools::BeBytesTo16(bbe16, 0);
		IntegerTools::Be16ToBytes(be16, rbe16, 0);

		if (bbe16 != rbe16)
		{
			throw TestException(std::string("Conversions"), std::string("BeBytesTo16"), std::string("BE16 Integer to array conversion has failed!"));
		}

		std::vector<byte>bbe32(4);
		std::vector<byte>rbe32(4);
		gen.Generate(bbe32);
		uint be32 = IntegerTools::BeBytesTo32(bbe32, 0);
		IntegerTools::Be32ToBytes(be32, rbe32, 0);

		if (bbe32 != rbe32)
		{
			throw TestException(std::string("Conversions"), std::string("BeBytesTo32"), std::string("BE32 Integer to array conversion has failed!"));
		}

		std::vector<byte>bbe64(8);
		std::vector<byte>rbe64(8);
		gen.Generate(bbe64);
		ulong be64 = IntegerTools::BeBytesTo64(bbe64, 0);
		IntegerTools::Be64ToBytes(be64, rbe64, 0);

		if (bbe64 != rbe64)
		{
			throw TestException(std::string("Conversions"), std::string("BeBytesTo64"), std::string("BE64 Integer to array conversion has failed!"));
		}

		std::vector<byte>ble16(2);
		std::vector<byte>rle16(2);
		gen.Generate(ble16);
		ushort le16 = IntegerTools::LeBytesTo16(ble16, 0);
		IntegerTools::Le16ToBytes(le16, rle16, 0);

		if (ble16 != rle16)
		{
			throw TestException(std::string("Conversions"), std::string("LeBytesTo16"), std::string("LE16 Integer to array conversion has failed!"));
		}

		std::vector<byte>ble32(4);
		std::vector<byte>rle32(4);
		gen.Generate(ble32);
		uint le32 = IntegerTools::LeBytesTo32(ble32, 0);
		IntegerTools::Le32ToBytes(le32, rle32, 0);

		if (ble32 != rle32)
		{
			throw TestException(std::string("Conversions"), std::string("LeBytesTo32"), std::string("LE32 Integer to array conversion has failed!"));
		}

		std::vector<byte>ble64(8);
		std::vector<byte>rle64(8);
		gen.Generate(ble64);
		ulong le64 = IntegerTools::LeBytesTo64(ble64, 0);
		IntegerTools::Le64ToBytes(le64, rle64, 0);

		if (ble64 != rle64)
		{
			throw TestException(std::string("Conversions"), std::string("LeBytesTo64"), std::string("LE64 Integer to array conversion has failed!"));
		}

		// test block conversions

		std::vector<ushort>inp16(256);
		std::vector<byte>otp16(512);
		std::vector<ushort>ret16(256);
		gen.Fill(inp16, 0, inp16.size());

		IntegerTools::BeToBlock(inp16, 0, otp16, 0, otp16.size());
		IntegerTools::BlockToBe(otp16, 0, ret16, 0, otp16.size());

		if (ret16 != inp16)
		{
			throw TestException(std::string("Conversions"), std::string("BeToBlock"), std::string("BE16 block conversion has failed!"));
		}

		otp16.clear();
		otp16.resize(512);
		ret16.clear();
		ret16.resize(256);

		IntegerTools::LeToBlock(inp16, 0, otp16, 0, otp16.size());
		IntegerTools::BlockToLe(otp16, 0, ret16, 0, otp16.size());

		if (ret16 != inp16)
		{
			throw TestException(std::string("Conversions"), std::string("LeToBlock"), std::string("LE16 block conversion has failed!"));
		}

		std::vector<uint>inp32(128);
		std::vector<byte>otp32(512);
		std::vector<uint>ret32(128);
		gen.Fill(inp32, 0, inp32.size());

		IntegerTools::BeToBlock(inp32, 0, otp32, 0, otp32.size());
		IntegerTools::BlockToBe(otp32, 0, ret32, 0, otp32.size());

		if (ret32 != inp32)
		{
			throw TestException(std::string("Conversions"), std::string("BlockToBe"), std::string("BE32 block conversion has failed!"));
		}

		otp32.clear();
		otp32.resize(512);
		ret32.clear();
		ret32.resize(128);

		IntegerTools::LeToBlock(inp32, 0, otp32, 0, otp32.size());
		IntegerTools::BlockToLe(otp32, 0, ret32, 0, otp32.size());

		if (ret32 != inp32)
		{
			throw TestException(std::string("Conversions"), std::string("BlockToLe"), std::string("LE32 block conversion has failed!"));
		}

		std::vector<ulong>inp64(64);
		std::vector<byte>otp64(512);
		std::vector<ulong>ret64(64);
		gen.Fill(inp64, 0, inp64.size());

		IntegerTools::BeToBlock(inp64, 0, otp64, 0, otp64.size());
		IntegerTools::BlockToBe(otp64, 0, ret64, 0, otp64.size());

		if (ret64 != inp64)
		{
			throw TestException(std::string("Conversions"), std::string("BeToBlock"), std::string("BE64 block conversion has failed!"));
		}

		otp64.clear();
		otp64.resize(512);
		ret64.clear();
		ret64.resize(64);

		IntegerTools::LeToBlock(inp64, 0, otp64, 0, otp64.size());
		IntegerTools::BlockToLe(otp64, 0, ret64, 0, otp64.size());

		if (ret64 != inp64)
		{
			throw TestException(std::string("Conversions"), std::string("LeToBlock"), std::string("LE64 block conversion has failed!"));
		}
	}

	void UtilityTest::Operations()
	{
		// TODO: complete this once library is stable
	}

	void UtilityTest::Rotation()
	{
		Prng::SecureRandom gen;
		uint x32 = gen.NextUInt32();

		for (uint i = 0; i < 32; ++i)
		{
			uint y = IntegerTools::RotL32(x32, i);
			uint z = rol(x32, i);

			if (y != z)
			{
				throw TestException(std::string("Rotation"), std::string("RotL32"), std::string("32bit left rotation has failed!"));
			}
		}

		for (uint i = 0; i < 32; ++i)
		{
			uint y = IntegerTools::RotR32(x32, i);
			uint z = ror(x32, i);

			if (y != z)
			{
				throw TestException(std::string("Rotation"), std::string("RotR32"), std::string("32bit right rotation has failed!"));
			}
		}

		ulong x64 = gen.NextUInt64();

		for (uint i = 0; i < 64; ++i)
		{
			ulong y = IntegerTools::RotL64(x64, i);
			ulong z = rol(x64, i);

			if (y != z)
			{
				throw TestException(std::string("Rotation"), std::string("RotL64"), std::string("64bit left rotation has failed!"));
			}
		}

		for (uint i = 0; i < 64; ++i)
		{
			ulong y = IntegerTools::RotR64(x64, i);
			ulong z = ror(x64, i);

			if (y != z)
			{
				throw TestException(std::string("Rotation"), std::string("RotR64"), std::string("64bit right rotation has failed!"));
			}
		}
	}

	void UtilityTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
