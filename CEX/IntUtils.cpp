#include "IntUtils.h"
#include "Intrinsics.h"

NAMESPACE_UTILITY


uint IntUtils::BitPrecision(ulong Value)
{
	if (!Value)
		return 0;

	uint l = 0, h = 8 * sizeof(Value);

	while (h - l > 1)
	{
		uint t = (l + h) / 2;
		if (Value >> t)
			l = t;
		else
			h = t;
	}

	return h;
}

byte IntUtils::BitReverse(byte Value)
{
	Value = ((Value & 0xAA) >> 1) | ((Value & 0x55) << 1);
	Value = ((Value & 0xCC) >> 2) | ((Value & 0x33) << 2);
	return static_cast<byte>(RotFL32(Value, 4));
}

ushort IntUtils::BitReverse(ushort Value)
{
	Value = ((Value & 0xAAAA) >> 1) | ((Value & 0x5555) << 1);
	Value = ((Value & 0xCCCC) >> 2) | ((Value & 0x3333) << 2);
	Value = ((Value & 0xF0F0) >> 4) | ((Value & 0x0F0F) << 4);
	return ByteReverse(Value);
}

uint IntUtils::BitReverse(uint Value)
{
	Value = ((Value & 0xAAAAAAAA) >> 1) | ((Value & 0x55555555) << 1);
	Value = ((Value & 0xCCCCCCCC) >> 2) | ((Value & 0x33333333) << 2);
	Value = ((Value & 0xF0F0F0F0) >> 4) | ((Value & 0x0F0F0F0F) << 4);
	return ByteReverse(Value);
}

#ifdef WORD64_AVAILABLE
ulong IntUtils::BitReverse(ulong Value)
{
#ifdef SLOW_WORD64
	return (ulong(BitReverse(uint(Value))) << 32) | BitReverse(uint(Value >> 32));
#else
	Value = ((Value & W64LIT(0xAAAAAAAAAAAAAAAA)) >> 1) | ((Value & W64LIT(0x5555555555555555)) << 1);
	Value = ((Value & W64LIT(0xCCCCCCCCCCCCCCCC)) >> 2) | ((Value & W64LIT(0x3333333333333333)) << 2);
	Value = ((Value & W64LIT(0xF0F0F0F0F0F0F0F0)) >> 4) | ((Value & W64LIT(0x0F0F0F0F0F0F0F0F)) << 4);
	return ByteReverse(Value);
#endif
}
#endif

uint IntUtils::BytePrecision(ulong Value)
{
	uint i;
	for (i = sizeof(Value); i; --i)
		if (Value >> (i - 1) * 8)
			break;

	return i;
}

ushort IntUtils::ByteReverse(ushort Value)
{
	return static_cast<ushort>(RotFL32(Value, 8U));
}

uint IntUtils::ByteReverse(uint Value)
{
#ifdef CEX_PPC_INTRINSICS
	// PPC: load reverse indexed instruction
	return (uint)__lwbrx(&Value, 0);
#elif defined(CEX_FAST_ROTATE)
	// 5 instructions with rotate instruction, 9 without
	return (RotFR32(Value, 8U) & 0xff00ff00) | (RotFL32(Value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
	return RotFL32(Value, 16U);
#endif
}

ulong IntUtils::ByteReverse(ulong Value)
{
#ifdef CEX_PPC_INTRINSICS
	// PPC: load reverse indexed instruction
	return static_cast<uint>(__lwbrx(&Value, 0));
#elif defined(CEX_FAST_ROTATE)
	// 5 instructions with rotate instruction, 9 without
	return (RotFR32(Value, 8U) & 0xff00ff00) | (RotFL32(Value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	Value = ((Value & 0xFF00FF00) >> 8) | ((Value & 0x00FF00FF) << 8);
	return RotFL32(Value, 16U);
#endif
}

bool IntUtils::IsBigEndian()
{
	int num = 1;
	return (*(byte *)&num != 1);
}

void IntUtils::Be16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(IS_BIG_ENDIAN)
	memcpy(&Output[OutOffset], &Value, sizeof(ushort));
#else
	Output[OutOffset + 1] = static_cast<byte>(Value);
	Output[OutOffset] = static_cast<byte>(Value >> 8);
#endif
}

void IntUtils::Be32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined IS_BIG_ENDIAN
	memcpy(&Output[OutOffset], &Value, sizeof(uint));
#else
	Output[OutOffset + 3] = static_cast<byte>(Value);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
	Output[OutOffset] = static_cast<byte>(Value >> 24);
#endif
}

void IntUtils::Be64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(IS_BIG_ENDIAN)
	memcpy(&Output[OutOffset], &Value, sizeof(ulong));
#else
	Output[OutOffset + 7] = static_cast<byte>(Value);
	Output[OutOffset + 6] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 5] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 4] = static_cast<byte>(Value >> 24);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 32);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 40);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 48);
	Output[OutOffset] = static_cast<byte>(Value >> 56);
#endif
}

void IntUtils::BeUL256ToBlock(std::vector<uint> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_BIG_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 8 * sizeof(uint));
#else
	Be32ToBytes(Input[0], Output, OutOffset);
	Be32ToBytes(Input[1], Output, OutOffset + 4);
	Be32ToBytes(Input[2], Output, OutOffset + 8);
	Be32ToBytes(Input[3], Output, OutOffset + 12);
	Be32ToBytes(Input[4], Output, OutOffset + 16);
	Be32ToBytes(Input[5], Output, OutOffset + 20);
	Be32ToBytes(Input[6], Output, OutOffset + 24);
	Be32ToBytes(Input[7], Output, OutOffset + 28);
#endif
}

void IntUtils::BeULL512ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_BIG_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 8 * sizeof(ulong));
#else
	Be64ToBytes(Input[0], Output, OutOffset);
	Be64ToBytes(Input[1], Output, OutOffset + 8);
	Be64ToBytes(Input[2], Output, OutOffset + 16);
	Be64ToBytes(Input[3], Output, OutOffset + 24);
	Be64ToBytes(Input[4], Output, OutOffset + 32);
	Be64ToBytes(Input[5], Output, OutOffset + 40);
	Be64ToBytes(Input[6], Output, OutOffset + 48);
	Be64ToBytes(Input[7], Output, OutOffset + 56);
#endif
}

ushort IntUtils::BytesToBe16(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_BIG_ENDIAN)
	ushort value = 0;
	memcpy(&value, &Input[InOffset], sizeof(ushort));
	return value;
#else
	return
		(static_cast<ushort>(Input[InOffset] << 8)) |
		(static_cast<ushort>(Input[InOffset + 1]));
#endif
}

uint IntUtils::BytesToBe32(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_BIG_ENDIAN)
	uint value = 0;
	memcpy(&value, &Input[InOffset], sizeof(uint));
	return value;
#else
	return
		(static_cast<uint>(Input[InOffset] << 24)) |
		(static_cast<uint>(Input[InOffset + 1] << 16)) |
		(static_cast<uint>(Input[InOffset + 2] << 8)) |
		(static_cast<uint>(Input[InOffset + 3]));
#endif
}

ulong IntUtils::BytesToBe64(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_BIG_ENDIAN)
	ulong value = 0;
	memcpy(&value, &Input[InOffset], sizeof(ulong));
	return value;
#else
	return
		((ulong)Input[InOffset] << 56) |
		((ulong)Input[InOffset + 1] << 48) |
		((ulong)Input[InOffset + 2] << 40) |
		((ulong)Input[InOffset + 3] << 32) |
		((ulong)Input[InOffset + 4] << 24) |
		((ulong)Input[InOffset + 5] << 16) |
		((ulong)Input[InOffset + 6] << 8) |
		((ulong)Input[InOffset + 7]);
#endif
}

// ** Little Endian ** //

bool IntUtils::IsLittleEndian()
{
	int num = 1;
	return (*(byte *)&num == 1);
}

void IntUtils::Le16ToBytes(const ushort Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Value, sizeof(ushort));
#else
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
#endif
}

void IntUtils::Le32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Value, sizeof(uint));
#else
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
#endif
}

void IntUtils::Le64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Value, sizeof(ulong));
#else
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
	Output[OutOffset + 4] = static_cast<byte>(Value >> 32);
	Output[OutOffset + 5] = static_cast<byte>(Value >> 40);
	Output[OutOffset + 6] = static_cast<byte>(Value >> 48);
	Output[OutOffset + 7] = static_cast<byte>(Value >> 56);
#endif
}

void IntUtils::LeUL256ToBlock(std::vector<uint> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 8 * sizeof(uint));
#else
	Le32ToBytes(Input[0], Output, OutOffset);
	Le32ToBytes(Input[1], Output, OutOffset + 4);
	Le32ToBytes(Input[2], Output, OutOffset + 8);
	Le32ToBytes(Input[3], Output, OutOffset + 12);
	Le32ToBytes(Input[4], Output, OutOffset + 16);
	Le32ToBytes(Input[5], Output, OutOffset + 20);
	Le32ToBytes(Input[6], Output, OutOffset + 24);
	Le32ToBytes(Input[7], Output, OutOffset + 28);
#endif
}

void IntUtils::LeULL256ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 4 * sizeof(ulong));
#else
	Le64ToBytes(Input[0], Output, OutOffset);
	Le64ToBytes(Input[1], Output, OutOffset + 8);
	Le64ToBytes(Input[2], Output, OutOffset + 16);
	Le64ToBytes(Input[3], Output, OutOffset + 24);
#endif
}

void IntUtils::LeULL512ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 8 * sizeof(ulong));
#else
	Le64ToBytes(Input[0], Output, OutOffset);
	Le64ToBytes(Input[1], Output, OutOffset + 8);
	Le64ToBytes(Input[2], Output, OutOffset + 16);
	Le64ToBytes(Input[3], Output, OutOffset + 24);
	Le64ToBytes(Input[4], Output, OutOffset + 32);
	Le64ToBytes(Input[5], Output, OutOffset + 40);
	Le64ToBytes(Input[6], Output, OutOffset + 48);
	Le64ToBytes(Input[7], Output, OutOffset + 56);
#endif
}

void IntUtils::LeULL1024ToBlock(std::vector<ulong> &Input, std::vector<byte> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[0], 16 * sizeof(ulong));
#else
	Le64ToBytes(Input[0], Output, OutOffset);
	Le64ToBytes(Input[1], Output, OutOffset + 8);
	Le64ToBytes(Input[2], Output, OutOffset + 16);
	Le64ToBytes(Input[3], Output, OutOffset + 24);
	Le64ToBytes(Input[4], Output, OutOffset + 32);
	Le64ToBytes(Input[5], Output, OutOffset + 40);
	Le64ToBytes(Input[6], Output, OutOffset + 48);
	Le64ToBytes(Input[7], Output, OutOffset + 56);
	Le64ToBytes(Input[8], Output, OutOffset + 64);
	Le64ToBytes(Input[9], Output, OutOffset + 72);
	Le64ToBytes(Input[10], Output, OutOffset + 80);
	Le64ToBytes(Input[11], Output, OutOffset + 88);
	Le64ToBytes(Input[12], Output, OutOffset + 96);
	Le64ToBytes(Input[13], Output, OutOffset + 104);
	Le64ToBytes(Input[14], Output, OutOffset + 112);
	Le64ToBytes(Input[15], Output, OutOffset + 120);
#endif
}

ushort IntUtils::BytesToLe16(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	ushort value = 0;
	memcpy(&value, &Input[InOffset], sizeof(ushort));
	return value;
#else
	return
		(static_cast<ushort>(Input[InOffset]) |
		(static_cast<ushort>(Input[InOffset + 1] << 8)));
#endif
}

uint IntUtils::BytesToLe32(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	uint value = 0;
	memcpy(&value, &Input[InOffset], sizeof(uint));
	return value;
#else
	return
		(static_cast<uint>(Input[InOffset]) |
		(static_cast<uint>(Input[InOffset + 1] << 8)) |
			(static_cast<uint>(Input[InOffset + 2] << 16)) |
			(static_cast<uint>(Input[InOffset + 3] << 24)));
#endif
}

ulong IntUtils::BytesToLe64(const std::vector<byte> &Input, const size_t InOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	ulong value = 0;
	memcpy(&value, &Input[InOffset], sizeof(ulong));
	return value;
#else
	return
		((ulong)Input[InOffset]) |
		((ulong)Input[InOffset + 1] << 8) |
		((ulong)Input[InOffset + 2] << 16) |
		((ulong)Input[InOffset + 3] << 24) |
		((ulong)Input[InOffset + 4] << 32) |
		((ulong)Input[InOffset + 5] << 40) |
		((ulong)Input[InOffset + 6] << 48) |
		((ulong)Input[InOffset + 7] << 56);
#endif
}

void IntUtils::BytesToLeUL512(const std::vector<byte> &Input, const size_t InOffset, std::vector<uint> &Output, const size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(uint));
#else
	Output[OutOffset] = BytesToLe32(Input, InOffset);
	Output[OutOffset + 1] = BytesToLe32(Input, InOffset + 4);
	Output[OutOffset + 2] = BytesToLe32(Input, InOffset + 8);
	Output[OutOffset + 3] = BytesToLe32(Input, InOffset + 12);
	Output[OutOffset + 4] = BytesToLe32(Input, InOffset + 16);
	Output[OutOffset + 5] = BytesToLe32(Input, InOffset + 20);
	Output[OutOffset + 6] = BytesToLe32(Input, InOffset + 24);
	Output[OutOffset + 7] = BytesToLe32(Input, InOffset + 28);
	Output[OutOffset + 8] = BytesToLe32(Input, InOffset + 32);
	Output[OutOffset + 9] = BytesToLe32(Input, InOffset + 36);
	Output[OutOffset + 10] = BytesToLe32(Input, InOffset + 40);
	Output[OutOffset + 11] = BytesToLe32(Input, InOffset + 44);
	Output[OutOffset + 12] = BytesToLe32(Input, InOffset + 48);
	Output[OutOffset + 13] = BytesToLe32(Input, InOffset + 52);
	Output[OutOffset + 14] = BytesToLe32(Input, InOffset + 56);
	Output[OutOffset + 15] = BytesToLe32(Input, InOffset + 60);
#endif
}

void IntUtils::BytesToLeULL256(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[InOffset], 4 * sizeof(ulong));
#else
	Output[OutOffset] = BytesToLe64(Input, InOffset);
	Output[OutOffset + 1] = BytesToLe64(Input, InOffset + 8);
	Output[OutOffset + 2] = BytesToLe64(Input, InOffset + 16);
	Output[OutOffset + 3] = BytesToLe64(Input, InOffset + 24);
#endif
}

void IntUtils::BytesToLeULL512(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[InOffset], 8 * sizeof(ulong));
#else
	Output[OutOffset] = BytesToLe64(Input, InOffset);
	Output[OutOffset + 1] = BytesToLe64(Input, InOffset + 8);
	Output[OutOffset + 2] = BytesToLe64(Input, InOffset + 16);
	Output[OutOffset + 3] = BytesToLe64(Input, InOffset + 24);
	Output[OutOffset + 4] = BytesToLe64(Input, InOffset + 32);
	Output[OutOffset + 5] = BytesToLe64(Input, InOffset + 40);
	Output[OutOffset + 6] = BytesToLe64(Input, InOffset + 48);
	Output[OutOffset + 7] = BytesToLe64(Input, InOffset + 56);
#endif
}

void IntUtils::BytesToLeULL1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<ulong> &Output, size_t OutOffset)
{
#if defined(IS_LITTLE_ENDIAN)
	memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(ulong));
#else
	Output[OutOffset] = BytesToLe64(Input, InOffset);
	Output[OutOffset + 1] = BytesToLe64(Input, InOffset + 8);
	Output[OutOffset + 2] = BytesToLe64(Input, InOffset + 16);
	Output[OutOffset + 3] = BytesToLe64(Input, InOffset + 24);
	Output[OutOffset + 4] = BytesToLe64(Input, InOffset + 32);
	Output[OutOffset + 5] = BytesToLe64(Input, InOffset + 40);
	Output[OutOffset + 6] = BytesToLe64(Input, InOffset + 48);
	Output[OutOffset + 7] = BytesToLe64(Input, InOffset + 56);
	Output[OutOffset + 8] = BytesToLe64(Input, InOffset + 64);
	Output[OutOffset + 9] = BytesToLe64(Input, InOffset + 72);
	Output[OutOffset + 10] = BytesToLe64(Input, InOffset + 80);
	Output[OutOffset + 11] = BytesToLe64(Input, InOffset + 88);
	Output[OutOffset + 12] = BytesToLe64(Input, InOffset + 96);
	Output[OutOffset + 13] = BytesToLe64(Input, InOffset + 104);
	Output[OutOffset + 14] = BytesToLe64(Input, InOffset + 112);
	Output[OutOffset + 15] = BytesToLe64(Input, InOffset + 120);
#endif
}

#if defined(IS_LITTLE_ENDIAN)

ushort IntUtils::BytesToWord16(const std::vector<byte> &Input)
{
	return
		(static_cast<ushort>(Input[0]) |
		(static_cast<ushort>(Input[1] << 8)));
}

ushort IntUtils::BytesToWord16(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		(static_cast<ushort>(Input[InOffset]) |
		(static_cast<ushort>(Input[InOffset + 1] << 8)));
}

uint IntUtils::BytesToWord32(const std::vector<byte> &Input)
{
	return
		(static_cast<uint>(Input[0]) |
		(static_cast<uint>(Input[1] << 8)) |
			(static_cast<uint>(Input[2] << 16)) |
			(static_cast<uint>(Input[3] << 24)));
}

uint IntUtils::BytesToWord32(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		(static_cast<uint>(Input[InOffset]) |
		(static_cast<uint>(Input[InOffset + 1] << 8)) |
			(static_cast<uint>(Input[InOffset + 2] << 16)) |
			(static_cast<uint>(Input[InOffset + 3] << 24)));
}

ulong IntUtils::BytesToWord64(const std::vector<byte> &Input)
{
	return
		((ulong)Input[0]) |
		((ulong)Input[1] << 8) |
		((ulong)Input[2] << 16) |
		((ulong)Input[3] << 24) |
		((ulong)Input[4] << 32) |
		((ulong)Input[5] << 40) |
		((ulong)Input[6] << 48) |
		((ulong)Input[7] << 56);
}

ulong IntUtils::BytesToWord64(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		((ulong)Input[InOffset]) |
		((ulong)Input[InOffset + 1] << 8) |
		((ulong)Input[InOffset + 2] << 16) |
		((ulong)Input[InOffset + 3] << 24) |
		((ulong)Input[InOffset + 4] << 32) |
		((ulong)Input[InOffset + 5] << 40) |
		((ulong)Input[InOffset + 6] << 48) |
		((ulong)Input[InOffset + 7] << 56);
}

void IntUtils::Word16ToBytes(const ushort Value, std::vector<byte> &Output)
{
	Output[0] = static_cast<byte>(Value);
	Output[1] = static_cast<byte>(Value >> 8);
}

void IntUtils::Word16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
}

void IntUtils::Word32ToBytes(const uint Value, std::vector<byte> &Output)
{
	Output[0] = static_cast<byte>(Value);
	Output[1] = static_cast<byte>(Value >> 8);
	Output[2] = static_cast<byte>(Value >> 16);
	Output[3] = static_cast<byte>(Value >> 24);
}

void IntUtils::Word32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
}

void IntUtils::Word64ToBytes(const ulong Value, std::vector<byte> &Output)
{
	Output[0] = static_cast<byte>(Value);
	Output[1] = static_cast<byte>(Value >> 8);
	Output[2] = static_cast<byte>(Value >> 16);
	Output[3] = static_cast<byte>(Value >> 24);
	Output[4] = static_cast<byte>(Value >> 32);
	Output[5] = static_cast<byte>(Value >> 40);
	Output[6] = static_cast<byte>(Value >> 48);
	Output[7] = static_cast<byte>(Value >> 56);
}

void IntUtils::Word64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset] = static_cast<byte>(Value);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 24);
	Output[OutOffset + 4] = static_cast<byte>(Value >> 32);
	Output[OutOffset + 5] = static_cast<byte>(Value >> 40);
	Output[OutOffset + 6] = static_cast<byte>(Value >> 48);
	Output[OutOffset + 7] = static_cast<byte>(Value >> 56);
}

#else

ushort IntUtils::BytesToWord16(const std::vector<byte> &Input)
{
	return
		(static_cast<ushort>(Input[1]) |
		(static_cast<ushort>(Input[0] << 8)));
}

ushort IntUtils::BytesToWord16(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		(static_cast<ushort>(Input[InOffset + 1]) |
		(static_cast<ushort>(Input[InOffset] << 8)));
}

uint IntUtils::BytesToWord32(const std::vector<byte> &Input)
{
	return
		(static_cast<uint>(Input[3]) |
		(static_cast<uint>(Input[2] << 8)) |
			(static_cast<uint>(Input[1] << 16)) |
			(static_cast<uint>(Input[0] << 24)));
}

uint IntUtils::BytesToWord32(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		(static_cast<uint>(Input[InOffset + 3]) |
		(static_cast<uint>(Input[InOffset + 2] << 8)) |
			(static_cast<uint>(Input[InOffset + 1] << 16)) |
			(static_cast<uint>(Input[InOffset] << 24)));
}

ulong IntUtils::BytesToWord64(const std::vector<byte> &Input)
{
	return
		((ulong)Input[7]) |
		((ulong)Input[6] << 8) |
		((ulong)Input[5] << 16) |
		((ulong)Input[4] << 24) |
		((ulong)Input[3] << 32) |
		((ulong)Input[2] << 40) |
		((ulong)Input[1] << 48) |
		((ulong)Input[0] << 56);
}

ulong IntUtils::BytesToWord64(const std::vector<byte> &Input, const size_t InOffset)
{
	return
		((ulong)Input[InOffset + 7]) |
		((ulong)Input[InOffset + 6] << 8) |
		((ulong)Input[InOffset + 5] << 16) |
		((ulong)Input[InOffset + 4] << 24) |
		((ulong)Input[InOffset + 3] << 32) |
		((ulong)Input[InOffset + 2] << 40) |
		((ulong)Input[InOffset + 1] << 48) |
		((ulong)Input[InOffset] << 56);
}

void IntUtils::Word16ToBytes(const ushort Value, std::vector<byte> &Output)
{
	Output[1] = static_cast<byte>(Value);
	Output[0] = static_cast<byte>(Value >> 8);
}

void IntUtils::Word16ToBytes(const ushort Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset + 1] = static_cast<byte>(Value);
	Output[OutOffset] = static_cast<byte>(Value >> 8);
}

void IntUtils::Word32ToBytes(const uint Value, std::vector<byte> &Output)
{
	Output[3] = static_cast<byte>(Value);
	Output[2] = static_cast<byte>(Value >> 8);
	Output[1] = static_cast<byte>(Value >> 16);
	Output[0] = static_cast<byte>(Value >> 24);
}

void IntUtils::Word32ToBytes(const uint Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset + 3] = static_cast<byte>(Value);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
	Output[OutOffset] = static_cast<byte>(Value >> 24);
}

void IntUtils::Word64ToBytes(const ulong Value, std::vector<byte> &Output)
{
	Output[7] = static_cast<byte>(Value);
	Output[6] = static_cast<byte>(Value >> 8);
	Output[5] = static_cast<byte>(Value >> 16);
	Output[4] = static_cast<byte>(Value >> 24);
	Output[3] = static_cast<byte>(Value >> 32);
	Output[2] = static_cast<byte>(Value >> 40);
	Output[1] = static_cast<byte>(Value >> 48);
	Output[0] = static_cast<byte>(Value >> 56);
}

void IntUtils::Word64ToBytes(const ulong Value, std::vector<byte> &Output, size_t OutOffset)
{
	Output[OutOffset + 7] = static_cast<byte>(Value);
	Output[OutOffset + 6] = static_cast<byte>(Value >> 8);
	Output[OutOffset + 5] = static_cast<byte>(Value >> 16);
	Output[OutOffset + 4] = static_cast<byte>(Value >> 24);
	Output[OutOffset + 3] = static_cast<byte>(Value >> 32);
	Output[OutOffset + 2] = static_cast<byte>(Value >> 40);
	Output[OutOffset + 1] = static_cast<byte>(Value >> 48);
	Output[OutOffset] = static_cast<byte>(Value >> 56);
}

#endif

ulong IntUtils::Crop(ulong Value, uint size)
{
	if (size < 8 * sizeof(Value))
		return (Value & ((1L << size) - 1));
	else
		return Value;
}

uint IntUtils::Parity(ulong Value)
{
	for (size_t i = 8 * sizeof(Value) / 2; i>0; i /= 2)
		Value ^= Value >> i;
	return (uint)Value & 1;
}

#if defined(CEX_HAS_MINSSE) && defined(CEX_FASTROTATE_ENABLED)
#	pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

uint IntUtils::RotL32(uint Value, uint Shift)
{
	return Shift ? _rotl(Value, Shift) : Value;
}

ulong IntUtils::RotL64(ulong Value, uint Shift)
{
	return Shift ? _rotl64(Value, Shift) : Value;
}

uint IntUtils::RotR32(uint Value, uint Shift)
{
	return Shift ? _rotr(Value, Shift) : Value;
}

ulong IntUtils::RotR64(ulong Value, uint Shift)
{
	return Shift ? _rotr64(Value, Shift) : Value;
}

uint IntUtils::RotFL32(uint Value, uint Shift)
{
	return _lrotl(Value, Shift);
}

ulong IntUtils::RotFL64(ulong Value, uint Shift)
{
	return _rotl64(Value, Shift);
}

uint IntUtils::RotFR32(uint Value, uint Shift)
{
	return _lrotr(Value, Shift);
}

ulong IntUtils::RotFR64(ulong Value, uint Shift)
{
	return _rotr64(Value, Shift);
}

#elif defined(CEX_PPC_INTRINSICS) && defined(CEX_FASTROTATE_ENABLED)

uint IntUtils::RotL32(uint Value, uint Shift)
{
	return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
}

ulong IntUtils::RotL64(ulong Value, uint Shift)
{
	return Shift ? __rlwinm(Value, Shift, 0, 63) : Value;
}

uint IntUtils::RotR32(uint Value, uint Shift)
{
	return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
}

ulong IntUtils::RotR64(ulong Value, uint Shift)
{
	return Shift ? __rlwinm(Value, 64 - Shift, 0, 63) : Value;
}

uint IntUtils::RotFL32(uint Value, uint Shift)
{
	return __rlwinm(Value, Shift, 0, 31);
}

ulong IntUtils::RotFL64(ulong Value, uint Shift)
{
	return (Value << Shift) | ((long)((ulong)Value >> -Shift));
}

uint IntUtils::RotFR32(uint Value, uint Shift)
{
	return __rlwinm(Value, 32 - Shift, 0, 31);
}

ulong IntUtils::RotFR64(ulong Value, uint Shift)
{
	return ((Value >> Shift) | (Value << (64 - Shift)));
}

#else

uint IntUtils::RotL32(uint Value, uint Shift)
{
	return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
}

ulong IntUtils::RotL64(ulong Value, uint Shift)
{
	return (Value << Shift) | (Value >> (sizeof(ulong) * 8 - Shift));
}

uint IntUtils::RotR32(uint Value, uint Shift)
{
	return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
}

ulong IntUtils::RotR64(ulong Value, uint Shift)
{
	return (Value >> Shift) | (Value << (sizeof(ulong) * 8 - Shift));
}

uint IntUtils::RotFL32(uint Value, uint Shift)
{
	return (Value << Shift) | (Value >> (32 - Shift));
}

ulong IntUtils::RotFL64(ulong Value, uint Shift)
{
	return (Value << Shift) | (Value >> (64 - Shift));
}

uint IntUtils::RotFR32(uint Value, uint Shift)
{
	return (Value >> Shift) | (Value << (32 - Shift));
}

ulong IntUtils::RotFR64(ulong Value, uint Shift)
{
	return ((Value >> Shift) | (Value << (64 - Shift)));
}

#endif

std::vector<byte> IntUtils::StripLeadingZeros(const std::vector<byte> &Input, size_t Length)
{
	size_t leading = 0;
	byte zeros = 0xFF;

	for (size_t i = 0; i != Length; ++i)
	{
		zeros &= IsZero<byte>(Input[i]);
		leading += Select<byte>(zeros, 1, 0);
	}

	return std::vector<byte>(Input[leading], Input[Length]);
}

std::vector<byte> IntUtils::ToBit16(ushort Value)
{
	std::vector<byte> data(2);
	Le16ToBytes(Value, data, 0);
	return data;
}

std::vector<byte> IntUtils::ToBit32(uint Value)
{
	std::vector<byte> data(4);
	Le32ToBytes(Value, data, 0);
	return data;
}

std::vector<byte> IntUtils::ToBit64(ulong Value)
{
	std::vector<byte> data(8);
	Le64ToBytes(Value, data, 0);
	return data;
}

ushort IntUtils::ToInt16(std::vector<byte> Input)
{
	return BytesToLe16(Input, 0);
}

uint IntUtils::ToInt32(std::vector<byte> Input)
{
	return BytesToLe32(Input, 0);
}

ulong IntUtils::ToInt64(std::vector<byte> Input)
{
	return BytesToLe64(Input, 0);
}

ushort IntUtils::ToInt16(std::vector<byte> Input, size_t InOffset)
{
	return BytesToLe16(Input, InOffset);
}

uint IntUtils::ToInt32(std::vector<byte> Input, size_t InOffset)
{
	return BytesToLe32(Input, InOffset);
}

ulong IntUtils::ToInt64(std::vector<byte> Input, size_t InOffset)
{
	return BytesToLe64(Input, InOffset);
}

void IntUtils::Word64sToBytes(const std::vector<ulong> &Input, std::vector<byte> &Output)
{
	if (Output.size() != Input.size() * sizeof(ulong))
		Output.resize(Input.size() * sizeof(ulong), 0);
	memcpy(&Output[0], &Input[0], Output.size());
}

void IntUtils::BytesToWord64s(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<ulong> &Output)
{
	if (Output.size() != (Input.size() - InOffset) * sizeof(ulong))
		Output.resize(Length / sizeof(ulong));
	memcpy(&Output[0], &Input[InOffset], Length);
}

void IntUtils::XOR128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, SimdProfiles SimdProfile)
{
	if (SimdProfile != SimdProfiles::None)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
	}
	else
	{
		Output[OutOffset] ^= Input[InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
	}
}

void IntUtils::XOR256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, SimdProfiles SimdProfile)
{
	if (SimdProfile == SimdProfiles::Simd256)
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
	}
	else if (SimdProfile == SimdProfiles::Simd128)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 16])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 16]))));
	}
	else
	{
		Output[OutOffset] ^= Input[InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
	}
}

void IntUtils::XORULL256(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile)
{
	if (SimdProfile == SimdProfiles::Simd256)
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
	}
	else if (SimdProfile == SimdProfiles::Simd128)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 2])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]))));
	}
	else
	{
		Output[OutOffset] ^= Input[InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
	}
}

void IntUtils::XORULL512(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile)
{
	if (SimdProfile == SimdProfiles::Simd256)
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset + 4]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset + 4])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset + 4]))));
	}
	else if (SimdProfile == SimdProfiles::Simd128)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 2])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 4]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 4])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 4]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 6]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 6])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 6]))));
	}
	else
	{
		Output[OutOffset] ^= Input[InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
	}
}

void IntUtils::XORULL1024(const std::vector<ulong> &Input, size_t InOffset, std::vector<ulong> &Output, size_t OutOffset, SimdProfiles SimdProfile)
{
	if (SimdProfile == SimdProfiles::Simd256)
	{
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset]))));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset + 4]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset + 4])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset + 4]))));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset + 8]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset + 8])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset + 8]))));
		_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[OutOffset + 12]), _mm256_xor_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[InOffset + 12])), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Output[OutOffset + 12]))));
	}
	else if (SimdProfile == SimdProfiles::Simd128)
	{
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 2])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 2]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 4]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 4])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 4]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 6]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 6])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 6]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 8]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 8])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 8]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 10]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 10])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 10]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 12]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 12])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 12]))));
		_mm_storeu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 14]), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(&Input[InOffset + 14])), _mm_loadu_si128(reinterpret_cast<__m128i*>(&Output[OutOffset + 14]))));
	}
	else
	{
		Output[OutOffset] ^= Input[InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
		Output[++OutOffset] ^= Input[++InOffset];
	}
}

void IntUtils::XORBLK(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length, SimdProfiles SimdProfile)
{
	const size_t BLOCK16 = 16;
	const size_t BLOCK32 = 32;
	size_t blkCtr = 0;

	do
	{
		if ((Length - blkCtr) < BLOCK32)
		{
			XOR128(Input, InOffset + blkCtr, Output, OutOffset + blkCtr, SimdProfile);
			blkCtr += BLOCK16;
		}
		else
		{
			XOR256(Input, InOffset + blkCtr, Output, OutOffset + blkCtr, SimdProfile);
			blkCtr += BLOCK32;
		}

	} while (blkCtr != Length);
}

void IntUtils::XORPRT(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length)
{
	size_t ctr = 0;

	while (ctr != Length)
	{
		Output[OutOffset + ctr] ^= Input[InOffset + ctr];
		++ctr;
	}
}



NAMESPACE_UTILITYEND