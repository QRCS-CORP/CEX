#include "SkeinUbiTweak.h"

NAMESPACE_DIGEST

ulong SkeinUbiTweak::BitsProcessed(const std::vector<ulong> &Tweak)
{
	return Tweak[0];
}

SkeinUbiType SkeinUbiTweak::BlockType(const std::vector<ulong> &Tweak)
{
	return static_cast<SkeinUbiType>(Tweak[1] >> 56);
}

void SkeinUbiTweak::BlockType(std::vector<ulong> &Tweak, SkeinUbiType Value)
{
	Tweak[1] = static_cast<ulong>(Value) << 56;
}

bool SkeinUbiTweak::IsFinalBlock(const std::vector<ulong> &Tweak)
{
	return (Tweak[1] & T1_FINAL) != 0;
}

void SkeinUbiTweak::IsFinalBlock(std::vector<ulong> &Tweak, ulong Value)
{
	long mask = Value ? 1 : 0;
	Tweak[1] = (Tweak[1] & ~T1_FINAL) | (static_cast<ulong>(-mask & T1_FINAL));
}

bool SkeinUbiTweak::IsFirstBlock(const std::vector<ulong> &Tweak)
{
	return (Tweak[1] & T1_FIRST) != 0;
}

void SkeinUbiTweak::IsFirstBlock(std::vector<ulong> &Tweak, bool Value)
{
	long mask = Value ? 1 : 0;
	Tweak[1] = (Tweak[1] & ~T1_FIRST) | (static_cast<ulong>(-mask & T1_FIRST));
}

byte SkeinUbiTweak::TreeLevel(const std::vector<ulong> &Tweak)
{
	return static_cast<ulong>((Tweak[1] >> 48) & 0x3F);
}

void SkeinUbiTweak::TreeLevel(std::vector<ulong> &Tweak, byte Value)
{
	if (Value > 63)
	{
		throw Exception::CryptoDigestException("Skein:TreeLevel", "Tree level must be between 0 and 63, inclusive.");
	}

	Tweak[1] &= ~(static_cast<ulong>(0x3f) << 48);
	Tweak[1] |= static_cast<ulong>(Value) << 48;
}

void SkeinUbiTweak::SetTweak(std::vector<ulong> &Tweak, const std::vector<ulong> &Value)
{
	Tweak = Value;
}

void SkeinUbiTweak::StartNewBlockType(std::vector<ulong> &Tweak, const SkeinUbiType Value)
{
	Tweak[0] = 0;
	BlockType(Tweak, Value);
	IsFirstBlock(Tweak, true);
}

void SkeinUbiTweak::SetBitsProcessed(std::vector<ulong> &Tweak, ulong Value)
{
	Tweak[0] = Value;
}

NAMESPACE_DIGESTEND