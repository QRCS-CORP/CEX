#include "SphincsUtils.h"

NAMESPACE_SPHINCS

ulong SphincsUtils::BytesToUll(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	size_t i;
	ulong val;

	val = 0;

	for (i = 0; i < Length; i++)
	{
		val |= (static_cast<ulong>(Input[Offset + i]) << (8 * (Length - 1 - i)));
	}

	return val;
}

void SphincsUtils::UllToBytes(std::vector<byte> &Output, size_t Offset, ulong Value, size_t Length)
{
	size_t i;

	i = Length;

	do
	{
		--i;
		Output[Offset + i] = Value & 0xFF;
		Value = Value >> 8;
	} 
	while (i != 0);
}

NAMESPACE_SPHINCSEND