#include "SphincsUtils.h"

NAMESPACE_SPHINCS

ulong SphincsUtils::BytesToUll(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	size_t i;
	ulong val;

	val = 0;

	for (i = 0; i < Length; i++)
	{
		val |= ((ulong)Input[Offset + i]) << (8 * (Length - 1 - i));
	}

	return val;
}

void SphincsUtils::CopyKeypairAddress(const std::array<uint, 8> &Input, std::array<uint, 8> &Output)
{
	Output[0] = Input[0];
	Output[1] = Input[1];
	Output[2] = Input[2];
	Output[3] = Input[3];
	Output[5] = Input[5];
}

void SphincsUtils::CopySubtreeAddress(const std::array<uint, 8> &Input, std::array<uint, 8> &Output)
{
	Output[0] = Input[0];
	Output[1] = Input[1];
	Output[2] = Input[2];
	Output[3] = Input[3];
}

void SphincsUtils::SetChainAddress(std::array<uint, 8> &Address, uint Chain)
{
	Address[6] = Chain;
}

void SphincsUtils::SetHashAddress(std::array<uint, 8> &Address, uint Hash)
{
	Address[7] = Hash;
}

void SphincsUtils::SetKeypairAddress(std::array<uint, 8> &Address, uint32_t Keypair)
{
	Address[5] = Keypair;
}

void SphincsUtils::SetLayerAddress(std::array<uint, 8> &Address, uint Layer)
{
	Address[0] = Layer;
}

void SphincsUtils::SetTreeAddress(std::array<uint, 8> &Address, ulong Tree)
{
	Address[1] = 0;
	Address[2] = static_cast<uint>(Tree >> 32);
	Address[3] = static_cast<uint>(Tree);
}

void SphincsUtils::SetTreeHeight(std::array<uint, 8> &Address, uint TreeHeight)
{
	Address[6] = TreeHeight;
}

void SphincsUtils::SetTreeIndex(std::array<uint, 8> &Address, uint TreeIndex)
{
	Address[7] = TreeIndex;
}

void SphincsUtils::SetType(std::array<uint, 8> &Address, uint Type)
{
	Address[4] = Type;
}

void SphincsUtils::UllToBytes(std::vector<byte> &Output, size_t Offset, ulong Value, uint32_t Length)
{
	int i;

	// iterate over out in decreasing order, for big-endianness
	for (i = Length - 1; i >= 0; i--)
	{
		Output[Offset + i] = Value & 0xFF;
		Value = Value >> 8;
	}
}

NAMESPACE_SPHINCSEND