#include "SPXPUtils.h"

NAMESPACE_SPHINCSPLUS

void SPXPUtils::AddressToBytes(std::vector<uint8_t> &Output, size_t Offset, const std::array<uint32_t, 8> &Address)
{
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		UllToBytes(Output, Offset + (i * 4), Address[i], 4);
	}
}

uint64_t SPXPUtils::BytesToUll(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	size_t i;
	uint64_t val;

	val = 0;

	for (i = 0; i < Length; i++)
	{
		val |= (static_cast<uint64_t>(Input[Offset + i]) << (8 * (Length - 1 - i)));
	}

	return val;
}

void SPXPUtils::PrfAddress(std::vector<uint8_t> &Output, size_t Offset, const std::vector<uint8_t> &Key, const std::array<uint32_t, 8> & Address, size_t N)
{
	std::vector<uint8_t> buf(N + SPX_ADDR_BYTES);

	MemoryTools::Copy(Key, 0, buf, 0, N);
	SPXPUtils::AddressToBytes(buf, N, Address);
	XOF(buf, 0, buf.size(), Output, Offset, N, Keccak::KECCAK256_RATE_SIZE);
}

void SPXPUtils::THash(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
	const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> & Address, std::vector<uint8_t> &Buffer, std::vector<uint8_t> &Mask, size_t N)
{
	size_t i;

	MemoryTools::Clear(Buffer, 0, Buffer.size());
	MemoryTools::Clear(Mask, 0, Mask.size());
	MemoryTools::Copy(PkSeed, 0, Buffer, 0, N);
	SPXPUtils::AddressToBytes(Buffer, N, Address);

	std::vector<uint8_t> k(N + SPX_ADDR_BYTES);
	MemoryTools::Copy(Buffer, 0, k, 0, k.size());

	Keccak::XOFP1600(k, 0, k.size(), Mask, 0, InputBlocks * N, Keccak::KECCAK256_RATE_SIZE);

	for (i = 0; i < InputBlocks * N; ++i)
	{
		Buffer[N + SPX_ADDR_BYTES + i] = Input[InOffset + i] ^ Mask[i];
	}

	k.resize(N + SPX_ADDR_BYTES + InputBlocks * N);
	MemoryTools::Copy(Buffer, 0, k, 0, k.size());

	Keccak::XOFP1600(k, 0, k.size(), Output, OutOffset, N, Keccak::KECCAK256_RATE_SIZE);
}

void SPXPUtils::TreeHash(std::vector<uint8_t> &Root, size_t RootOffset, std::vector<uint8_t> &Authpath, size_t AuthOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed,
	uint32_t LeafIndex, uint32_t IndexOffset, uint32_t TreeHeight, std::array<uint32_t, 8> & TreeAddress, std::vector<uint8_t> &Stack, std::vector<uint32_t> &Heights, size_t N,
	std::function<void(std::vector<uint8_t> &,
		size_t,
		const std::vector<uint8_t> &,
		const std::vector<uint8_t> &,
		uint32_t, std::array<uint32_t, 8> &,
		size_t)> &LeafGen)
{
	std::vector<uint8_t> buf(N + SPX_ADDR_BYTES + 2 * N);
	std::vector<uint8_t> leaf(N);
	std::vector<uint8_t> mask(2 * N);
	size_t offset;
	uint32_t idx;
	uint32_t treeidx;

	offset = 0;

	for (idx = 0; idx < static_cast<uint32_t>(1 << TreeHeight); ++idx)
	{
		// add the next (fors or wots) leaf node to the stack
		LeafGen(leaf, 0, SkSeed, PkSeed, idx + IndexOffset, TreeAddress, N);
		MemoryTools::Copy(leaf, 0, Stack, offset * N, N);
		++offset;
		Heights[offset - 1] = 0;

		// if this is a node we need for the auth path
		if ((LeafIndex ^ 0x1) == idx)
		{
			MemoryTools::Copy(Stack, ((offset - 1) * N), Authpath, AuthOffset, N);
		}

		// while the top-most nodes are of equal height
		while (offset >= 2 && Heights[offset - 1] == Heights[offset - 2])
		{
			// compute index of the new node, in the next layer
			treeidx = (idx >> (Heights[offset - 1] + 1));
			// set the address of the node we're creating
			SetTreeHeight(TreeAddress, Heights[offset - 1] + 1);
			SetTreeIndex(TreeAddress, treeidx + (IndexOffset >> (Heights[offset - 1] + 1)));
			// hash the top-most nodes from the stack together
			THash(Stack, ((offset - 2) * N), Stack, ((offset - 2) * N), 2, PkSeed, TreeAddress, buf, mask, N);
			--offset;
			// note that the top-most node is now one layer higher
			++Heights[offset - 1];

			// if this is a node we need for the auth path
			if (((LeafIndex >> Heights[offset - 1]) ^ 0x1) == treeidx)
			{
				MemoryTools::Copy(Stack, (offset - 1) * N, Authpath, AuthOffset + (N * Heights[offset - 1]), N);
			}
		}
	}

	MemoryTools::Copy(Stack, 0, Root, RootOffset, N);
}

void SPXPUtils::UllToBytes(std::vector<uint8_t> &Output, size_t Offset, uint64_t Value, size_t Length)
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

void SPXPUtils::XOF(const std::vector<uint8_t> &Input, size_t InOffset, size_t InLength, std::vector<uint8_t> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFP1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

NAMESPACE_SPHINCSEND