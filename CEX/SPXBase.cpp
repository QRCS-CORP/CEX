#include "SPXBase.h"

NAMESPACE_SPHINCSPLUS
	
	// Utils

	void SPXBase::CopyKeypairAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
		Output[5] = Input[5];
	}

	void SPXBase::CopySubtreeAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
	}

	void SPXBase::SetChainAddress(std::array<uint32_t, 8> &Address, uint32_t Chain)
	{
		Address[6] = Chain;
	}

	void SPXBase::SetHashAddress(std::array<uint32_t, 8> &Address, uint32_t Hash)
	{
		Address[7] = Hash;
	}

	void SPXBase::SetKeypairAddress(std::array<uint32_t, 8> &Address, uint32_t Keypair)
	{
		Address[5] = Keypair;
	}

	void SPXBase::SetLayerAddress(std::array<uint32_t, 8> &Address, uint32_t Layer)
	{
		Address[0] = Layer;
	}

	void SPXBase::SetTreeAddress(std::array<uint32_t, 8> &Address, uint64_t Tree)
	{
		Address[1] = 0;
		Address[2] = static_cast<uint32_t>(Tree >> 32);
		Address[3] = static_cast<uint32_t>(Tree);
	}

	void SPXBase::SetTreeHeight(std::array<uint32_t, 8> &Address, uint32_t TreeHeight)
	{
		Address[6] = TreeHeight;
	}

	void SPXBase::SetTreeIndex(std::array<uint32_t, 8> &Address, uint32_t TreeIndex)
	{
		Address[7] = TreeIndex;
	}

	void SPXBase::SetType(std::array<uint32_t, 8> &Address, uint32_t Type)
	{
		Address[4] = Type;
	}

	void SPXBase::UllToBytes(std::vector<uint8_t> &Output, size_t Offset, uint64_t Value, size_t Length)
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

	void SPXBase::AddressToBytes(std::vector<uint8_t> &Output, size_t Offset, const std::array<uint32_t, 8> &Address)
	{
		size_t i;

		for (i = 0; i < Address.size(); ++i)
		{
			IntegerTools::Be32ToBytes(Address[i], Output, Offset + (i * 4));
		}
	}

	uint64_t SPXBase::BytesToUll(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
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

	void SPXBase::PrfAddress(std::vector<uint8_t> &Output, size_t Offset, const std::vector<uint8_t> &Key, const std::array<uint32_t, 8> &Address, size_t N)
	{
		std::vector<uint8_t> buf(N + SPX_ADDR_BYTES);

		MemoryTools::Copy(Key, 0, buf, 0, N);
		AddressToBytes(buf, N, Address);
		XOF(buf, 0, buf.size(), Output, Offset, N, Keccak::KECCAK256_RATE_SIZE);
	}

	void SPXBase::XOF(const std::vector<uint8_t> &Input, size_t InOffset, size_t InLength, std::vector<uint8_t> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
	{
		Keccak::XOFP1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
	}

NAMESPACE_SPHINCSPLUSEND
