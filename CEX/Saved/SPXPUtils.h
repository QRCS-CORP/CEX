// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_SPXBASE_H
#define CEX_SPXBASE_H

#include "CexDomain.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include <functional>

/// 
/// internal
/// 

NAMESPACE_SPHINCSPLUS

using Digest::Keccak;
using Tools::MemoryTools;

/// <summary>
// An internal Sphincs+ utilities class
/// </summary>
class SPXPUtils
{
private:

	static const uint32_t SPX_OFFSET_LAYER = 3;
	static const uint32_t SPX_OFFSET_TREE = 8;
	static const uint32_t SPX_OFFSET_TYPE = 19;
	static const uint32_t SPX_OFFSET_KP_ADDR2 = 22;
	static const uint32_t SPX_OFFSET_KP_ADDR1 = 23;
	static const uint32_t SPX_OFFSET_CHAIN_ADDR = 27;
	static const uint32_t SPX_OFFSET_HASH_ADDR = 31;
	static const uint32_t SPX_OFFSET_TREE_HGT = 27;
	static const uint32_t SPX_OFFSET_TREE_INDEX = 28;
	static const size_t SPX_ADDR_BYTES = 32;

public:
	
	inline static void CopyKeypairAddressV2(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output, uint32_t D, uint32_t Height)
	{
		//qsc_memutils_copy((uint8_t*)out, (const uint8_t*)in, SPX_OFFSET_TREE + 8);
		MemoryTools::Copy(Input, 0, Output, 0, SPX_OFFSET_TREE + 8);

		if (Height / D > 8)
		{
			//((uint8_t*)out)[SPX_OFFSET_KP_ADDR2] = ((uint8_t*)in)[SPX_OFFSET_KP_ADDR2];
			MemoryTools::CopyRaw((uint8_t*)Input.data() + SPX_OFFSET_KP_ADDR2, (uint8_t*)Output.data() + SPX_OFFSET_KP_ADDR2, 1);
			//Output[5] = Input[5];
		}
		else
		{
			//((uint8_t*)out)[SPX_OFFSET_KP_ADDR1] = ((const uint8_t*)in)[SPX_OFFSET_KP_ADDR1];
			MemoryTools::CopyRaw((uint8_t*)Input.data() + SPX_OFFSET_KP_ADDR1, (uint8_t*)Output.data() + SPX_OFFSET_KP_ADDR1, 1);
		}

		//Output[0] = Input[0];
		//Output[1] = Input[1];
		//Output[2] = Input[2];
		//Output[3] = Input[3];
	}

	inline static void CopyKeypairAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
		Output[5] = Input[5];
	}

	inline static void CopySubtreeAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
	}

	inline static void SetChainAddress(std::array<uint32_t, 8> &Address, uint32_t Chain)
	{
		Address[6] = Chain;
	}

	inline static void SetHashAddress(std::array<uint32_t, 8> &Address, uint32_t Hash)
	{
		Address[7] = Hash;
	}

	inline static void SetKeypairAddress(std::array<uint32_t, 8> &Address, uint32_t Keypair)
	{
		Address[5] = Keypair;
	}

	inline static void SetLayerAddress(std::array<uint32_t, 8> &Address, uint32_t Layer)
	{
		Address[0] = Layer;
	}

	inline static void SetTreeAddress(std::array<uint32_t, 8> &Address, uint64_t Tree)
	{
		Address[1] = 0;
		Address[2] = static_cast<uint32_t>(Tree >> 32);
		Address[3] = static_cast<uint32_t>(Tree);
	}

	inline static void SetTreeHeight(std::array<uint32_t, 8> &Address, uint32_t TreeHeight)
	{
		Address[6] = TreeHeight;
	}

	inline static void SetTreeIndex(std::array<uint32_t, 8> &Address, uint32_t TreeIndex)
	{
		Address[7] = TreeIndex;
	}

	inline static void SetType(std::array<uint32_t, 8> &Address, uint32_t Type)
	{
		Address[4] = Type;
	}

	//~~~Static~~~//

	static void AddressToBytes(std::vector<uint8_t> &Output, size_t Offset, const std::array<uint32_t, 8> &Address);

	static uint64_t BytesToUll(const std::vector<uint8_t> &Input, size_t Offset, size_t Length);

	static void PrfAddress(std::vector<uint8_t> &Output, size_t Offset, const std::vector<uint8_t> &Key, const std::array<uint32_t, 8> &Address, size_t N);

	static void THash(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, std::vector<uint8_t> &Buffer, std::vector<uint8_t> &Mask, size_t N);

	static void TreeHash(std::vector<uint8_t> &Root, size_t RootOffset, std::vector<uint8_t> &Authpath, size_t AuthOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed,
		uint32_t LeafIndex, uint32_t IndexOffset, uint32_t TreeHeight, std::array<uint32_t, 8> &TreeAddress, std::vector<uint8_t> &Stack, std::vector<uint32_t> &Heights, size_t N,
		std::function<void(std::vector<uint8_t> &,
			size_t,
			const std::vector<uint8_t> &,
			const std::vector<uint8_t> &,
			uint32_t, std::array<uint32_t, 8> &,
			size_t)> &LeafGen);

	static void UllToBytes(std::vector<uint8_t> &Output, size_t Offset, uint64_t Value, size_t Length);

	static void XOF(const std::vector<uint8_t> &Input, size_t InOffset, size_t InLength, std::vector<uint8_t> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
};

NAMESPACE_SPHINCSEND
#endif
