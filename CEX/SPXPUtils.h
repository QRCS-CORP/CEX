// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
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

#ifndef CEX_SPHINCSUTILS_H
#define CEX_SPHINCSUTILS_H

#include "CexDomain.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include <functional>

/// 
/// internal
/// 

NAMESPACE_SPHINCSPLUS

using Digest::Keccak;
using Utility::MemoryTools;

/// <summary>
// An internal SphincsPlus+ utilities class
/// </summary>
class SPXPUtils
{
private:

	static const size_t SPX_ADDR_BYTES = 32;

public:

	//~~~Inlined~~~//

	inline static void CopyKeypairAddress(const std::array<uint, 8> &Input, std::array<uint, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
		Output[5] = Input[5];
	}

	inline static void CopySubtreeAddress(const std::array<uint, 8> &Input, std::array<uint, 8> &Output)
	{
		Output[0] = Input[0];
		Output[1] = Input[1];
		Output[2] = Input[2];
		Output[3] = Input[3];
	}

	inline static void SetChainAddress(std::array<uint, 8> &Address, uint Chain)
	{
		Address[6] = Chain;
	}

	inline static void SetHashAddress(std::array<uint, 8> &Address, uint Hash)
	{
		Address[7] = Hash;
	}

	inline static void SetKeypairAddress(std::array<uint, 8> &Address, uint32_t Keypair)
	{
		Address[5] = Keypair;
	}

	inline static void SetLayerAddress(std::array<uint, 8> &Address, uint Layer)
	{
		Address[0] = Layer;
	}

	inline static void SetTreeAddress(std::array<uint, 8> &Address, ulong Tree)
	{
		Address[1] = 0;
		Address[2] = static_cast<uint>(Tree >> 32);
		Address[3] = static_cast<uint>(Tree);
	}

	inline static void SetTreeHeight(std::array<uint, 8> &Address, uint TreeHeight)
	{
		Address[6] = TreeHeight;
	}

	inline static void SetTreeIndex(std::array<uint, 8> &Address, uint TreeIndex)
	{
		Address[7] = TreeIndex;
	}

	inline static void SetType(std::array<uint, 8> &Address, uint Type)
	{
		Address[4] = Type;
	}

	//~~~Static~~~//

	static void AddressToBytes(std::vector<byte> &Output, size_t Offset, const std::array<uint, 8> &Address);

	static ulong BytesToUll(const std::vector<byte> &Input, size_t Offset, size_t Length);

	static void PrfAddress(std::vector<byte> &Output, size_t Offset, const std::vector<byte> &Key, const std::array<uint, 8> &Address, size_t N);

	static void THash(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const size_t InputBlocks,
		const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::vector<byte> &Buffer, std::vector<byte> &Mask, size_t N);

	static void TreeHash(std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed,
		uint LeafIndex, uint IndexOffset, uint TreeHeight, std::array<uint, 8> &TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights, size_t N,
		std::function<void(std::vector<byte> &,
			size_t,
			const std::vector<byte> &,
			const std::vector<byte> &,
			uint, std::array<uint, 8> &,
			size_t)> &LeafGen);

	static void UllToBytes(std::vector<byte> &Output, size_t Offset, ulong Value, size_t Length);

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
};

NAMESPACE_SPHINCSEND
#endif
