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

NAMESPACE_SPHINCS

/// 
/// internal
/// 

/// <summary>
// An internal Sphincs+ utilities class
/// </summary>
class SphincsUtils
{
public:

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

	static ulong BytesToUll(const std::vector<byte> &Input, size_t Offset, size_t Length);

	static void UllToBytes(std::vector<byte> &Output, size_t Offset, ulong Value, size_t Length);
};

NAMESPACE_SPHINCSEND
#endif
