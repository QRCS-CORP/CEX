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

#ifndef CEX_FORS_H
#define CEX_FORS_H

#include "CexDomain.h"
#include "MemoryTools.h"
#include "SPXPUtils.h"

/// 
/// internal
/// 

NAMESPACE_SPHINCSPLUS

using Digest::Keccak;
using Tools::MemoryTools;

/// <summary>
// An SPXPFORS (Forest of Random Subsets) utilities class
/// </summary>
class SPXPFORS
{
private:

	static const size_t SPX_ADDR_BYTES = 32;
	static const size_t SPX_ADDR_TYPE_FORSTREE = 3;
	static const size_t SPX_ADDR_TYPE_FORSPK = 4;
	static const size_t SPX_D = 8;
	static const size_t SPX_FULL_HEIGHT = 64;
	static const size_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);

public:

	static void ComputeRoot(std::vector<uint8_t> &Root, size_t RootOffset, const std::vector<uint8_t> &Leaf, uint32_t LeafOffset, uint32_t IdxOffset, const std::vector<uint8_t> &AuthPath,
		size_t AuthOffset, uint32_t TreeHeight, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t N);

	static void ForsGenLeaf(std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, uint32_t AddressIdx,
		const std::array<uint32_t, 8> &TreeAddress, size_t N);

	static void ForsGenSk(std::vector<uint8_t> &Secret, size_t SecretOffset, const std::vector<uint8_t> &Seed, std::array<uint32_t, 8> &Address, size_t N);

	static void ForsPkFromSig(std::vector<uint8_t> &PublicKey, size_t PubKeyOffset, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress, uint32_t ForsHeight, size_t ForsTrees, size_t N);

	static void ForsSign(std::vector<uint8_t> &Signature, size_t SigOffset, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress, size_t ForsHeight, size_t ForsTrees, size_t N);

	static void ForsSkToLeaf(std::vector<uint8_t> &Leaf, const std::vector<uint8_t> &SecretKey, size_t KeyOffset, const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> &LeafAddress, size_t N);

	static void GenMessageRandom(const std::vector<uint8_t> &SkPrf, const std::vector<uint8_t> &OptRnd, std::vector<uint8_t> &Message, size_t MsgOffset, size_t MsgLength, size_t N);

	static void HashMessage(std::vector<uint8_t> &Digest, uint64_t &Tree, uint32_t &LeafIndex, const std::vector<uint8_t> &Rand, const std::vector<uint8_t> &PublicKey,
		std::vector<uint8_t> &Message, size_t MsgOffset, size_t MsgLength, size_t ForsHeight, size_t ForsTrees, size_t N);

	static void MessageToIndices(std::vector<uint32_t> &Indices, const std::vector<uint8_t> &Messages, size_t ForsHeight, size_t ForsTrees);
};

NAMESPACE_SPHINCSEND
#endif
