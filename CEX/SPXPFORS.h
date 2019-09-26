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
using Utility::MemoryTools;

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

	static void ComputeRoot(std::vector<byte> &Root, size_t RootOffset, const std::vector<byte> &Leaf, uint LeafOffset, uint IdxOffset, const std::vector<byte> &AuthPath,
		size_t AuthOffset, uint TreeHeight, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, size_t N);

	static void ForsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, uint AddressIdx,
		const std::array<uint, 8> &TreeAddress, size_t N);

	static void ForsGenSk(std::vector<byte> &Secret, size_t SecretOffset, const std::vector<byte> &Seed, std::array<uint, 8> &Address, size_t N);

	static void ForsPkFromSig(std::vector<byte> &PublicKey, size_t PubKeyOffset, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message,
		const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, uint ForsHeight, size_t ForsTrees, size_t N);

	static void ForsSign(std::vector<byte> &Signature, size_t SigOffset, std::vector<byte> &PublicKey, const std::vector<byte> &Message,
		const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, size_t ForsHeight, size_t ForsTrees, size_t N);

	static void ForsSkToLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretKey, size_t KeyOffset, const std::vector<byte> &PublicSeed, std::array<uint, 8> &LeafAddress, size_t N);

	static void GenMessageRandom(const std::vector<byte> &SkPrf, const std::vector<byte> &OptRnd, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t N);

	static void HashMessage(std::vector<byte> &Digest, ulong &Tree, uint &LeafIndex, const std::vector<byte> &Rand, const std::vector<byte> &PublicKey,
		std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t ForsHeight, size_t ForsTrees, size_t N);

	static void MessageToIndices(std::vector<uint> &Indices, const std::vector<byte> &Messages, size_t ForsHeight, size_t ForsTrees);
};

NAMESPACE_SPHINCSEND
#endif
