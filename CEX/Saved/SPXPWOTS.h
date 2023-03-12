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

#ifndef CEX_WOTS_H
#define CEX_WOTS_H

#include "CexDomain.h"
#include "MemoryTools.h"
#include "SPXPUtils.h"

NAMESPACE_SPHINCSPLUS

using Digest::Keccak;
using Tools::MemoryTools;

/// 
/// internal
/// 

/// <summary>
// The Winternitz One Time Signature utilities
/// </summary>
class SPXPWOTS
{
private:

	static const size_t SPX_ADDR_BYTES = 32;
	static const size_t SPX_WOTS_LEN2 = 3;
	static const size_t SPX_WOTS_LOGW = 4;
	static const size_t SPX_WOTS_W = 16;
	static const size_t SPX_ADDR_TYPE_WOTS = 0;
	static const size_t SPX_ADDR_TYPE_WOTSPK = 1;

public:

	static void BaseW(std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<uint8_t> &Input);

	static void ChainLengths(std::vector<int32_t> &Lengths, const std::vector<uint8_t> &Message, size_t N);

	static void GenChain(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, uint32_t Start, uint32_t Steps,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t N);

	static void THash(std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t BufLen, std::vector<uint8_t> &Mask, size_t N);

	static void WotsChecksum(std::vector<int32_t> &CSumBaseW, size_t BaseOffset, const std::vector<int32_t> &MsgBaseW, size_t N);

	static void WotsGenLeaf(std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, uint32_t AddressIndex,
		const std::array<uint32_t, 8> &TreeAddress, size_t N);

	static void WotsGenPk(std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t N);

	static void WotsGenSk(std::vector<uint8_t> &Key, size_t Offset, const std::vector<uint8_t> &KeySeed, std::array<uint32_t, 8> &WotsAddress, size_t N);

	static void WotsPkFromSig(std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &PrivateSeed, std::array<uint32_t, 8> &Address, size_t N);

	static void WotsSign(std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &SecretSeed,
		const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> &Address, size_t N);
};

NAMESPACE_SPHINCSEND
#endif
