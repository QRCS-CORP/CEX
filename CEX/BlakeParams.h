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

#ifndef CEX_BLAKEPARAMS_H
#define CEX_BLAKEPARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"
#include "IntegerTools.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Tools::IntegerTools;

/// <summary>
/// The parallel Blake2 parameters structure
/// </summary> 
struct BlakeParams
{
private:

	static const std::string CLASS_NAME;
	static const size_t HDR_BASE = 12;

	// 256=12, 512=40
	std::vector<uint8_t> m_dstCode;
	uint8_t m_fanOut;
	uint8_t m_innerLen;
	uint8_t m_keyLen;
	uint32_t m_leafSize;
	uint8_t m_maxDepth;
	uint8_t m_nodeDepth;
	uint8_t m_nodeOffset;
	uint8_t m_outputSize;
	uint8_t m_reserved;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; state is initialized to zero defaults
	/// </summary>
	BlakeParams();

	/// <summary>
	/// Initialize the MessageHeader structure using a serialized uint8_t array
	/// </summary>
	///
	/// <param name="TreeArray">A serialized BlakeParams structure</param>
	explicit BlakeParams(const std::vector<uint8_t> &TreeArray);

	/// <summary>
	/// Initialize the default structure.
	/// <para>Default settings are sequential mode.</para>
	/// </summary>
	///
	/// <param name="OutputSize">Digest output uint8_t length; set to 32 for Blake2-256, or 64 for Blake2-512</param>
	/// <param name="TreeDepth">Maximal depth (1 uint8_t): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (limit of one state per processor core is recommended)</param>
	/// <param name="LeafSize">The outer leaf length in bytes; set to 0 for unlimited</param>
	/// <param name="InnerLength">Inner hash uint8_t length (1 uint8_t): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
	explicit BlakeParams(uint8_t OutputSize, uint8_t TreeDepth = 1, uint8_t Fanout = 1, uint8_t LeafSize = 0, uint8_t InnerLength = 0);

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="OutputSize">Digest output uint8_t length (1 uint8_t): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s</param>
	/// <param name="KeyLength">Key uint8_t length (1 uint8_t): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)</param>
	/// <param name="FanOut">Fanout (1 uint8_t): an integer in [0, 255] set to the number of desired threads for parallel mode, set to 1 or 0 for sequential mode</param>
	/// <param name="MaxDepth">Maximal depth (1 uint8_t): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
	/// <param name="LeafLength">Leaf maximal uint8_t length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)</param>
	/// <param name="NodeOffset">Node offset (1 uint8_t): an integer in [0, 256 −1] (set to 0 for the first, leftmost, leaf, or in sequential mode)</param>
	/// <param name="NodeDepth">Node depth (1 uint8_t): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)</param>
	/// <param name="InnerLength">Inner hash uint8_t length (1 uint8_t): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
	/// <param name="DistributionCode">The optional personalization string; must be no longer than DistributionCodeMax in size</param>
	BlakeParams(uint8_t OutputSize, uint8_t KeyLength, uint8_t FanOut, uint8_t MaxDepth, uint32_t LeafLength, uint8_t NodeOffset, uint8_t NodeDepth, uint8_t InnerLength, std::vector<uint8_t> &DistributionCode);

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Fanout (1 uint8_t): an integer in [0, 255] set to the number of desired threads for parallel mode, set to 1 or 0 for sequential mode
	/// </summary>
	uint8_t &FanOut();

	/// <summary>
	/// Read/Write: Key uint8_t length (1 uint8_t): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)
	/// </summary>
	uint8_t &KeyLength();

	/// <summary>
	/// Read/Write: Inner hash uint8_t length (1 uint8_t): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)
	/// </summary>
	uint8_t &InnerLength();

	/// <summary>
	/// Read/Write: Leaf maximal uint8_t length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)
	/// </summary>
	uint32_t &LeafLength();

	/// <summary>
	/// Read/Write: Maximal depth (1 uint8_t): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)
	/// </summary>
	uint8_t &MaxDepth();

	/// <summary>
	/// Read/Write: Node offset (1 bytes): an integer in [0, 256 −1] (set to 0 for the first, leftmost, leaf, or in sequential mode)
	/// </summary>
	uint8_t &NodeOffset();

	/// <summary>
	/// Read/Write: Node depth (1 uint8_t): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)
	/// </summary>
	uint8_t &NodeDepth();

	/// <summary>
	/// Read/Write: Digest output uint8_t length (1 uint8_t): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s
	/// </summary>
	uint8_t &OutputSize();

	/// <summary>
	/// Read/Write: Flag reserved for future use
	/// </summary>
	uint8_t &Reserved();

	/// <summary>
	/// Read/Write: The personalization string
	/// </summary>
	std::vector<uint8_t> &DistributionCode();

	/// <summary>
	/// Read Only: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	BlakeParams Clone();

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a BlakeParams instance</returns>
	BlakeParams* DeepCopy();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(BlakeParams &Input);

	/// <summary>
	/// Get the default configuration
	/// </summary>
	/// 
	/// <param name="Config">The configuration array</param>
	template <class T>
	void GetConfig(std::vector<T> &Config)
	{
		if (sizeof(T) == sizeof(uint64_t))
		{
			Config[0] = m_outputSize;
			Config[0] |= (static_cast<uint64_t>(m_keyLen) << 8);
			Config[0] |= (static_cast<uint64_t>(m_fanOut) << 16);
			Config[0] |= (static_cast<uint64_t>(m_maxDepth) << 24);
			Config[0] |= (static_cast<uint64_t>(m_leafSize) << 32);
			Config[1] = m_nodeOffset;
			Config[2] = m_nodeDepth;
			Config[2] |= (static_cast<uint64_t>(m_innerLen) << 8);
			Config[2] |= (static_cast<uint64_t>(m_reserved) << 16);

			for (size_t i = 3; i < Config.size(); ++i)
			{
				Config[i] = IntegerTools::LeBytesTo64(m_dstCode, (i - 3) * sizeof(uint64_t));
			}
		}
		else
		{
			Config[0] = m_outputSize;
			Config[0] |= (static_cast<uint32_t>(m_keyLen) << 8);
			Config[0] |= (static_cast<uint32_t>(m_fanOut) << 16);
			Config[0] |= (static_cast<uint32_t>(m_maxDepth) << 24);
			Config[1] = m_leafSize;
			Config[2] = m_nodeOffset;
			Config[3] |= (static_cast<uint32_t>(m_nodeDepth) << 16);
			Config[3] |= (static_cast<uint32_t>(m_innerLen) << 24);
			Config[4] = m_reserved;

			for (size_t i = 5; i < Config.size(); ++i)
			{
				Config[i] = IntegerTools::LeBytesTo32(m_dstCode, (i - 5) * sizeof(uint32_t));
			}
		}
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int32_t GetHashCode();

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	size_t GetHeaderSize();

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the BlakeParams structure serialized to a uint8_t array
	/// </summary>
	/// 
	/// <returns>The uint8_t array containing the BlakeParams</returns>
	std::vector<uint8_t> ToBytes();
};

NAMESPACE_DIGESTEND
#endif
