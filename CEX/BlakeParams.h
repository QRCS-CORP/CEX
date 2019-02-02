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

#ifndef CEX_BLAKEPARAMS_H
#define CEX_BLAKEPARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;

/// <summary>
/// The parallel Blake2 parameters structure
/// </summary> 
struct BlakeParams
{
private:

	static const std::string CLASS_NAME;
	static const size_t HDR_BASE = 12;

	// 256=12, 512=40
	std::vector<byte> m_dstCode;
	byte m_fanOut;
	byte m_innerLen;
	byte m_keyLen;
	uint m_leafSize;
	byte m_maxDepth;
	byte m_nodeDepth;
	byte m_nodeOffset;
	byte m_outputSize;
	byte m_reserved;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; state is initialized to zero defaults
	/// </summary>
	BlakeParams();

	/// <summary>
	/// Initialize the MessageHeader structure using a serialized byte array
	/// </summary>
	///
	/// <param name="TreeArray">A serialized BlakeParams structure</param>
	explicit BlakeParams(const std::vector<byte> &TreeArray);

	/// <summary>
	/// Initialize the default structure.
	/// <para>Default settings are sequential mode.</para>
	/// </summary>
	///
	/// <param name="OutputSize">Digest output byte length; set to 32 for Blake2-256, or 64 for Blake2-512</param>
	/// <param name="TreeDepth">Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (limit of one state per processor core is recommended)</param>
	/// <param name="LeafSize">The outer leaf length in bytes; set to 0 for unlimited</param>
	/// <param name="InnerLength">Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
	explicit BlakeParams(byte OutputSize, byte TreeDepth = 1, byte Fanout = 1, byte LeafSize = 0, byte InnerLength = 0);

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="OutputSize">Digest output byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s</param>
	/// <param name="KeyLength">Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)</param>
	/// <param name="FanOut">Fanout (1 byte): an integer in [0, 255] set to the number of desired threads for parallel mode, set to 1 or 0 for sequential mode</param>
	/// <param name="MaxDepth">Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
	/// <param name="LeafLength">Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)</param>
	/// <param name="NodeOffset">Node offset (1 byte): an integer in [0, 256 −1] (set to 0 for the first, leftmost, leaf, or in sequential mode)</param>
	/// <param name="NodeDepth">Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)</param>
	/// <param name="InnerLength">Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
	/// <param name="DistributionCode">The optional personalization string; must be no longer than DistributionCodeMax in size</param>
	BlakeParams(byte OutputSize, byte KeyLength, byte FanOut, byte MaxDepth, uint LeafLength, byte NodeOffset, byte NodeDepth, byte InnerLength, std::vector<byte> &DistributionCode);

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Fanout (1 byte): an integer in [0, 255] set to the number of desired threads for parallel mode, set to 1 or 0 for sequential mode
	/// </summary>
	byte &FanOut();

	/// <summary>
	/// Read/Write: Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)
	/// </summary>
	byte &KeyLength();

	/// <summary>
	/// Read/Write: Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)
	/// </summary>
	byte &InnerLength();

	/// <summary>
	/// Read/Write: Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)
	/// </summary>
	uint &LeafLength();

	/// <summary>
	/// Read/Write: Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)
	/// </summary>
	byte &MaxDepth();

	/// <summary>
	/// Read/Write: Node offset (1 bytes): an integer in [0, 256 −1] (set to 0 for the first, leftmost, leaf, or in sequential mode)
	/// </summary>
	byte &NodeOffset();

	/// <summary>
	/// Read/Write: Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)
	/// </summary>
	byte &NodeDepth();

	/// <summary>
	/// Read/Write: Digest output byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s
	/// </summary>
	byte &OutputSize();

	/// <summary>
	/// Read/Write: Flag reserved for future use
	/// </summary>
	byte &Reserved();

	/// <summary>
	/// Read/Write: The personalization string
	/// </summary>
	std::vector<byte> &DistributionCode();

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
		if (sizeof(T) == sizeof(ulong))
		{
			Config[0] = m_outputSize;
			Config[0] |= (static_cast<ulong>(m_keyLen) << 8);
			Config[0] |= (static_cast<ulong>(m_fanOut) << 16);
			Config[0] |= (static_cast<ulong>(m_maxDepth) << 24);
			Config[0] |= (static_cast<ulong>(m_leafSize) << 32);
			Config[1] = m_nodeOffset;
			Config[2] = m_nodeDepth;
			Config[2] |= (static_cast<ulong>(m_innerLen) << 8);
			Config[2] |= (static_cast<ulong>(m_reserved) << 16);

			for (size_t i = 3; i < Config.size(); ++i)
			{
				Config[i] = Utility::IntegerTools::LeBytesTo64(m_dstCode, (i - 3) * sizeof(ulong));
			}
		}
		else
		{
			Config[0] = m_outputSize;
			Config[0] |= (static_cast<uint>(m_keyLen) << 8);
			Config[0] |= (static_cast<uint>(m_fanOut) << 16);
			Config[0] |= (static_cast<uint>(m_maxDepth) << 24);
			Config[1] = m_leafSize;
			Config[2] = m_nodeOffset;
			Config[3] |= (static_cast<uint>(m_nodeDepth) << 16);
			Config[3] |= (static_cast<uint>(m_innerLen) << 24);
			Config[4] = m_reserved;

			for (size_t i = 5; i < Config.size(); ++i)
			{
				Config[i] = Utility::IntegerTools::LeBytesTo32(m_dstCode, (i - 5) * sizeof(uint));
			}
		}
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode();

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
	/// Convert the BlakeParams structure serialized to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the BlakeParams</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_DIGESTEND
#endif
