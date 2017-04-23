// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_BLAKE2PARAMS_H
#define _CEX_BLAKE2PARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

/// <summary>
/// The Blake2 parameters structure
/// </summary> 
struct BlakeParams
{
private:

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

	/// <summary>
	/// Get/Set: Fanout (1 byte): an integer in [0, 255] set to the number of desired threads for parallel mode, set to 1 or 0 for sequential mode
	/// </summary>
	byte &FanOut() { return m_fanOut; }

	/// <summary>
	/// Get/Set: Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)
	/// </summary>
	byte &KeyLength() { return m_keyLen; }

	/// <summary>
	/// Get/Set: Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)
	/// </summary>
	byte &InnerLength() { return m_innerLen; }

	/// <summary>
	/// Get/Set: Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)
	/// </summary>
	uint &LeafLength() { return m_leafSize; }

	/// <summary>
	/// Get/Set: Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)
	/// </summary>
	byte &MaxDepth() { return m_maxDepth; }

	/// <summary>
	/// Get/Set: Node offset (1 bytes): an integer in [0, 256 −1] (set to 0 for the first, leftmost, leaf, or in sequential mode)
	/// </summary>
	byte &NodeOffset() { return m_nodeOffset; }

	/// <summary>
	/// Get/Set: Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)
	/// </summary>
	byte &NodeDepth() { return m_nodeDepth; }

	/// <summary>
	/// Get/Set: Digest output byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s
	/// </summary>
	byte &OutputSize() { return m_outputSize; }

	/// <summary>
	/// Get/Set: Flag reserved for future use
	/// </summary>
	byte &Reserved() { return m_reserved; }

	/// <summary>
	/// Get/Set: The personalization string
	/// </summary>
	std::vector<byte> &DistributionCode() { return m_dstCode; }

	/// <summary>
	/// Get: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax()
	{
		return ((m_outputSize == 32) ? 12 : 40);
	}


	/// <summary>
	/// Default instantiation.
	/// <para>Parameters must be added through their property members.</para>
	BlakeParams() {}

	/// <summary>
	/// Initialize the default structure.
	/// <para>Default settings are sequential mode.</para>
	/// </summary>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Blake2-256, or 64 for Blake2-512</param>
	/// <param name="TreeDepth">Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (limit of one state per processor core is recommended)</param>
	/// <param name="LeafSize">The outer leaf length in bytes; set to 0 for unlimited</param>
	/// <param name="InnerLength">Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
	explicit BlakeParams(byte OutputSize, byte TreeDepth = 1, byte Fanout = 1, byte LeafSize = 0, byte InnerLength = 0)
		:
		m_dstCode(0),
		m_fanOut(Fanout),
		m_innerLen(InnerLength),
		m_keyLen(0),
		m_leafSize(LeafSize),
		m_maxDepth(TreeDepth),
		m_nodeDepth(0),
		m_nodeOffset(0),
		m_outputSize(OutputSize),
		m_reserved(0)
	{
		m_dstCode.resize(DistributionCodeMax());
	}

	/// <summary>
	/// Initialize the MessageHeader structure using a serialized byte array
	/// </summary>
	explicit BlakeParams(const std::vector<byte> &TreeArray)
		:
		m_dstCode(0),
		m_fanOut(0),
		m_innerLen(0),
		m_keyLen(0),
		m_leafSize(0),
		m_maxDepth(0),
		m_nodeDepth(0),
		m_nodeOffset(0),
		m_outputSize(0),
		m_reserved(0)
	{
		if (TreeArray.size() != 32 && TreeArray.size() != 64)
			throw Exception::CryptoDigestException("BlakeParams:Ctor", "The TreeArray buffer is too short!");

		memcpy(&m_outputSize, &TreeArray[0], 1);
		memcpy(&m_keyLen, &TreeArray[1], 1);
		memcpy(&m_fanOut, &TreeArray[2], 1);
		memcpy(&m_maxDepth, &TreeArray[3], 1);
		m_leafSize = IntUtils::LeBytesTo32(TreeArray, 4);
		memcpy(&m_nodeOffset, &TreeArray[8], 1);
		memcpy(&m_nodeDepth, &TreeArray[9], 1);
		memcpy(&m_innerLen, &TreeArray[10], 1);
		memcpy(&m_reserved, &TreeArray[11], 1);
		m_dstCode.resize(DistributionCodeMax());
		memcpy(&m_dstCode[0], &TreeArray[12], m_dstCode.size());
	}

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
	explicit BlakeParams(byte OutputSize, byte KeyLength, byte FanOut, byte MaxDepth, uint LeafLength, byte NodeOffset, byte NodeDepth, byte InnerLength, std::vector<byte> &DistributionCode)
		:
		m_dstCode(DistributionCode),
		m_fanOut(FanOut),
		m_innerLen(InnerLength),
		m_keyLen(KeyLength),
		m_leafSize(LeafLength),
		m_maxDepth(MaxDepth),
		m_nodeDepth(NodeDepth),
		m_nodeOffset(NodeOffset),
		m_outputSize(OutputSize),
		m_reserved(0)
	{
		m_dstCode.resize(DistributionCodeMax());
	}

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	BlakeParams Clone()
	{
		BlakeParams result(ToBytes());
		return result;
	}

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a BlakeParams instance</returns>
	BlakeParams* DeepCopy()
	{
		return new BlakeParams(ToBytes());
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(BlakeParams &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}

	template <class T>
	void GetConfig(std::vector<T> &Config)
	{
		if (sizeof(T) == sizeof(ulong))
		{
			Config[0] = m_outputSize;
			Config[0] |= ((ulong)m_keyLen << 8);
			Config[0] |= ((ulong)m_fanOut << 16);
			Config[0] |= ((ulong)m_maxDepth << 24);
			Config[0] |= ((ulong)m_leafSize << 32);
			Config[1] = m_nodeOffset;
			Config[2] = m_nodeDepth;
			Config[2] |= ((ulong)m_innerLen << 8);
			Config[2] |= ((ulong)m_reserved << 16);

			for (size_t i = 3; i < Config.size(); ++i)
				Config[i] = IntUtils::LeBytesTo64(m_dstCode, (i - 3) * sizeof(ulong));
		}
		else
		{
			Config[0] = m_outputSize;
			Config[0] |= ((uint)m_keyLen << 8);
			Config[0] |= ((uint)m_fanOut << 16);
			Config[0] |= ((uint)m_maxDepth << 24);
			Config[1] = m_leafSize;
			Config[2] = m_nodeOffset;
			Config[3] |= ((uint)m_nodeDepth << 16);
			Config[3] |= ((uint)m_innerLen << 24);
			Config[4] = m_reserved;

			for (size_t i = 5; i < Config.size(); ++i)
				Config[i] = IntUtils::LeBytesTo32(m_dstCode, (i - 5) * sizeof(uint));
		}
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = 31 * m_outputSize;

		result += 31 * m_keyLen;
		result += 31 * m_fanOut;
		result += 31 * m_maxDepth;
		result += 31 * m_leafSize;
		result += 31 * m_nodeOffset;
		result += 31 * m_nodeDepth;
		result += 31 * m_innerLen;
		result += 31 * m_reserved;

		for (size_t i = 0; i < m_dstCode.size(); ++i)
			result += 31 * m_dstCode[i];

		return result;
	}

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	size_t GetHeaderSize()
	{
		return m_outputSize;
	}

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset()
	{
		m_outputSize = 0;
		m_keyLen = 0;
		m_fanOut = 0;
		m_maxDepth = 0;
		m_leafSize = 0;
		m_nodeOffset = 0;
		m_nodeDepth = 0;
		m_innerLen = 0;
		m_reserved = 0;

		memset(&m_dstCode[0], (byte)0, m_dstCode.size());
	}

	/// <summary>
	/// Convert the BlakeParams structure serialized to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the BlakeParams</returns>
	std::vector<byte> ToBytes()
	{
		std::vector<byte> trs(GetHeaderSize());

		memcpy(&trs[0], &m_outputSize, 1);
		memcpy(&trs[1], &m_keyLen, 1);
		memcpy(&trs[2], &m_fanOut, 1);
		memcpy(&trs[3], &m_maxDepth, 1);
		IntUtils::Le32ToBytes(m_leafSize, trs, 4);
		memcpy(&trs[8], &m_nodeOffset, 1);
		memcpy(&trs[9], &m_nodeDepth, 1);
		memcpy(&trs[10], &m_innerLen, 1);
		memcpy(&trs[11], &m_reserved, 1);
		memcpy(&trs[12], &m_dstCode[0], m_dstCode.size());

		return trs;
	}
};

NAMESPACE_DIGESTEND
#endif