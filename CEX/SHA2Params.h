// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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

#ifndef _CEX_SHA2PARAMS_H
#define _CEX_SHA2PARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"

NAMESPACE_DIGEST

/// <summary>
/// The SHA2 parameters structure
/// </summary> 
struct SHA2Params
{
private:
	static const size_t HDR_SIZE = 16;

	uint8_t m_dgtLen;
	uint8_t m_keyLen;
	uint8_t m_treeDepth;
	uint32_t m_leafLength;
	uint8_t m_parallelDegree;
	uint8_t m_subtreeLength;
	uint8_t m_nodeOffset;
	uint16_t m_reserved1;
	uint32_t m_reserved2;

public:
	/// <summary>
	/// Get/Set: Digest output byte length; set to 32 for SHA256 or 64 for SHA512
	/// </summary>
	uint8_t &DigestLength() { return m_dgtLen; }

	/// <summary>
	/// Get/Set: The MAC Key byte length
	/// </summary>
	uint8_t &KeyLength() { return m_keyLen; }

	/// <summary>
	/// Get/Set: The tree branch depth; Set to 0 is sequential mode, 2 is a single branch, set to 3 processes intermediate hashes at SubTreeLength intervals
	/// </summary>
	uint8_t &TreeDepth() { return m_treeDepth; }

	/// <summary>
	/// Get/Set: The outer leaf length
	/// <para>The size in bytes of the message block processed by the parallel intrinsics functions; must be 256 or 512.</para>
	/// <para>When using the either the SHA-2 256 or 512 bit variant, setting to 256 will use SSE3 compatable api, setting to 512 engages the AVX i256 api version of the function.</para>
	/// <para>Changing this size will change the digest output value.</para>
	/// </summary>
	uint32_t &LeafLength() { return m_leafLength; }

	/// <summary>
	/// Get/Set: The number of threads used to process the message; the default is 4.
	/// <para>This value can be any even number; and should be the number of processor cores on the target system.</para>
	/// <para>Changing this size will change the digest output value.</para>
	/// </summary>
	uint8_t &ParallelDegree() { return m_parallelDegree; }

	/// <summary>
	/// Get/Set: The number of leaf nodes in the last tier branch of the tree
	/// </summary>
	uint8_t &SubTreeLength() { return m_subtreeLength; }

	/// <summary>
	/// Get/Set: The nodes offset position within the branch
	/// </summary>
	uint8_t &NodeOffset() { return m_nodeOffset; }

	/// <summary>
	/// Get/Set: A flag reserved for future use
	/// </summary>
	uint16_t &Reserved1() { return m_reserved1; }

	/// <summary>
	/// Get/Set: A flag reserved for future use
	/// </summary>
	uint32_t &Reserved2() { return m_reserved2; }


	/// <summary>
	/// Initialize the default structure.
	/// <para>Default settings are sequential mode.</para>
	/// </summary>
	SHA2Params()
		:
		m_dgtLen(0),
		m_keyLen(0),
		m_treeDepth(1),
		m_leafLength(0),
		m_parallelDegree(0),
		m_nodeOffset(0),
		m_reserved1(0),
		m_reserved2(0),
		m_subtreeLength(0)
	{
	}

	/// <summary>
	/// Initialize the structure using a serialized byte array
	/// </summary>
	SHA2Params(std::vector<uint8_t> TreeArray)
		:
		m_dgtLen(0),
		m_keyLen(0),
		m_treeDepth(0),
		m_leafLength(0),
		m_parallelDegree(0),
		m_nodeOffset(0),
		m_reserved1(0),
		m_reserved2(0),
		m_subtreeLength(0)
	{
		if (TreeArray.size() < HDR_SIZE)
			throw CryptoDigestException("SHA2Params:Ctor", "The TreeArray buffer is too short!");

		memcpy(&m_dgtLen, &TreeArray[0], 1);
		memcpy(&m_keyLen, &TreeArray[1], 1);
		memcpy(&m_treeDepth, &TreeArray[2], 1);
		memcpy(&m_leafLength, &TreeArray[3], 4);
		memcpy(&m_parallelDegree, &TreeArray[7], 1);
		memcpy(&m_subtreeLength, &TreeArray[8], 1);
		memcpy(&m_nodeOffset, &TreeArray[9], 1);
		memcpy(&m_reserved1, &TreeArray[10], 2);
		memcpy(&m_reserved2, &TreeArray[12], 4);
	}

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="DigestLength">Digest output byte length; set to 32 for SHA256 or 64 for SHA512</param>
	/// <param name="KeyLength">Key byte length (set to 0 if no key is used)</param>
	/// <param name="TreeDepth">The tree branch depth; Set to 0 is sequential mode, 1 is a single branch, set to 2 processes intermediate hashes at SubTreeLength intervals</param>
	/// <param name="LeafLength">The outer leaf length in bytes; set to the digests internal blocksize (64 or 128)</param>
	/// <param name="ParallelDegree">The number of threads used to process the message; the default is 4.
	/// <para>This value can be any even number; and should be the number of processor cores on the target system.
	/// Changing this size will change the digest output value.</para></param>
	/// <param name="SubTreeLength">The number of leaf nodes in the last tier branch of the tree</param>
	/// <param name="NodeOffset">The nodes offset position within the branch</param>
	/// <param name="Reserved1">A flag reserved for future use</param>
	/// <param name="Reserved2">A flag reserved for future use</param>
	SHA2Params(uint8_t DigestLength, uint8_t KeyLength, uint8_t TreeDepth, uint32_t LeafLength, uint8_t ParallelDegree, uint8_t SubTreeLength, uint8_t NodeOffset = 0, uint16_t Reserved1 = 0, uint32_t Reserved2 = 0)
		:
		m_dgtLen(DigestLength),
		m_keyLen(KeyLength),
		m_treeDepth(TreeDepth),
		m_leafLength(LeafLength),
		m_parallelDegree(ParallelDegree),
		m_nodeOffset(NodeOffset),
		m_reserved1(Reserved1),
		m_reserved2(Reserved2),
		m_subtreeLength(SubTreeLength)
	{
	}


	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	SHA2Params Clone()
	{
		SHA2Params result(DigestLength(), KeyLength(), TreeDepth(), LeafLength(), ParallelDegree(), SubTreeLength(), NodeOffset(), Reserved1(), Reserved2());
		return result;
	}

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a SHA2Params instance</returns>
	SHA2Params* DeepCopy()
	{
		return new SHA2Params(DigestLength(), KeyLength(), TreeDepth(), LeafLength(), ParallelDegree(), SubTreeLength(), NodeOffset(), Reserved1(), Reserved2());
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(SHA2Params &Obj)
	{
		if (this->GetHashCode() != Obj.GetHashCode())
			return false;

		return true;
	}

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	int GetHashCode()
	{
		int result = 31 * m_dgtLen;

		result += 31 * m_keyLen;
		result += 31 * m_treeDepth;
		result += 31 * m_leafLength;
		result += 31 * m_parallelDegree;
		result += 31 * m_subtreeLength;
		result += 31 * m_nodeOffset;
		result += 31 * m_reserved1;
		result += 31 * m_reserved2;

		return result;
	}

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static int GetHeaderSize()
	{
		return HDR_SIZE;
	}

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset()
	{
		m_dgtLen = 0;
		m_keyLen = 0;
		m_treeDepth = 0;
		m_leafLength = 0;
		m_parallelDegree = 0;
		m_subtreeLength = 0;
		m_nodeOffset = 0;
		m_reserved1 = 0;
		m_reserved2 = 0;
	}

	/// <summary>
	/// Convert the SHA2Params structure serialized to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the SHA2Params</returns>
	std::vector<uint8_t> ToBytes()
	{
		std::vector<uint8_t> trs(HDR_SIZE, 0);

		memcpy(&trs[0], &m_dgtLen, 1);
		memcpy(&trs[1], &m_keyLen, 1);
		memcpy(&trs[2], &m_treeDepth, 1);
		memcpy(&trs[3], &m_leafLength, 4);
		memcpy(&trs[7], &m_parallelDegree, 1);
		memcpy(&trs[8], &m_subtreeLength, 1);
		memcpy(&trs[9], &m_nodeOffset, 1);
		memcpy(&trs[10], &m_reserved1, 2);
		memcpy(&trs[12], &m_reserved2, 4);

		return trs;
	}
};

NAMESPACE_DIGESTEND
#endif