// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef _CEXENGINE_KECCAKPARAMS_H
#define _CEXENGINE_KECCAKPARAMS_H

#include "CexDomain.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

/// <summary>
/// The Keccak configuration parameters structure
/// </summary> 
struct KeccakParams
{
private:
	static const size_t HDR_SIZE = 24;

	// offset | size | type
	// 0		4		Node relational offset
	// 4		2		Version number Currently set to 1: ToBytes(1, 2)
	// 6		8		Output length ToBytes(No, 8)
	// 14		4		Tree leaf size
	// 18		1		Tree fanout
	// 19		1		Tree height
	// 20		4		Reserved3, set to 0
	// 24		8-104	Personalization string

	uint m_nodeOffset;
	ushort m_treeVersion;
	ulong m_outputSize;
	uint m_leafSize;
	byte m_treeDepth;
	byte m_treeFanout;
	uint m_reserved;
	// 256=112|512=48
	std::vector<byte> m_dstCode;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get/Set: The number of leaf nodes in the last tier branch of the tree
	/// </summary>
	byte &FanOut() { return m_treeFanout; }

	/// <summary>
	/// Get/Set: The outer leaf length
	/// </summary>
	uint &LeafSize() { return m_leafSize; }

	/// <summary>
	/// Get/Set: The tree nodes relational offset
	/// </summary>
	uint &NodeOffset() { return m_nodeOffset; }

	/// <summary>
	/// Get/Set: Digest output byte length
	/// </summary>
	ulong &OutputSize() { return m_outputSize; }

	/// <summary>
	/// Get/Set: Reserved for future use
	/// </summary>
	uint &Reserved() { return m_reserved; }

	/// <summary>
	/// Get/Set: The personalization string
	/// </summary>
	std::vector<byte> &DistributionCode() { return m_dstCode; }

	/// <summary>
	/// Get: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax()
	{
		if (m_outputSize == 32)
			return 112;
		else
			return 48;
	}

	/// <summary>
	/// Get/Set: The skein version number
	/// </summary>
	ushort &Version() { return m_treeVersion; }

	//~~~Constructor~~~//

	/// <summary>
	/// Default instantiation.
	/// <para>Parameters must be added through their property members, and the Calculate() function called.</para>
	KeccakParams() {}

	/// <summary>
	/// Initialize with the default parameters.
	/// <para>Default settings are configured for sequential mode.</para>
	/// </summary>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this must be the digests block size</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	KeccakParams(ulong OutputSize, uint LeafSize = 0, byte Fanout = 0)
		:
		m_nodeOffset(0),
		m_treeVersion(1),
		m_outputSize(OutputSize),
		m_leafSize(LeafSize),
		m_treeDepth(0),
		m_treeFanout(Fanout),
		m_reserved(0),
		m_dstCode(0)
	{
		m_dstCode.resize(DistributionCodeMax());
	}

	/// <summary>
	/// Initialize the KeccakParams structure using a serialized byte array
	/// </summary>
	explicit KeccakParams(const std::vector<byte> &TreeArray)
		:
		m_nodeOffset(0),
		m_treeVersion(0),
		m_outputSize(0),
		m_leafSize(0),
		m_treeDepth(0),
		m_treeFanout(0),
		m_reserved(0),
		m_dstCode(0)
	{
		CEXASSERT(TreeArray.size() >= GetHeaderSize(), "The TreeArray buffer is too short!");

		m_nodeOffset = IntUtils::LeBytesTo32(TreeArray, 0);
		m_treeVersion = IntUtils::LeBytesTo16(TreeArray, 4);
		m_outputSize = IntUtils::LeBytesTo64(TreeArray, 6);
		m_leafSize = IntUtils::LeBytesTo32(TreeArray, 14);
		memcpy(&m_treeDepth, &TreeArray[18], 1);
		memcpy(&m_treeFanout, &TreeArray[19], 1);
		m_reserved = IntUtils::LeBytesTo32(TreeArray, 20);
		m_dstCode.resize(DistributionCodeMax());
		memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
	}

	/// <summary>
	/// Initialize this structure with all parameters
	/// </summary>
	/// 
	/// <param name="NodeOffset">The tree nodes relational offset</param>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="Version">The Skein version number; should always be a value of '1'</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this should be the digest block size in bytes</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	/// <param name="TreeDepth">The depth of the parallel tree; this value is always zero in this implementation</param>
	/// <param name="Info">Optional personalization string</param>
	explicit KeccakParams(uint NodeOffset, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &Info)
		:
		m_nodeOffset(NodeOffset),
		m_treeVersion(Version),
		m_outputSize(OutputSize),
		m_leafSize(LeafSize),
		m_treeDepth(TreeDepth),
		m_treeFanout(Fanout),
		m_reserved(0),
		m_dstCode(Info)
	{
		m_dstCode.resize(DistributionCodeMax());

		CEXASSERT(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	/// 
	/// <returns>A copy of this KeccakParams structure</returns>
	KeccakParams Clone()
	{
		return KeccakParams(ToBytes());
	}

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a copy of this KeccakParams structure</returns>
	KeccakParams* DeepCopy()
	{
		return new KeccakParams(ToBytes());
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(KeccakParams &Input)
	{
		if (this->GetHashCode() != Input.GetHashCode())
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
		int result = 31 * m_treeVersion;
		result += 31 * m_nodeOffset;
		result += 31 * m_leafSize;
		result += 31 * m_outputSize;
		result += 31 * m_treeDepth;
		result += 31 * m_treeFanout;
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
		return HDR_SIZE + DistributionCodeMax();
	}

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset()
	{
		m_nodeOffset = 0;
		m_treeVersion = 0;
		m_outputSize = 0;
		m_leafSize = 0;
		m_treeDepth = 0;
		m_treeFanout = 0;
		m_reserved = 0;
		m_dstCode.clear();
	}

	/// <summary>
	/// Convert the KeccakParams structure to a serialized byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the serialized KeccakParams structure</returns>
	std::vector<byte> ToBytes()
	{
		std::vector<byte> config(GetHeaderSize());

		IntUtils::Le32ToBytes(m_nodeOffset, config, 0);
		IntUtils::Le16ToBytes(m_treeVersion, config, 4);
		IntUtils::Le64ToBytes(m_outputSize, config, 6);
		IntUtils::Le32ToBytes(m_leafSize, config, 14);
		memcpy(&config[18], &m_treeDepth, 1);
		memcpy(&config[19], &m_treeFanout, 1);
		IntUtils::Le32ToBytes(m_reserved, config, 20);
		memcpy(&config[24], &m_dstCode[0], m_dstCode.size());

		return config;
	}
};

NAMESPACE_DIGESTEND
#endif