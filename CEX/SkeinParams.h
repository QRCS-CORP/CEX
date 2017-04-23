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

#ifndef _CEXENGINE_SKEINPARAMS_H
#define _CEXENGINE_SKEINPARAMS_H

#include "CexDomain.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using Utility::IntUtils;

/// <summary>
/// The Skein configuration parameters structure
/// </summary> 
struct SkeinParams
{
private:
	static const size_t HDR_SIZE = 24;

	// skein 1.3, table 7:
	// offset | size | type
	// 0		4		Schema identifier The ASCII string “SHA3” = (0x53, 0x48, 0x41, 0x33), or ToBytes(0x33414853, 4)
	// 4		2		Version number Currently set to 1: ToBytes(1, 2)
	// 6		2		Reserved1, set to 0
	// 8		8		Output length ToBytes(No, 8)
	// 16		1		Tree leaf size enc.Yl
	// 17		1		Tree fan - out enc.Yf
	// 18		1		Max.tree height Ym
	// 19		13		Reserved2, set to 0
	// changed to:
	// 19		1		Reserved2, set to 0
	// 20		4		Reserved3, set to 0
	// 24		8-104	Personalization string

	// bytes 1-8
	std::vector<byte> m_treeSchema;
	ushort m_treeVersion;
	ushort m_reserved1;
	// 8-16
	ulong m_outputSize;
	// 16-24
	byte m_leafSize;
	byte m_treeDepth;
	byte m_treeFanout;
	byte m_reserved2;
	uint m_reserved3;
	// 24-32/64/128 8/40/104
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
	byte &LeafSize() { return m_leafSize; }

	/// <summary>
	/// Get/Set: Digest output byte length
	/// </summary>
	ulong &OutputSize() { return m_outputSize; }

	/// <summary>
	/// Get/Set: Reserved for future use
	/// </summary>
	ushort &Reserved1() { return m_reserved1; }

	/// <summary>
	/// Get/Set: Reserved for future use
	/// </summary>
	byte &Reserved2() { return m_reserved2; }

	/// <summary>
	/// Get/Set: Reserved for future use
	/// </summary>
	uint &Reserved3() { return m_reserved3; }

	/// <summary>
	/// Get/Set: The personalization string
	/// </summary>
	std::vector<byte> &DistributionCode() { return m_dstCode; }

	/// <summary>
	/// Get: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax() 
	{ 
		return (m_outputSize - HDR_SIZE);
	}

	/// <summary>
	/// Get/Set: The 4 byte schema array
	/// </summary>
	std::vector<byte> &Schema() { return m_treeSchema; }

	/// <summary>
	/// Get/Set: The skein version number
	/// </summary>
	ushort &Version() { return m_treeVersion; }

	//~~~Constructor~~~//

	/// <summary>
	/// Default instantiation.
	/// <para>Parameters must be added through their property members, and the Calculate() function called.</para>
	SkeinParams() {}

	/// <summary>
	/// Initialize with the default parameters.
	/// <para>Default settings are configured for sequential mode.</para>
	/// </summary>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this must be the digests block size</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (limit of one state per processor core is recommended)</param>
	SkeinParams(ulong OutputSize, byte LeafSize = 0, byte Fanout = 0)
		:
		m_treeSchema{ 83, 72, 65, 51 }, 
		m_treeVersion(1),
		m_reserved1(0),
		m_outputSize(OutputSize),
		m_leafSize(LeafSize),
		m_treeDepth(0),
		m_treeFanout(Fanout),
		m_reserved2(0),
		m_reserved3(0),
		m_dstCode(0)
	{
		m_dstCode.resize(DistributionCodeMax());
	}

	/// <summary>
	/// Initialize the SkeinParams structure using a serialized byte array
	/// </summary>
	explicit SkeinParams(const std::vector<byte> &TreeArray)
		:
		m_treeSchema(4),
		m_treeVersion(0),
		m_reserved1(0),
		m_outputSize(0),
		m_leafSize(0),
		m_treeDepth(0),
		m_treeFanout(0),
		m_reserved2(0),
		m_reserved3(0),
		m_dstCode(0)
	{
		CEXASSERT(TreeArray.size() >= GetHeaderSize(), "The TreeArray buffer is too short!");

		memcpy(&m_treeSchema[0], &TreeArray[0], 4);
		m_treeVersion = IntUtils::LeBytesTo16(TreeArray, 4);
		m_reserved1 = IntUtils::LeBytesTo16(TreeArray, 6);
		m_outputSize = IntUtils::LeBytesTo64(TreeArray, 8);
		memcpy(&m_leafSize, &TreeArray[16], 1);
		memcpy(&m_treeDepth, &TreeArray[17], 1);
		memcpy(&m_treeFanout, &TreeArray[18], 1);
		memcpy(&m_reserved2, &TreeArray[19], 1);
		m_reserved3 = IntUtils::LeBytesTo32(TreeArray, 20);
		m_dstCode.resize(DistributionCodeMax());
		memcpy(&m_dstCode[0], &TreeArray[24], m_dstCode.size());
	}

	/// <summary>
	/// Initialize this structure with all parameters
	/// </summary>
	/// 
	/// <param name="Schema">The four byte configuration schema array; default should be 'SHA3', (83, 72, 65, 51)</param>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="Version">The Skein version number; should always be a value of '1'</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this should be the digest block size in bytes</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	/// <param name="TreeDepth">The depth of the parallel tree; this value is always zero in this implementation</param>
	/// <param name="DistributionCode">The optional personalization string; must be no longer than DistributionCodeMax in size</param>
	explicit SkeinParams(const std::vector<byte> &Schema, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &DistributionCode)
		:
		m_treeSchema(Schema), 
		m_treeVersion(Version),
		m_reserved1(0),
		m_outputSize(OutputSize),
		m_leafSize(LeafSize),
		m_treeDepth(TreeDepth),
		m_treeFanout(Fanout),
		m_reserved2(0),
		m_reserved3(0),
		m_dstCode(DistributionCode)
	{
		m_dstCode.resize(DistributionCodeMax());

		CEXASSERT(Schema.size() == 4, "The Schema must be 4 bytes in length!");
		CEXASSERT(TreeDepth == 0, "The tree depth is always 0!");
		CEXASSERT(Version == 1, "The version number must be 1!");
		CEXASSERT(m_treeFanout == 0 || m_treeFanout > 0 && (m_leafSize != OutputSize || m_treeFanout % 2 == 0), "The fan-out must be an even number and should align to processor cores!");
	}

	//~~~Public Functions~~~//

	/// <summary>
	/// Return the formatted configuration string
	/// </summary>
	/// 
	/// <returns>The configuration string</returns>
	std::vector<ulong> GetConfig()
	{
		std::vector<ulong> config(m_outputSize / sizeof(ulong));

		// set schema bytes
		config[0] = IntUtils::LeBytesTo32(m_treeSchema, 0);
		// version and key size
		config[0] |= ((ulong)m_treeVersion << 32);
		config[0] |= ((ulong)m_reserved1 << 48);
		// output size
		config[1] = m_outputSize * sizeof(ulong);
		// leaf size and fanout
		config[2] |= ((ulong)m_leafSize);
		config[2] |= ((ulong)m_treeFanout << 8);
		config[2] |= ((ulong)m_treeDepth << 16);
		config[2] |= ((ulong)m_reserved2 << 24);
		config[2] |= ((ulong)m_reserved3 << 32);

		// distribution code
		for (size_t i = 3; i < config.size(); ++i)
			config[i] = IntUtils::LeBytesTo64(m_dstCode, (i - 3) * sizeof(ulong));

		return config;
	}

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	/// 
	/// <returns>A copy of this SkeinParams structure</returns>
	SkeinParams Clone()
	{
		return SkeinParams(ToBytes());
	}

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a copy of this SkeinParams structure</returns>
	SkeinParams* DeepCopy()
	{
		return new SkeinParams(ToBytes());
	}

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Obj">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(SkeinParams &Obj)
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
		int result = 31 * m_treeVersion;
		result += 31 * m_reserved1;
		result += 31 * m_leafSize;
		result += 31 * m_outputSize;
		result += 31 * m_treeDepth;
		result += 31 * m_treeFanout;
		result += 31 * m_reserved2;
		result += 31 * m_reserved3;

		for (size_t i = 0; i < m_dstCode.size(); ++i)
			result += 31 * m_dstCode[i];
		for (size_t i = 0; i < m_treeSchema.size(); ++i)
			result += 31 * m_treeSchema[i];

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
		m_treeSchema.clear();
		m_treeVersion = 0;
		m_reserved1 = 0;
		m_outputSize = 0;
		m_leafSize = 0;
		m_treeDepth = 0;
		m_treeFanout = 0;
		m_reserved2 = 0;
		m_reserved3 = 0;
		m_dstCode.clear();
	}

	/// <summary>
	/// Convert the SkeinParams structure to a serialized byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the serialized SkeinParams structure</returns>
	std::vector<byte> ToBytes()
	{
		std::vector<byte> trs(GetHeaderSize(), 0);

		memcpy(&trs[0], &m_treeSchema[0], 4);
		IntUtils::Le16ToBytes(m_treeVersion, trs, 4);
		IntUtils::Le16ToBytes(m_reserved1, trs, 6);
		IntUtils::Le64ToBytes(m_outputSize, trs, 8);
		memcpy(&trs[16], &m_leafSize, 1);
		memcpy(&trs[17], &m_treeDepth, 1);
		memcpy(&trs[18], &m_treeFanout, 1);
		memcpy(&trs[19], &m_reserved2, 1);
		IntUtils::Le32ToBytes(m_reserved3, trs, 20);
		memcpy(&trs[24], &m_dstCode[0], m_dstCode.size());

		return trs;
	}
};

NAMESPACE_DIGESTEND
#endif