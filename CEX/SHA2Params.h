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

#ifndef CEX_SHA2PARAMS_H
#define CEX_SHA2PARAMS_H

#include "CexDomain.h"

NAMESPACE_DIGEST

/// <summary>
/// The SHA2 configuration parameters structure
/// </summary> 
struct SHA2Params
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

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; state is initialized to zero defaults
	/// </summary>
	SHA2Params();

	/// <summary>
	/// Initialize the SHA2Params structure using a serialized byte array
	/// </summary>
	///
	/// <param name="TreeArray">A serialized SHA2Params structure</param>
	explicit SHA2Params(const std::vector<byte> &TreeArray);

	/// <summary>
	/// Initialize with the default parameters.
	/// <para>Default settings are configured for sequential mode.</para>
	/// </summary>
	/// <param name="OutputSize">Digest output byte length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this must be the digests block size</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	explicit SHA2Params(ulong OutputSize, uint LeafSize = 0, byte Fanout = 0);

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
	SHA2Params(uint NodeOffset, ulong OutputSize, ushort Version, uint LeafSize, byte Fanout, byte TreeDepth, std::vector<byte> &Info);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHA2Params();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The number of leaf nodes in the last tier branch of the tree
	/// </summary>
	byte &FanOut();

	/// <summary>
	/// Read/Write: The outer leaf length
	/// </summary>
	uint &LeafSize();

	/// <summary>
	/// Read/Write: The tree nodes relational offset
	/// </summary>
	uint &NodeOffset();

	/// <summary>
	/// Read/Write: Digest output byte length
	/// </summary>
	ulong &OutputSize();

	/// <summary>
	/// Read/Write: Reserved for future use
	/// </summary>
	uint &Reserved();

	/// <summary>
	/// Read/Write: The personalization string
	/// </summary>
	std::vector<byte> &DistributionCode();

	/// <summary>
	/// Read Only: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax();

	/// <summary>
	/// Read/Write: The skein version number
	/// </summary>
	ushort &Version();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	/// 
	/// <returns>A copy of this SHA2Params structure</returns>
	SHA2Params Clone();

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a copy of this SHA2Params structure</returns>
	SHA2Params* DeepCopy();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(SHA2Params &Input);

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
	/// Convert the SHA2Params structure to a serialized byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the serialized SHA2Params structure</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_DIGESTEND
#endif