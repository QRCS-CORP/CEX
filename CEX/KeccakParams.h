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

#ifndef CEX_KECCAKPARAMS_H
#define CEX_KECCAKPARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;

/// <summary>
/// The parallel Keccak configuration parameters structure
/// </summary> 
struct KeccakParams
{
private:

	static const std::string CLASS_NAME;
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

	uint32_t m_nodeOffset;
	uint16_t m_treeVersion;
	uint64_t m_outputSize;
	uint32_t m_leafSize;
	uint8_t m_treeDepth;
	uint8_t m_treeFanout;
	uint32_t m_reserved;
	// 256=112|512=48
	std::vector<uint8_t> m_dstCode;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor; state is initialized to zero defaults
	/// </summary>
	KeccakParams();

	/// <summary>
	/// Initialize the KeccakParams structure using a serialized uint8_t array
	/// </summary>
	///
	/// <param name="TreeArray">A serialized KeccakParams structure</param>
	explicit KeccakParams(const std::vector<uint8_t> &TreeArray);

	/// <summary>
	/// Initialize with the default parameters.
	/// <para>Default settings are configured for sequential mode.</para>
	/// </summary>
	///
	/// <param name="OutputSize">Digest output uint8_t length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this must be the digests block size</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	explicit KeccakParams(uint64_t OutputSize, uint32_t LeafSize = 0, uint8_t Fanout = 0);

	/// <summary>
	/// Initialize this structure with all parameters
	/// </summary>
	/// 
	/// <param name="NodeOffset">The tree nodes relational offset</param>
	/// <param name="OutputSize">Digest output uint8_t length; set to 32 for Skein256, 64 for Skein512 or 128 for Skein1024</param>
	/// <param name="Version">The Skein version number; should always be a value of '1'</param>
	/// <param name="LeafSize">The outer leaf length in bytes; this should be the digest block size in bytes</param>
	/// <param name="Fanout">The number of state leaf-nodes used by parallel processing (one state per processor core is recommended)</param>
	/// <param name="TreeDepth">The depth of the parallel tree; this value is always zero in this implementation</param>
	/// <param name="Info">Optional personalization string</param>
	KeccakParams(uint32_t NodeOffset, uint64_t OutputSize, uint16_t Version, uint32_t LeafSize, uint8_t Fanout, uint8_t TreeDepth, std::vector<uint8_t> &Info);

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The personalization string
	/// </summary>
	std::vector<uint8_t> &DistributionCode();

	/// <summary>
	/// Read Only: The maximum recommended size of the distribution code
	/// </summary>
	const size_t DistributionCodeMax();

	/// <summary>
	/// Read/Write: The number of leaf nodes in the last tier branch of the tree
	/// </summary>
	uint8_t &FanOut();

	/// <summary>
	/// Read/Write: The outer leaf length
	/// </summary>
	uint32_t &LeafSize();

	/// <summary>
	/// Read/Write: The tree nodes relational offset
	/// </summary>
	uint32_t &NodeOffset();

	/// <summary>
	/// Read/Write: Digest output uint8_t length
	/// </summary>
	uint64_t &OutputSize();

	/// <summary>
	/// Read/Write: Reserved for future use
	/// </summary>
	uint32_t &Reserved();

	/// <summary>
	/// Read/Write: The skein version number
	/// </summary>
	uint16_t &Version();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	/// 
	/// <returns>A copy of this KeccakParams structure</returns>
	KeccakParams Clone();

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a copy of this KeccakParams structure</returns>
	KeccakParams* DeepCopy();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(KeccakParams &Input);

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
	/// Convert the KeccakParams structure to a serialized uint8_t array
	/// </summary>
	/// 
	/// <returns>The uint8_t array containing the serialized KeccakParams structure</returns>
	std::vector<uint8_t> ToBytes();
};

NAMESPACE_DIGESTEND
#endif
