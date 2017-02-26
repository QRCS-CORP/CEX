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
//
// 
// Principal Algorithms:
// An implementation of Blake2, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O�Hearn, and Christian Winnerlein. 
// Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.
// 
// Implementation Details:
// An implementation of the Blake2S and Blake2SP digests with a 256 bit digest output size.
// Based on the Blake2 Github projects by Samuel Neves and Christian Winnerlein.
// Blake2: https://github.com/BLAKE2/BLAKE2
//
// Written by John Underhill, June 19, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_BLAKE2SP256_H
#define _CEX_BLAKE2SP256_H

#include "Blake2Params.h"
#include "IDigest.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the Blake2S and Blake2SP digests with a 256 bit digest output size
/// </summary> 
/// 
/// <example>
/// <description>Example using the Compute method:</description>
/// <para>Use the Compute method for small to medium data sizes</para>
/// <code>
/// BlakeS256 dgt;
/// std:vector&lt;uint8_t&gt; hash(dgt.DigestSize(), 0);
/// // compute a hash
/// dgt.Compute(input, hash);
/// </code>
/// </example>
///
/// <example>
/// <description>Use the Update method for large data sizes:</description>
/// <code>
/// BlakeS256 dgt;
/// std:vector&lt;uint8_t&gt; hash(dgt.DigestSize(), 0);
/// int64_t len = (int64_t)input.size();
///
/// // update blocks
/// while (len > dgt.DigestSize())
/// {
///		dgt.Update(input, offset, len);
///		offset += dgt.DigestSize();
///		len -= dgt.DigestSize();
/// }
///
/// if (len > 0)
///		dgt.Update(input, offset, len);
///
/// dgt.Finalize(hash, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Algorithm is selected through the constructor (2S or 2SP), parallel version is selected through either the Parallel flag, or via the Blake2Params ThreadCount() configuration parameter.</description></item>
/// <item><description>Parallel and sequential algorithms (Blake2S or Blake2SP) produce different digest outputs, this is expected.</description></item>
/// <item><description>Sequential Block size is 64 bytes, (512 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
/// <item><description>Parallel Block input size to the Update function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
/// <item><description>The number of threads used in parallel mode can be user defined through the Blake2Params->ThreadCount property to any even number of threads; note that hash value will change with threadcount.</description></item>
/// <item><description>Digest output size is fixed at 32 bytes, (256 bits).</description></item>
/// <item><description>The <see cref="Compute(uint8_t[])"/> method wraps the <see cref="Update(uint8_t[], size_t, size_t)"/> and Finalize methods</description>/></item>
/// <item><description>The <see cref="Finalize(uint8_t[], size_t)"/> method resets the internal state.</description></item>
/// <item><description>Optional intrinsics are runtime enabled automatically based on cpu support.</description></item>
/// <item><description>SIMD implementation requires compilation with SSSE3 or higher.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Blake2 <a href="https://blake2.net/">Homepage</a>.</description></item>
/// <item><description>Blake2 on <a href="https://github.com/BLAKE2/BLAKE2">Github</a>.</description></item>
/// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
/// <item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// <item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
/// </list>
/// </remarks>
class BlakeS256 : public IDigest
{
private:

	static const uint32_t BLOCK_SIZE = 64;
	static const uint32_t CHAIN_SIZE = 8;
	static const uint32_t COUNTER_SIZE = 2;
	static const uint32_t PARALLEL_DEG = 8;
	const uint32_t DEF_LEAFSIZE = 16384;
	const size_t DIGEST_SIZE = 32;
	const uint32_t FLAG_SIZE = 2;
	const uint32_t MAX_PRLBLOCK = 5120000;
	const uint32_t MIN_PRLBLOCK = 256;
	const size_t ROUND_COUNT = 10;
	const uint32_t UL_MAX = 4294967295;

	struct Blake2sState
	{
		std::vector<uint32_t> H;
		std::vector<uint32_t> T;
		std::vector<uint32_t> F;

		Blake2sState()
			:
			F(2, 0),
			H(8, 0),
			T(2, 0)
		{
		}

		void Reset()
		{
			if (F.size() > 0)
				memset(&F[0], 0, F.size() * sizeof(uint32_t));
			if (H.size() > 0)
				memset(&H[0], 0, H.size() * sizeof(uint32_t));
			if (T.size() > 0)
				memset(&T[0], 0, T.size() * sizeof(uint32_t));
		}
	};

	std::vector<uint32_t> m_cIV;
	bool m_hasSimd128;
	bool m_isDestroyed;
	bool m_isParallel;
	uint32_t m_leafSize;
	std::vector<uint8_t> m_msgBuffer;
	size_t m_msgLength;
	size_t m_parallelBlockSize;
	std::vector<Blake2sState> m_State;
	std::vector<uint32_t> m_treeConfig;
	bool m_treeDestroy;
	Blake2Params m_treeParams;
	size_t m_minParallel;

public:

	BlakeS256(const BlakeS256&) = delete;
	BlakeS256& operator=(const BlakeS256&) = delete;
	BlakeS256& operator=(BlakeS256&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: The digests type name
	/// </summary>
	virtual Digests Enumeral() 
	{ 
		if (m_isParallel)
			return Digests::BlakeSP256;
		else
			return Digests::BlakeS256;
	}

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name()
	{
		if (m_isParallel)
			return "BlakeSP256";
		else
			return "BlakeS256";
	}

	/// <summary>
	/// Get: Parallel block size; set either automatically, or through the constructors Blake2Params ThreadCount() parameter. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	virtual const size_t ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return MAX_PRLBLOCK; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return m_minParallel; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class as either the 2S or 2SP.
	/// <para>Initialize as either the parallel version Blake2SP, or sequential Blake2S.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the Blake2SP variant.</param>
	explicit BlakeS256(bool Parallel = false);

	/// <summary>
	/// Initialize the class with a Blake2Params structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (ThreadCount).
	/// If the ThreadCount is greater than 1, parallel mode (Blake2SP) is instantiated.
	/// The default thread count is 8, changing from the default will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The Blake2Params structure, containing the tree configuration settings.</param>
	explicit BlakeS256(Blake2Params &Params);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~BlakeS256();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process the message data and return the Hash value
	/// </summary>
	/// 
	/// <param name="Input">The message input data</param>
	/// <param name="Output">The hash value output array</param>
	virtual void Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Perform final processing and return the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	virtual size_t Finalize(std::vector<uint8_t> &Output, const size_t OutOffset);

	/// <summary>
	/// Run the digest as an HKDF bytes generator
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters; the input Key should be at least as large as the hash output size</param>
	/// <param name="Output">The array to fill with pseudo random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(ISymmetricKey &MacKey, std::vector<uint8_t> &Output);

	/// <summary>
	/// Initialize the digest as a MAC code generator
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters. 
	/// <para>The input Key must be a maximum size of 32 bytes, and a minimum size of 16 bytes. 
	/// If either the Salt or Info parameters are used, their size must be 8 bytes.
	/// The maximum combined size of Key, Salt, and Info, must be 64 bytes or less.</para></param>
	virtual void LoadMacKey(ISymmetricKey &MacKey);

	/// <summary>
	/// Reset the internal state to sequential defaults
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input message byte</param>
	virtual void Update(uint8_t Input);

	/// <summary>
	/// Update the message buffer
	/// </summary>
	///
	/// <remarks>
	/// <para>For best performance in parallel mode, use block sizes that are evenly divisible by ParallelMinimumSize() to reduce caching.
	/// Block size for parallel mode should be in a range of minimum 32KiB to 25MiB, larger block sizes reduce the impact of parallel loop creation.</para>
	/// </remarks>
	/// 
	/// <param name="Input">The Input message data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">The amount of data to process in bytes</param>
	virtual void Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length);

private:
	void Detect();
	void Initialize(Blake2Params &Params, Blake2sState &State);
	void ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, size_t Length);
	void ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, uint64_t Length);
};

NAMESPACE_DIGESTEND
#endif