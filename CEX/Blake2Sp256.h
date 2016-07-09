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
// 
// Principal Algorithms:
// An implementation of Blake2, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn, and Christian Winnerlein. 
// Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.
// 
// Implementation Details:
// An implementation of the Blake2S and Blake2SP digests with a 256 bit digest output size.
// Based on the Blake2 Github projects by Samuel Neves and Christian Winnerlein.
// Blake2: https://github.com/BLAKE2/BLAKE2
//
// Written by John Underhill, June 19, 2016
// contact: develop@vtdev.com

#ifndef _CEXENGINE_BLAKE2SS256_H
#define _CEXENGINE_BLAKE2SS256_H

#include "Blake2Params.h"
#include "Config.h"
#include "IDigest.h"
#include "MacParams.h"

NAMESPACE_DIGEST

/// <summary>
/// Blake2Sp256: An implementation of the Blake2S and Blake2SP digests with a 256 bit digest output size
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <para>Use the ComputeHash method for small to medium data sizes</para>
/// <code>
/// Blake2Sp256 dgt;
/// std:vector&lt;uint8_t&gt; hash(dgt.DigestSize(), 0);
/// // compute a hash
/// dgt.ComputeHash(input, hash);
/// </code>
/// </example>
///
/// <example>
/// <description>Example using the BlockUpdate and DoFinal methods:</description>
/// <para>Use the BlockUpdate method for large data sizes</para>
/// <code>
/// Blake2Sp256 dgt;
/// std:vector&lt;uint8_t&gt; hash(dgt.DigestSize(), 0);
/// int64_t len = (int64_t)input.size();
///
/// // update blocks
/// while (len > dgt.DigestSize())
/// {
///		dgt.BlockUpdate(input, offset, len);
///		offset += dgt.DigestSize();
///		len -= dgt.DigestSize();
/// }
///
/// if (len > 0)
///		dgt.BlockUpdate(input, offset, len);
///
/// dgt.DoFinal(hash, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Algorithm is selected through the constructor (2S or 2SP), parallel version is selected through either the Parallel flag, or via the Blake2Params ThreadCount() configuration parameter.</description></item>
/// <item><description>Parallel and sequential algorithms (Blake2S or Blake2SP) produce different digest outputs, this is expected.</description></item>
/// <item><description>Sequential Block size is 64 bytes, (512 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
/// <item><description>Parallel Block input size to the BlockUpdate function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
/// <item><description>The number of threads used in parallel mode can be user defined through the Blake2Params->ThreadCount property to any even number of threads; note that hash value will change with threadcount.</description></item>
/// <item><description>Digest output size is fixed at 32 bytes, (256 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(uint8_t[])"/> method wraps the <see cref="BlockUpdate(uint8_t[], size_t, size_t)"/> and DoFinal methods</description>/></item>
/// <item><description>The <see cref="DoFinal(uint8_t[], size_t)"/> method resets the internal state.</description></item>
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
class Blake2Sp256 : public IDigest
{
private:
	static constexpr uint32_t BLOCK_SIZE = 64;
	static constexpr uint32_t CHAIN_SIZE = 8;
	static constexpr uint32_t COUNTER_SIZE = 2;
	static constexpr uint32_t PARALLEL_DEG = 8;
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
	bool m_hasIntrinsics;
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

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name()
	{
		if (m_isParallel)
			return "BlakeSP256";
		else
			return "Blake2SP256";
	}

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual CEX::Enumeration::Digests Enumeral() 
	{ 
		if (m_isParallel)
			return CEX::Enumeration::Digests::Blake2SP256;
		else
			return CEX::Enumeration::Digests::Blake2S256;
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

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class as either the 2S or 2SP variant.
	/// <para>Initialize as either the parallel version Blake2SP, or sequential Blake2S variant.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the Blake2SP variant.</param>
	explicit Blake2Sp256(bool Parallel = false)
		:
		m_hasIntrinsics(false),
		m_isDestroyed(false),
		m_isParallel(Parallel),
		m_leafSize(Parallel ? DEF_LEAFSIZE : BLOCK_SIZE),
		m_minParallel(0),
		m_msgBuffer(Parallel ? 2 * PARALLEL_DEG * BLOCK_SIZE : BLOCK_SIZE),
		m_msgLength(0),
		m_State(Parallel ? 8 : 1),
		m_treeConfig(CHAIN_SIZE),
		m_treeDestroy(true)
	{
		m_cIV =
		{
			0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
			0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
		};

		// intrinsics support switch
		DetectCpu();

		if (m_isParallel)
		{
			// sets defaults of depth 2, fanout 8, 8 threads
			m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 8, 2, 0, 0, 0, (uint8_t)DIGEST_SIZE, 8 };
			// minimum block size
			m_minParallel = PARALLEL_DEG * BLOCK_SIZE;
			// default parallel input block expected is Pn * 16384 bytes
			m_parallelBlockSize = m_leafSize * PARALLEL_DEG;
			// initialize the leaf nodes 
			Reset();
		}
		else
		{
			// default depth 1, fanout 1, leaf length unlimited
			m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 1, 1, 0, 0, 0, 0, 0 };
			Initialize(m_treeParams, m_State[0]);
		}
	}

	/// <summary>
	/// Initialize the class with a Blake2Params structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (ThreadCount).
	/// If the ThreadCount is greater than 1, parallel mode (Blake2SP) is instantiated.
	/// The default thread count is 8, changing from the default will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The Blake2Params structure, containing the tree configuration settings.</param>
	explicit Blake2Sp256(Blake2Params &Params)
		:
		m_hasIntrinsics(false),
		m_isDestroyed(false),
		m_isParallel(false),
		m_leafSize(BLOCK_SIZE),
		m_minParallel(0),
		m_msgBuffer(Params.ThreadDepth() > 0 ? 2 * Params.ThreadDepth() * BLOCK_SIZE: BLOCK_SIZE),
		m_msgLength(0),
		m_State(Params.ThreadDepth() > 0 ? Params.ThreadDepth() : 1),
		m_treeConfig(CHAIN_SIZE),
		m_treeDestroy(false),
		m_treeParams(Params)
	{
		m_isParallel = m_treeParams.ThreadDepth() > 1;
		m_cIV =
		{
			0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
			0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
		};

		// intrinsics support switch
		DetectCpu();

		if (m_isParallel)
		{
#if defined(_DEBUG)
			assert(Params.LeafLength() > BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE == 0);
			assert(Params.ThreadDepth() > 2 || Params.ThreadDepth() % 2 == 0);
#endif
#if defined(CPP_EXCEPTIONS)
			if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
				throw CEX::Exception::CryptoDigestException("BlakeSP256:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
			if (Params.ThreadDepth() < 2 || Params.ThreadDepth() % 2 != 0)
				throw CEX::Exception::CryptoDigestException("BlakeSP256:Ctor", "The ThreadDepth parameter is invalid! Must be an even number greater than 1.");
#endif

			m_minParallel = m_treeParams.ThreadDepth() * BLOCK_SIZE;
			m_leafSize = Params.LeafLength() == 0 ? DEF_LEAFSIZE : Params.LeafLength();
			// set parallel block size as Pn * leaf size 
			m_parallelBlockSize = Params.ThreadDepth() * m_leafSize;
			Reset();
		}
		else
		{
			// fixed at defaults for sequential; depth 1, fanout 1, leaf length unlimited
			m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 1, 1, 0, 0, 0, 0, 0 };
			Initialize(m_treeParams, m_State[0]);
		}
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Blake2Sp256()
	{
		Destroy();
	}

	// *** Public Methods *** //

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
	virtual void BlockUpdate(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Process the message data and return the Hash value
	/// </summary>
	/// 
	/// <param name="Input">The message input data</param>
	/// <param name="Output">The hash value output array</param>
	virtual void ComputeHash(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output);

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
	virtual size_t DoFinal(std::vector<uint8_t> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the digest as a counter based DRBG
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters; the input Key must be a minimum of 32 bytes, maximum of combined Key, Salt, and Info, must be 64 bytes or less</param>
	/// <param name="Output">The psuedo random output</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(CEX::Common::MacParams &MacKey, std::vector<uint8_t> &Output);

	/// <summary>
	/// Initialize the digest as a MAC code generator
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters. 
	/// <para>The input Key must be a maximum size of 32 bytes, and a minimum size of 16 bytes. 
	/// If either the Salt or Info parameters are used, their size must be 8 bytes.
	/// The maximum combined size of Key, Salt, and Info, must be 64 bytes or less.</para></param>
	virtual void LoadMacKey(CEX::Common::MacParams &MacKey);

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

private:
	void DetectCpu();
	void Increase(Blake2sState &State, uint32_t Length);
	void Increment(std::vector<uint8_t> &Counter);
	void Initialize(Blake2Params &Params, Blake2sState &State);
	void ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, size_t Length);
	void ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, Blake2sState &State, uint64_t Length);
};

NAMESPACE_DIGESTEND
#endif
