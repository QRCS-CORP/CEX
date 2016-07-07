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
// An implementation of the Blake2B and Blake2BP digests with a 512 bit digest output size.
// Based on the Blake2 Github projects by Samuel Neves and Christian Winnerlein.
// Blake2: https://github.com/BLAKE2/BLAKE2
//
// Written by John Underhill, June 19, 2016
// contact: develop@vtdev.com

#ifndef _CEXENGINE_BLAKE2B512_H
#define _CEXENGINE_BLAKE2B512_H

#include "Blake2Params.h"
#include "Config.h"
#include "IDigest.h"
#include "MacParams.h"

NAMESPACE_DIGEST

	/// <summary>
	/// Blake2Bp512: An implementation of the Blake2B and Blake2BP digests with a 512 bit digest output size
	/// </summary> 
	/// 
	/// <example>
	/// <description>Example using the ComputeHash method:</description>
	/// <para>Use the ComputeHash method for small to medium data sizes</para>
	/// <code>
	/// Blake2Bp512 dgt;
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
	/// Blake2Bp512 dgt;
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
	/// <item><description>Algorithm is selected through the constructor (2B or 2BP), parallel version is selected through either the Parallel flag, or via the Blake2Params ThreadCount() configuration parameter.</description></item>
	/// <item><description>Parallel and sequential algorithms (Blake2B or Blake2BP) produce different digest outputs, this is expected.</description></item>
	/// <item><description>Sequential Block size is fixed at 128 bytes, (1024 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
	/// <item><description>Parallel Block input size to the BlockUpdate function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
	/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
	/// <item><description>Digest output size is fixed at 64 bytes, (512 bits).</description></item>
	/// <item><description>The <see cref="ComputeHash(uint8_t[])"/> method wraps the <see cref="BlockUpdate(uint8_t[], size_t, size_t)"/> and DoFinal methods</description>/></item>
	/// <item><description>The <see cref="DoFinal(uint8_t[], size_t)"/> method resets the internal state.</description></item>
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
	class Blake2Bp512 : public IDigest
	{
	private:
		static constexpr uint32_t BLOCK_SIZE = 128;
		static constexpr uint32_t CHAIN_SIZE = 8;
		static constexpr uint32_t COUNTER_SIZE = 2;
		static constexpr uint32_t PARALLEL_DEG = 4;
		const uint32_t DEF_LEAFSIZE = 16384;
		const size_t DIGEST_SIZE = 64;
		const uint32_t FLAG_SIZE = 2;
		const uint32_t MAX_PRLBLOCK = 5120000;
		const uint32_t MIN_PRLBLOCK = 512;
		const size_t ROUND_COUNT = 12;
		const uint64_t ULL_MAX = 18446744073709551615;

		struct Blake2bState
		{
			std::vector<uint64_t> H;
			std::vector<uint64_t> T;
			std::vector<uint64_t> F;

			Blake2bState()
				:
				F(2, 0),
				H(8, 0),
				T(2, 0)
			{
			}

			void Reset()
			{
				if (F.size() > 0)
					memset(&F[0], 0, F.size() * sizeof(uint64_t));
				if (H.size() > 0)
					memset(&H[0], 0, H.size() * sizeof(uint64_t));
				if (T.size() > 0)
					memset(&T[0], 0, T.size() * sizeof(uint64_t));
			}
		};

		std::vector<uint64_t> m_cIV;
		bool m_hasIntrinsics;
		bool m_isDestroyed;
		bool m_isParallel;
		uint32_t m_leafSize;
		std::vector<uint8_t> m_msgBuffer;
		size_t m_msgLength;
		size_t m_parallelBlockSize;
		std::vector<Blake2bState> m_State;
		std::vector<uint64_t> m_treeConfig;
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
		/// Get: The digests type enumeration member
		/// </summary>
		virtual CEX::Enumeration::Digests Enumeral() 
		{ 
			if (m_isParallel)
				return CEX::Enumeration::Digests::Blake2BP512;
			else
				return CEX::Enumeration::Digests::Blake2B512;
		}

		/// <summary>
		/// Get: Digest name
		/// </summary>
		virtual const char *Name()
		{
			if (m_isParallel)
				return "BlakeBP512";
			else
				return "Blake2BP512";
		}

		/// <summary>
		/// Get/Set: Parallel block size; set either automatically, or through the constructors Blake2Params parameter. Must be a multiple of <see cref="ParallelMinimumSize"/>.
		/// </summary>
		size_t &ParallelBlockSize() { return m_parallelBlockSize; }

		/// <summary>
		/// Get: Maximum input size with parallel processing
		/// </summary>
		const size_t ParallelMaximumSize() { return MAX_PRLBLOCK; }

		/// <summary>
		/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
		/// </summary>
		const size_t ParallelMinimumSize() { return m_minParallel; }

		// *** Constructor *** //

		/// <summary>
		/// Initialize the digest
		/// </summary>
		///
		/// <remarks>
		/// <para>Setting the Parallel mode to true initializes the Blake2BP digest configuration (parallel), when set to false initializes the Blake2B configuration.
		/// Note that the two different algorithms (BlakeB and BlakeBP) will return different hash codes (this is expected, use one or the other).</para>
		/// <remarks>
		///
		/// <param name="Parallel">If set to true the digest uses the Blake2BP parallel configuration, false processes in sequential mode.</param>
		explicit Blake2Bp512(bool Parallel = false)
			:
			m_hasIntrinsics(false),
			m_isDestroyed(false),
			m_isParallel(Parallel),
			m_leafSize(Parallel ? DEF_LEAFSIZE : BLOCK_SIZE),
			m_minParallel(0),
			m_msgBuffer(Parallel ? 2 * PARALLEL_DEG * BLOCK_SIZE : BLOCK_SIZE),
			m_msgLength(0),
			m_State(Parallel ? PARALLEL_DEG : 1),
			m_treeConfig(8),
			m_treeDestroy(true)
		{
			m_cIV =
			{
				0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
				0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
			};

			// intrinsics support switch
			DetectCpu();

			if (m_isParallel)
			{
				// sets defaults of depth 2, fanout 4, 4 threads
				m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 4, 2, 0, 0, 0, (uint8_t)DIGEST_SIZE, 4 };
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
		/// Initialize the digest
		/// </summary>
		///
		/// <remarks>
		/// <para>Setting the TreeConfig::FanOut() to greater than 1 initializes the Blake2-BP digest configuration (parallel), when set to false initializes the Blake2-B configuration.
		/// Note that the two different algorithms (BlakeB and BlakeBP) will return different hash codes (this is expected, use one or the other).
		/// The default sequential mode Blake2Params configuration settings are : treeParams = { (uint8_t)DIGEST_SIZE, 0, 1, 1, 0, 0, 0, 0, 0 };.
		/// The default parallel mode Blake2Params configuration settings are : treeParams = { (uint8_t)DIGEST_SIZE, 0, 4, 2, 0, 0, 0, (uint8_t)DIGEST_SIZE, 4 };.
		/// See the Blake2Params documentation for details on flags and configuration settings.</para>
		/// </remarks>
		/// 
		/// <param name="Params">A Blake2Params structure containing the Tree Hash configuration settings.</param>
		explicit Blake2Bp512(Blake2Params &Params)
			:
			m_hasIntrinsics(false),
			m_isDestroyed(false),
			m_isParallel(false),
			m_leafSize(BLOCK_SIZE),
			m_minParallel(0),
			m_msgBuffer(Params.ThreadDepth() > 0 ? 2 * Params.ThreadDepth() * BLOCK_SIZE : BLOCK_SIZE),
			m_msgLength(0),
			m_State(Params.ThreadDepth() > 0 ? Params.ThreadDepth() : 1),
			m_treeConfig(CHAIN_SIZE),
			m_treeDestroy(false),
			m_treeParams(Params)
		{
			m_isParallel = m_treeParams.ThreadDepth() > 1;
			m_cIV =
			{
				0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
				0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
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
					throw CEX::Exception::CryptoDigestException("BlakeBP512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
				if (Params.ThreadDepth() < 2 || Params.ThreadDepth() % 2 != 0)
					throw CEX::Exception::CryptoDigestException("BlakeBP512:Ctor", "The ThreadDepth parameter is invalid! Must be an even number greater than 1.");
#endif

				m_minParallel = m_treeParams.ThreadDepth() * BLOCK_SIZE;
				m_leafSize = Params.LeafLength() == 0 ? DEF_LEAFSIZE : Params.LeafLength();
				// set parallel block size as Pn * leaf size 
				m_parallelBlockSize = Params.ThreadDepth() * m_leafSize;
				// initialize leafs
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
		virtual ~Blake2Bp512()
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
		void Destroy();

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
		/// <param name="MacKey">The input key parameters; the input Key must be a minimum of 64 bytes, maximum of combined Key, Salt, and Info, must be 128 bytes or less</param>
		/// <param name="Output">The psuedo random output</param>
		/// 
		/// <returns>The number of bytes generated</returns>
		size_t Generate(CEX::Common::MacParams &MacKey, std::vector<uint8_t> &Output);

		/// <summary>
		/// Initialize the digest as a MAC code generator
		/// </summary>
		/// 
		/// <param name="MacKey">The input key parameters. 
		/// <para>The input Key must be a maximum size of 64 bytes, and a minimum size of 32 bytes. 
		/// If either the Salt or Info parameters are used, their size must be 16 bytes.
		/// The maximum combined size of Key, Salt, and Info, must be 128 bytes or less.</para></param>
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
		void Increase(Blake2bState &State, uint64_t Length);
		void Increment(std::vector<uint8_t> &Counter);
		void Initialize(Blake2Params &Params, Blake2bState &State);
		void ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, Blake2bState &State, size_t Length);
		void ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, Blake2bState &State, uint64_t Length);
	};

NAMESPACE_DIGESTEND
#endif
