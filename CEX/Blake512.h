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
// An implementation of Blake2, designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn, and Christian Winnerlein. 
// Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.
// 
// Implementation Details:
// An implementation of the Blake512Compress and Blake2BP digests with a 512 bit digest output size.
// Based on the Blake2 Github projects by Samuel Neves and Christian Winnerlein.
// Blake2: https://github.com/BLAKE2/BLAKE2
//
// Written by John Underhill, June 19, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_BLAKE2B512_H
#define _CEX_BLAKE2B512_H

#include "BlakeParams.h"
#include "IDigest.h"
#include "ISymmetricKey.h"

NAMESPACE_DIGEST

using Key::Symmetric::ISymmetricKey;

/// <summary>
/// An implementation of the Blake512Compress and Blake2BP digests with a 512 bit digest output size
/// </summary> 
/// 
/// <example>
/// <description>Example using the Compute method:</description>
/// <para>Use the Compute method for small to medium data sizes</para>
/// <code>
/// Blake512 dgt;
/// std:vector&lt;byte&gt; hash(dgt.DigestSize(), 0);
/// // compute a hash
/// dgt.Compute(input, hash);
/// </code>
/// </example>
///
/// <example>
/// <description>Use the Update method for large data sizes:</description>
/// <code>
/// Blake512 dgt;
/// std:vector&lt;byte&gt; hash(dgt.DigestSize(), 0);
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
/// <item><description>Algorithm is selected through the constructor (2B or 2BP), parallel version is selected through either the Parallel flag, or via the BlakeParams ThreadCount() configuration parameter.</description></item>
/// <item><description>Parallel and sequential algorithms (Blake512Compress or Blake2BP) produce different digest outputs, this is expected.</description></item>
/// <item><description>Sequential Block size 128 bytes, (1024 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
/// <item><description>Parallel Block input size to the Update function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
/// <item><description>The number of threads used in parallel mode can be user defined through the BlakeParams->ThreadCount property to any even number of threads; note that hash output value will change with threadcount.</description></item>
/// <item><description>Digest output size is fixed at 64 bytes, (512 bits).</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="Update(byte[], size_t, size_t)"/> and Finalize methods</description>/></item>
/// <item><description>The <see cref="Finalize(byte[], size_t)"/> method resets the internal state.</description></item>
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
class Blake512 : public IDigest
{
private:

	static const size_t BLOCK_SIZE = 128;
	static const uint CHAIN_SIZE = 8;
	static const uint COUNTER_SIZE = 2;
	static const uint DEF_PRLDEGREE = 4;
	static const uint DEF_LEAFSIZE = 16384;
	static const size_t DIGEST_SIZE = 64;
	static const uint FLAG_SIZE = 2;
	static const uint MAX_PRLBLOCK = 5120000;
	static const uint MIN_PRLBLOCK = 512;
	static const size_t ROUND_COUNT = 12;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;
	static const ulong ULL_MAX = 18446744073709551615;

	struct Blake2bState
	{
		std::vector<ulong> F;
		std::vector<ulong> H;
		std::vector<ulong> T;

		Blake2bState()
			:
			F(2),
			H(8),
			T(2)
		{
		}

		void Reset()
		{
			if (F.size() > 0)
				memset(&F[0], 0, F.size() * sizeof(ulong));
			if (H.size() > 0)
				memset(&H[0], 0, H.size() * sizeof(ulong));
			if (T.size() > 0)
				memset(&T[0], 0, T.size() * sizeof(ulong));
		}
	};

	std::vector<ulong> m_cIV;
	std::vector<Blake2bState> m_dgtState;
	bool m_isDestroyed;
	uint m_leafSize;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	std::vector<ulong> m_treeConfig;
	bool m_treeDestroy;
	BlakeParams m_treeParams;
	ParallelOptions m_parallelProfile;

public:

	Blake512(const Blake512&) = delete;
	Blake512& operator=(const Blake512&) = delete;
	Blake512& operator=(Blake512&&) = delete;

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
	virtual const Digests Enumeral() 
	{ 
		return Digests::Blake512;
	}

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() { return m_parallelProfile.IsParallel(); }

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name()
	{
		return "Blake512";
	}

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	virtual const size_t ParallelBlockSize() { return m_parallelProfile.ParallelBlockSize(); }

	/// <summary>
	/// Get/Set: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a BlakeParams with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() { return m_parallelProfile; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class as either the 2B or 2BP.
	/// <para>Initialize as either the parallel version Blake2BP, or sequential Blake512Compress.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the Blake2BP variant.</param>
	explicit Blake512(bool Parallel = false);

	/// <summary>
	/// Initialize the class with a BlakeParams structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (ThreadCount).
	/// If the ThreadCount is greater than 1, parallel mode (Blake2BP) is instantiated.
	/// The default threadcount is 4, changing from the default will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The BlakeParams structure, containing the tree configuration settings.</param>
	explicit Blake512(BlakeParams &Params);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Blake512();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process the message data and return the Hash value
	/// </summary>
	/// 
	/// <param name="Input">The message input data</param>
	/// <param name="Output">The hash value output array</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output);

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
	virtual size_t Finalize(std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the digest as a MAC code generator
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters. 
	/// <para>The input Key must be a maximum size of 32 bytes, and a minimum size of 16 bytes. 
	/// If either the Salt or Info parameters are used, their size must be 8 bytes.
	/// The maximum combined size of Key, Salt, and Info, must be 64 bytes or less.</para></param>
	virtual void Initialize(ISymmetricKey &MacKey);

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoDigestException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Reset the internal state to sequential defaults
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input message byte</param>
	virtual void Update(byte Input);

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
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:

	void Compress(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, size_t Length);
	void LoadState(Blake2bState &State);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
