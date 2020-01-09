// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
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
// Written by John G. Underhill, June 19, 2016
// Updated March 1, 2017
// Updated April 18, 2017
// Updated March 19, 2019
// Contact: develop@vtdev.com

#ifndef CEX_BLAKE512_H
#define CEX_BLAKE512_H

#include "BlakeParams.h"
#include "IDigest.h"
#include "ISymmetricKey.h"

NAMESPACE_DIGEST

using Cipher::ISymmetricKey;

/// <summary>
/// An implementation of the Blake2B and Blake2BP sequential and parallel message-digests using a 512-bit hash code
/// </summary> 
/// 
/// <example>
/// <description>Example using the simplified Compute method:</description>
/// <para>Use the Compute for small-to-medium sized data.</para>
/// <code>
/// Blake512 dgt;
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The algorithm, parallel or sequential, is selected through the constructor (2B or 2BP); the parallel version is selected through either the Parallel flag, or via the BlakeParams ThreadCount() configuration parameter.</description></item>
/// <item><description>Parallel and sequential algorithms (Blake2B or Blake2BP) produce different digest outputs.</description></item>
/// <item><description>The sequential Block size is 128 bytes, (1024 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
/// <item><description>When using the Update function in a parallel configuration, input data length should be aligned to the ParallelBlockSize() for best performance, this is the minimum input size that triggers parallel processing.</description></item>
/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KB to 24MB.</description></item>
/// <item><description>The number of threads used in parallel mode can be user defined through the BlakeParams->ThreadCount property to any even number of threads; note that hash output value will change with threadcount.</description></item>
/// <item><description>Digest output size is fixed at 64 bytes, (512 bits).</description></item>
/// <item><description>The ComputeHash(byte[], byte[]) function wraps the Update(byte[], size_t, size_t) and Finalize(byte[], size_t) functions; (suitable for small data).</description>/></item>
/// <item><description>The Update functions process message input, this can be a byte, 32--bit or 64-bit unsigned integer, or a vector of bytes.</description></item>
/// <item><description>The Finalize(byte[], size_t) function returns the hash code but does not reset the internal state, call Reset() to reinitialize to default state.</description></item>
/// <item><description>Setting Parallel to true in the constructor instantiates the multi-threaded variant.</description></item>
/// <item><description>Multi-threaded and sequential versions produce a different output hash for a message, this is expected.</description></item>
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
class Blake512 final : public IDigest
{
private:

	static const size_t CONFIG_SIZE = 8;
	static const size_t DEF_PRLDEGREE = 4;
	static const size_t MAX_PRLDEGREE = 64;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	class Blake2bState;
	std::vector<Blake2bState> m_dgtState;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;
	BlakeParams m_treeParams;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Blake512(const Blake512&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Blake512& operator=(const Blake512&) = delete;

	/// <summary>
	/// Initialize the class as either the 2B or 2BP.
	/// <para>Initialize as either the parallel version Blake2BP, or sequential Blake2B.
	/// Note: this constructor will revert to sequential processing when set to parallel on a system that does not support parallel processing</para>
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
	///
	/// <exception cref="CryptoDigestException">Thrown if an invalid configuration parameters are passed</exception>
	explicit Blake512(BlakeParams &Params);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Blake512() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The message-digests internal block size in bytes
	/// </summary>
	size_t BlockSize() override;

	/// <summary>
	/// Read Only: The message-digests output hash-size in bytes
	/// </summary>
	size_t DigestSize() override;

	/// <summary>
	/// Read Only: The message-digests enumeration type-name
	/// </summary>
	const Digests Enumeral() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: The message-digests formal class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a BlakeParams with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Compute the hash value in a single-step using the input message and the output vector receiving the hash code.
	/// <para>Not recommended for vector sizes exceeding 1MB, use the Update/Finalize api to loop in large data.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message byte-vector</param>
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Finalize message processing and return the hash code.
	/// <para>Used in conjunction with the Update api to process a message, and then return the finalized hash code.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	void Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the digest as a MAC code generator
	/// </summary>
	/// 
	/// <param name="MacKey">The input key parameters. 
	/// <para>The input Key must be a maximum size of 32 bytes, and a minimum size of 16 bytes. 
	/// If either the Salt or Info parameters are used, their size must be 8 bytes.
	/// The maximum combined size of Key, Salt, and Info, must be 64 bytes or less.</para></param>
	///
	/// <exception cref="CryptoDigestException">Thrown if an invalid key size is used</exception>
	void Initialize(ISymmetricKey &MacKey);

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Reset the message-digests internal state
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input message byte</param>
	void Update(byte Input) override;

	/// <summary>
	/// Update the message digest with a single unsigned 32-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 32-bit integer to process</param>
	void Update(uint Input) override;

	/// <summary>
	/// Update the message digest with a single unsigned 64-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 64-bit integer to process</param>
	void Update(ulong Input) override;

	/// <summary>
	/// Update the message digest with a vector using offset and length parameters.
	/// <para>Used in conjunction with the Finalize function, processes message data used to generate the hash code.</para>
	/// </summary>
	///
	/// <param name="Input">The input message byte-vector</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	static void LoadState(Blake2bState &State, BlakeParams &Params, std::vector<ulong> &Config);
	static void Permute(const std::vector<byte> &Input, size_t InOffset, Blake2bState &State);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, ulong Length, Blake2bState &State);
};

NAMESPACE_DIGESTEND
#endif
