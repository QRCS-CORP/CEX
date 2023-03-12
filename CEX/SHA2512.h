// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Written by John G. Underhill, July 31, 2016
// Updated March 20, 2017
// Updated April 18, 2017
// Updated March 19, 2019
// Contact: develop@qscs.ca

#ifndef CEX_SHA2512_H
#define CEX_SHA2512_H

#include "IDigest.h"
#include "SHA2Params.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the SHA-2 sequential and parallel message-digests with a 512-bit hash code
/// </summary> 
/// 
/// <example>
/// <description>Using the Compute method:</description>
/// <code>
/// SHA2512 dgt;
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Tree Hashing Description:</description>
/// <para>The tree hashing mode is instantiated when the parallel mechanism is engaged through the constructors Parallel parameter, 
/// or by setting the FanOut accessor to the number of desired threads when using the SHA2Params constructor. \n 
/// The default number of threads is 8, this can be changed using the ParallelMaxDegree(size_t) function, but not directly through the ParallelProfile accessor,
/// (state sizes must be recalculated when the thread count changes).
/// Changing the thread count from the default, will produce a different hash output. \n
/// The thread count must be an even number less or equal to the number of processing cores. \n
/// For best performance in tree hashing mode, the message input block-size (Length parameter of an Update call), should be ParallelBlockSize in length. \n
/// The ideal parallel block-size is calculated automatically based on the hardware profile and algorithm requirments. \n
/// The parallel mode uses multi-threaded parallel processing, with each thread maintaining a single unique state. \n
/// The hash finalizer processes each leaf state as contiguous message input for the root hash; i.e. R = H(S0 || S1 || S2 || ...Sn).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>State block size is 128 bytes, (1024 bits), in parallel mode the ParallelBlockSize() is used (P * B * 4).</description></item>
/// <item><description>Digest output size is 64 bytes, (512 bits).</description></item>
/// <item><description>The ComputeHash(uint8_t[], uint8_t[]) function wraps the Update(uint8_t[], size_t, size_t) and Finalize(uint8_t[], size_t) functions; (suitable for small data).</description>/></item>
/// <item><description>The Update functions process message input, this can be a uint8_t, 32--bit or 64-bit unsigned integer, or a vector of bytes.</description></item>
/// <item><description>The Finalize(uint8_t[], size_t) function returns the hash code but does not reset the internal state, call Reset() to reinitialize to default state.</description></item>
/// <item><description>Setting Parallel to true in the constructor instantiates the multi-threaded variant.</description></item>
/// <item><description>Multi-threaded and sequential versions produce a different output hash for a message, this is expected.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Standard</a>.</description></item>
/// <item><description><a href="http://keccak.noekeon.org/Sakura.pdf">Sakura:</a> a flexible coding for tree hashing.</description></item>
/// <item><description>SHA2256: A <a href="https://eprint.iacr.org/2012/476.pdf">j-lanes tree hashing mode</a> and j-lanes SHA-256.</description></item>
/// <item><description>Analysis of <a href="http://scholarworks.rit.edu/theses/8312/">KECCAK Tree Hashing</a> on GPU Architectures.</description></item>
/// <item><description>Parallelized Hashing via <a href="http://file.scirp.org/pdf/JIS_2014071709515287.pdf">j-Lanes and j-Pointers</a> Tree Modes.</description></item>
/// <item><description>Analysis of SIMD Applicability to <a href="https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf">SHA Algorithms</a></description></item>
/// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
/// <item><description>NIST, 2014 SHA3 Workshop <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/Aug2014/documents/kelsey_sha3_2014_panel.pdf">What Should Be In A Parallel Hashing Standard?</a>.</description></item>
/// <item><description>Recommendation for Random Number Generation Using <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Deterministic Random Bit Generators.</a></description></item>
/// </list>
/// </remarks>
class SHA2512 final : public IDigest
{
private:

	static const size_t DEF_PRLDEGREE = 8;
	static const size_t MAX_PRLDEGREE = 64;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	class SHA2512State;
	std::vector<SHA2512State> m_dgtState;
	std::vector<uint8_t> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;
	SHA2Params m_treeParams;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SHA2512(const SHA2512&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SHA2512& operator=(const SHA2512&) = delete;

	/// <summary>
	/// Initialize the class with either the Parallel or Sequential hashing engine.
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard SHA-2 256bit hashing instance.
	/// Note: this constructor will revert to sequential processing when set to parallel on a system that does not support parallel processing</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded SHA-2 variant.</param>
	explicit SHA2512(bool Parallel = false);

	/// <summary>
	/// Initialize the class with an SHA2Params structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (FanOut).
	/// If the parallel degree is greater than 1, multi-threading hash engine is instantiated.
	/// The default thread count is 8, changing this value will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The SHA2Params structure, containing the tree configuration settings.</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the SHA2Params structure contains invalid values</exception>
	explicit SHA2512(SHA2Params &Params);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHA2512() override;

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
	/// Read Only: Parallel block size; the uint8_t-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a SHA2Params with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Compute the hash value in a single-step using the input message and the output vector receiving the hash code.
	/// <para>Not recommended for vector sizes exceeding 1MB, use the Update/Finalize api to loop in large data.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message uint8_t-vector</param>
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too int16_t</exception>
	void Compute(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output) override;

	/// <summary>
	/// Finalize message processing and return the hash code.
	/// <para>Used in conjunction with the Update api to process a message, and then return the finalized hash code.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output array is too int16_t</exception>
	void Finalize(std::vector<uint8_t> &Output, size_t OutOffset) override;

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
	/// Update the hash with a single uint8_t
	/// </summary>
	/// 
	/// <param name="Input">Input message uint8_t</param>
	void Update(uint8_t Input) override;

	/// <summary>
	/// Update the message digest with a single unsigned 32-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 32-bit integer to process</param>
	void Update(uint32_t Input) override;

	/// <summary>
	/// Update the message digest with a single unsigned 64-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 64-bit integer to process</param>
	void Update(uint64_t Input) override;

	/// <summary>
	/// Update the message digest with a vector using offset and length parameters.
	/// <para>Used in conjunction with the Finalize function, processes message data used to generate the hash code.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Length">The number of message bytes to process</param>
	void Update(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length) override;

private:

	static void HashFinal(std::vector<uint8_t> &Input, size_t InOffset, size_t Length, SHA2512State &State);
	static void Permute(const std::vector<uint8_t> &Input, size_t InOffset, SHA2512State &State);
	void ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, SHA2512State &State, uint64_t Length);
};

NAMESPACE_DIGESTEND
#endif
