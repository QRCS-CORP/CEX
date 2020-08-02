// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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
// The Skein Hash Function Family: <a href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</a>.
// Implementation Details:
// An implementation of the Skein digest with a 256 bit digest size. 
// Written by John G. Underhill, January 13, 2015
// Updated July 2, 2018
// Updated March 19, 2019
// Updated March 23, 2020
// Contact: develop@vtdev.commo


#ifndef CEX_SKEIN256_H
#define CEX_SKEIN256_H

#include "IDigest.h"
#include "SkeinParams.h"
#include "SkeinUbiTweak.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the Skein sequential and parallel message-digests with a 256-bit hash code
/// </summary> 
/// 
/// <example>
/// <description>Example using the Update method:</description>
/// <code>
/// Skein256 dgt;
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Tree Hashing Description:</description>
/// <para>The tree hashing mode is instantiated when the parallel mechanism is engaged through one of the two constructors parameters. \n 
/// The default settings are applied when using the Skein256(bool) constructor, or a manually defined configuration when using the Skein256(SkeinParams) constructor. \n
/// The SkeinParams structure contains property accessors that are initialized by the boolean constructor at their defaults; 
/// Schema(83,72,65,51) OuputSize(64), Version(1), FanOut(Parallel ? 8 : 0), and LeafSize(32). \n
/// The SkeinParams structure when passed to the constructor, can be used to change the FanOut property (which corresponds to the number of threads used in parallel mode), 
/// which must be an even number less or equal to the number of processing cores. \n
/// For best performance in tree hashing mode, the message input block-size (Length parameter of an Update call), should be ParallelBlockSize in length. \n
/// The ideal parallel block-size is calculated automatically based on the hardware profile and algorithm requirments. \n
/// The parallel mode uses multi-threaded parallel processing, with each thread maintaining a single unique state. \n
/// The hash finalizer processes each leaf state as contiguous message input for the root hash; i.e. R = H(S0 || S1 || S2 || ...Sn). \n 
/// The FanOut accessor in a SkeinParams structure is the sum number of leaves in the sequential hash chain, the default is 8, which uses eight states/threads. \n 
/// Changing any of the SkeinParams values from their defaults, will produce a different hash output. \n
/// The SkeinParams structure also contains an optional DistributionCode() property, which is a personalization string applied when generating the initial state (the default is zero).
/// The personalization string can be used to create a unique distribution, in either sequential or parallel operating modes.
/// The DistributionCodeMax() accessor provides the upper limit to the personalization strings byte-length, this size is different for each variant; (256=8, 512=40, 1024=104).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The input message block-size is 32 bytes, (256 bits).</description></item>
/// <item><description>Digest output size is 32 bytes, (256 bits).</description></item>
/// <item><description>The ComputeHash(byte[], byte[]) function wraps the Update(byte[], size_t, size_t) and Finalize(byte[], size_t) functions; (suitable for small data).</description>/></item>
/// <item><description>The Update functions process message input, this can be a byte, 32--bit or 64-bit unsigned integer, or a vector of bytes.</description></item>
/// <item><description>The Finalize(byte[], size_t) function returns the hash code but does not reset the internal state, call Reset() to reinitialize to default state.</description></item>
/// <item><description>Setting Parallel to true in the constructor instantiates the multi-threaded variant using a default FanOut of 8 threads.</description></item>
/// <item><description>Multi-threaded and sequential versions produce a different output hash for a message, and changing the Fanout property from the default of 8, will also change the output hash.</description></item>
/// <item><description>The supported tree hashing mode in this implementation is a sequential chain (hash list); intermediate hashes are finalized as contiguous message input to the root hash in the finalizer.</description></item>
/// </list> 
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The Skein Hash Function Family <a href="https://www.schneier.com/academic/paperfiles/skein1.3.pdf">Skein V1.1</a>.</description></item>
/// <item><description>NIST Round 3 <a href="https://www.schneier.com/academic/paperfiles/skein-1.3-modifications.pdf">Tweak Description</a>.</description></item>
/// <item><description>Skein <a href="https://www.schneier.com/academic/paperfiles/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition>.</description></item>
/// </list>
/// </remarks>
class Skein256 final : public IDigest
{
private:

	static const size_t DEF_PRLDEGREE = 8;
	static const size_t MAX_PRLDEGREE = 64;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	class Skein256State;
	std::vector<Skein256State> m_dgtState;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;
	SkeinParams m_treeParams;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Skein256(const Skein256&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Skein256& operator=(const Skein256&) = delete;

	/// <summary>
	/// Initialize the class with either the Parallel or Sequential hashing engine.
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard Skein 512bit hashing instance.
	/// Note: this constructor will revert to sequential processing when set to parallel on a system that does not support parallel processing</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded Skein variant.</param>
	explicit Skein256(bool Parallel = false);

	/// <summary>
	/// Initialize the class with an SkeinParams structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (FanOut).
	/// If the parallel degree is greater than 1, multi-threading hash engine is instantiated.
	/// The default thread count is 8, changing this value will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The SkeinParams structure, containing the tree configuration settings.</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the SkeinParams structure contains invalid values</exception>
	explicit Skein256(SkeinParams &Params);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Skein256() override;

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
	/// and reinitialize the state, or initialize the digest using a SkeinParams with the FanOut property set to the desired number of threads.</para>
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
	/// <param name="Input">Input byte</param>
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
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	static void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, Skein256State &State);
	static void Initialize(std::vector<Skein256State> &State, SkeinParams &Params);
	static void LoadState(Skein256State &State, std::array<ulong, 4> &Config);
	static void Permute(std::array<ulong, 4> &Message, Skein256State &State);
	static void ProcessBlock(const std::vector<byte> &Input, size_t InOffset, Skein256State &State, size_t Length);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, Skein256State &State, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
