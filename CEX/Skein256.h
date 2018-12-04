// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
// The Skein Hash Function Family: <a href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</a>.
// Implementation Details:
// An implementation of the Skein digest with a 256 bit digest size. 
// Written by John Underhill, January 13, 2015
// Updated July 2, 2018
// Contact: develop@vtdev.commo


#ifndef CEX_SKEIN256_H
#define CEX_SKEIN256_H

#include "IDigest.h"
#include "SkeinParams.h"
#include "SkeinUbiTweak.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the Skein message digest with a 256 bit digest return size
/// </summary> 
/// 
/// <example>
/// <description>Example using the Update method:</description>
/// <code>
/// Skein256 dgt;
/// std::vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(hash, 0);
/// dgt.Reset();
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Tree Hashing Description:</description>
/// <para>The tree hashing mode is instantiated when the parallel mechanism is engaged through one of the two constructors. \n 
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
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="Update(byte[], size_t, size_t)"/> and <see cref="Finalize(byte[], size_t)"/> methods; (suitable for small data).</description>/></item>
/// <item><description>The <see cref="Update(byte)"/> and <see cref="Update(byte[], size_t, size_t)"/> methods process message input.</description></item>
/// <item><description>The <see cref="Finalize(byte[], size_t)"/> method returns the hash or MAC code but does not reset the internal state, call <see cref="Reset()"/> to reinitialize to default state.</description></item>
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

	static const size_t BLOCK_SIZE = 32;
	static const std::string CLASS_NAME;
	static const byte DEF_PRLDEGREE = 8;
	static const size_t DIGEST_SIZE = 32;
	static const size_t MAX_PRLBLOCK = 1024 * 1000 * DEF_PRLDEGREE * 100;
	static const size_t MIN_PRLBLOCK = BLOCK_SIZE * DEF_PRLDEGREE;
	static const size_t STATE_SIZE = 4;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	struct Skein256State;
	std::vector<Skein256State> m_dgtState;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;
	bool m_treeDestroy;
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
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard Skein 512bit hashing instance.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded Skein variant.</param>
	///
	/// <exception cref="Exception::CryptoDigestException">Thrown if an invalid parallel parameters are used</exception>
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
	/// Read Only: The Digests internal blocksize in bytes
	/// </summary>
	size_t BlockSize() override;

	/// <summary>
	/// Read Only: Size of returned digest in bytes
	/// </summary>
	size_t DigestSize() override;

	/// <summary>
	/// Read Only: The digests type name
	/// </summary>
	const Digests Enumeral() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: The digests class name
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
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	size_t Finalize(std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	void Update(byte Input) override;

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<Skein256State> &State, size_t StateOffset);
	void Initialize();
	void LoadState(Skein256State &State, std::array<ulong, 4> &Config);
	void Permute(std::array<ulong, 4> &Message, Skein256State &State);
	void ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein256State> &State, size_t StateOffset, size_t Length = BLOCK_SIZE);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein256State> &State, size_t StateOffset, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
