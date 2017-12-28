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
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Principal Algorithms:
// An implementation of the SHA-3 digest based on Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. 
// SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.
// 
// Implementation Details:
// An implementation of the SHA-3 digest with a 256 bit return size. 
// Written by John Underhill, September 19, 2014
// Updated December 25, 2017
// Contact: develop@vtdev.com

#ifndef CEX_KECCAK256_H
#define CEX_KECCAK256_H

#include "IDigest.h"
#include "KeccakParams.h"
#include "KeccakState.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the SHA-3 Keccak digest
/// </summary>
///
/// <example>
/// <description>Example using the Compute method:</description>
/// <code>
/// Keccak256 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.Compute(Input, hash);
/// </code>
/// </example>
///
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Output aligns with the Nist SHA3 standard.</description></item>
/// <item><description>Hash sizes are 28, 32, and 36 bytes (224, 256, and 288 bits).</description></item>
/// <item><description>Block sizes are 144, 128, and 136 bytes (1152, 1024, 1088 bits).</description></item>
/// <item><description>Use the <see cref="BlockSize"/> property to determine block sizes at runtime.</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="Update(byte[], int, int)"/> and Finalize methods.</description>/></item>
/// <item><description>The <see cref="Finalize(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <list type="number">
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Fips202</a>.</description></item>
/// <item><description>NIST <a href = "http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd">SP800-185</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
/// <item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/keccak_specs_summary.html">Specifications</a> summary.</description></item>
/// <item><description>Keccak <a href="https://keccak.team/files/Keccak-reference-3.0.pdf">Reference</a> Guide.</description></item>
/// </list>
/// </remarks>
class Keccak256 final : public IDigest
{
private:

	static const size_t BLOCK_SIZE = 136;
	static const std::string CLASS_NAME;
	static const size_t DEF_PRLDEGREE = 8;
	static const size_t DIGEST_SIZE = 32;
	static const byte DOMAIN_CODE = 0x06;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;
	static const size_t STATE_SIZE = 25;

	std::vector<KeccakState> m_dgtState;
	bool m_isDestroyed;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;
	bool m_treeDestroy;
	KeccakParams m_treeParams;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Keccak256(const Keccak256&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Keccak256& operator=(const Keccak256&) = delete;

	/// <summary>
	/// Initialize the class with either the Parallel or Sequential hashing engine.
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard SHA-3 256bit hashing instance.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded SHA-3 variant.</param>
	///
	/// <exception cref="Exception::CryptoDigestException">Thrown if an invalid parallel parameters are used</exception>
	explicit Keccak256(bool Parallel = false);

	/// <summary>
	/// Initialize the class with an KeccakParams structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (FanOut).
	/// If the parallel degree is greater than 1, multi-threading hash engine is instantiated.
	/// The default thread count is 8, changing this value will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The KeccakParams structure, containing the tree configuration settings.</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the KeccakParams structure contains invalid values</exception>
	explicit Keccak256(KeccakParams &Params);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Keccak256() override;

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
	/// and reinitialize the state, or initialize the digest using a KeccakParams with the FanOut property set to the desired number of threads.</para>
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
	/// Update the digest with a single byte
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

	void Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State);
	void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, KeccakState &State);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, KeccakState &State, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
