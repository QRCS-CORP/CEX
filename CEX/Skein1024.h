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
// The Skein Hash Function Family: <a href="https://www.schneier.com/skein1.3.pdf">Skein V1.1</a>.
// Implementation Details:
// An implementation of the Skein digest with a 1024 bit return size. 
// Written by John Underhill, January 13, 2015
// Updated March 11, 2017
// Contact: develop@vtdev.com

#ifndef _CEX_SKEIN1024_H
#define _CEX_SKEIN1024_H

#include "IDigest.h"
#include "SkeinParams.h"
#include "SkeinUbiTweak.h"
#include "Threefish1024.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the Skein message digest with a 1024 bit digest return size
/// </summary> 
/// 
/// <example>
/// <description>Example using the Update method:</description>
/// <code>
/// Skein1024 dgt;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(hash, 0);
/// dgt.Reset();
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Tree Hashing Description:</description>
/// <para>The tree hashing mode is instantiated when the parallel mechanism is engaged through one of the two constructors.<BR></BR> 
/// The default settings are applied when using the Skein1024(bool) constructor, or a manually defined configuration when using the Skein1024(SkeinParams) constructor.<BR></BR>
/// The SkeinParams structure contains property accessors that are initialized by the boolean constructor at their defaults; 
/// Schema(83,72,65,51) OuputSize(128), Version(1), FanOut(Parallel ? 8 : 0), and LeafSize(128).<BR></BR>
/// The SkeinParams structure when passed to the constructor, can be used to change the FanOut property (which corresponds to the number of threads used in parallel mode), 
/// which must be an even number less or equal to the number of processing cores.<BR></BR>
/// For best performance in tree hashing mode, the message input block-size (Length parameter of an Update call), should be ParallelBlockSize in length.<BR></BR>
/// The ideal parallel block-size is calculated automatically based on the hardware profile and algorithm requirments.<BR></BR>
/// The parallel mode uses multi-threaded parallel processing, with each thread maintaining a single unique state.<BR></BR>
/// The hash finalizer processes each leaf state as contiguous message input for the root hash; i.e. R = H(S0 || S1 || S2 || ...Sn).<BR></BR> 
/// The FanOut accessor in a SkeinParams structure is the sum number of leaves in the sequential hash chain, the default is 8, which uses eight states/threads.<BR></BR> 
/// Changing any of the SkeinParams values from their defaults, will produce a different hash output.<BR></BR>
/// The SkeinParams structure also contains an optional DistributionCode() property, which is a personalization string applied when generating the initial state (the default is zero).
/// The personalization string can be used to create a unique distribution, in either sequential or parallel operating modes.
/// The DistributionCodeMax() accessor provides the upper limit to the personalization strings byte-length, this size is different for each variant; (256=8, 512=40, 1024=104).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The input message block-size is 128 bytes, (1024 bits).</description></item>
/// <item><description>Digest output size is 128 bytes, (1024 bits).</description></item>
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
class Skein1024 : public IDigest
{
private:

	static const size_t BLOCK_SIZE = 128;
	static const byte DEF_PRLDEGREE = 8;
	static const size_t DIGEST_SIZE = 128;
	static const size_t MAX_PRLBLOCK = 1024 * 1000 * DEF_PRLDEGREE * 100;
	static const size_t MIN_PRLBLOCK = BLOCK_SIZE * DEF_PRLDEGREE;
	static const size_t STATE_SIZE = 16;
	// size of reserved state buffer subtracted from parallel size calculations
	const size_t STATE_PRECACHED = 2048;

	struct Skein1024State
	{
		// state
		std::vector<ulong> S;
		// tweak
		std::vector<ulong> T;
		// config
		std::vector<ulong> V;

		Skein1024State()
			:
			// state
			S(16, 0),
			// tweak
			T(2, 0),
			// config
			V(16, 0)
		{
		}

		void Increase(size_t Length)
		{
			T[0] += Length;
		}

		void Reset()
		{
			if (V.size() > 0)
				memset(&V[0], 0, V.size() * sizeof(ulong));
			if (S.size() > 0)
				memset(&S[0], 0, S.size() * sizeof(ulong));
			if (T.size() > 0)
				memset(&T[0], 0, T.size() * sizeof(ulong));
		}
	};

	SkeinParams m_treeParams;
	std::vector<Skein1024State> m_dgtState;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;

public:

	Skein1024(const Skein1024&) = delete;
	Skein1024& operator=(const Skein1024&) = delete;
	Skein1024& operator=(Skein1024&&) = delete;

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
	virtual Digests Enumeral() { return Digests::Skein1024; }

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input data array passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() { return m_parallelProfile.IsParallel(); }

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name() { return "Skein1024"; }

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	virtual const size_t ParallelBlockSize() { return m_parallelProfile.ParallelBlockSize(); }

	/// <summary>
	/// Get/Set: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a SkeinParams with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() { return m_parallelProfile; }


	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class with either the Parallel or Sequential hashing engine.
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard Skein 512bit hashing instance.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded Skein variant.</param>
	explicit Skein1024(bool Parallel = false);

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
	explicit Skein1024(SkeinParams &Params);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Skein1024();

	//~~~Public Functions~~~//

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

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
	virtual size_t Finalize(std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:

	void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<Skein1024State> &State, size_t StateOffset);
	void Initialize();
	void LoadState(Skein1024State &State, std::vector<ulong> &Config);
	void ProcessBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein1024State> &State, size_t StateOffset, size_t Length = BLOCK_SIZE);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, std::vector<Skein1024State> &State, size_t StateOffset, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
