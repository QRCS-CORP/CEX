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
// Implementation Details:
// An implementation of a block cipher Counter mode Generator
// Written by John G. Underhill, November 21, 2015
// Updated October 23, 2016
// Updated April 18, 2017
// Updated February 14, 2019
// Updated June 14, 2020
// Contact: develop@vtdev.com

#ifndef CEX_BCG_H
#define CEX_BCG_H

#include "DrbgBase.h"
#include "Digests.h"
#include "IKdf.h"
#include "ParallelOptions.h"
#include "SymmetricKey.h"

NAMESPACE_DRBG

using Kdf::IKdf;
using Cipher::SymmetricKey;

/// <summary>
/// An implementation of a Block cipher Counter mode Generator DRBG: BCG
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// BCG rng([Providers::ACP][Parallel]);
/// // initialize
/// rng.Initialize(Key, [Nonce], [Info]);
/// // generate bytes
/// rng.Generate(Output, [Offset], [Length]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Block cipher Counter Generator creates a key-stream by encrypting an incrementing Big Endian ordered 256-bit monotonic counter (nonce). \n
/// The underlying cipher is the wide-block form of the Rijndael cipher (256-bit block), wrapped in a CTR mode. \n
/// The implementation is parallelized by constructing a larger staggered-parallel counter array, and processing large blocks using 128, 256, or 512 bit SIMD instructions. \n
/// The Rijndael key-schedule has been replaced with the more secure Keccak based cSHAKE-256 XOF function.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>C</B>=pseudo-random, <B>K</B>=seed, <B>E</B>=encrypt \n
/// <EM>Generate</EM> \n
/// R0 ← IV. For 1 ≤ j ≤ t, Cj ← EK(Cj), C+1.</para> \n
///
/// <description><B>Initialization and Update:</B></description>
/// <para>The Initialize functions have three different parameter options: the Key which is the primary key, 
/// the Nonce used to initialize the internal counter, and the optional Info array which maps to the cSHAKE customization parameter. \n
/// The Key value must be one of the LegalKeySizes in length, and must be a secret and random value. \n
/// The supported nonce size is the block cipher functions internal block-size, in this function, that is always 256 bits (32 bytes). \n
/// The 32 byte Nonce value should also be a secret value, used to initialize the counter to a non-zero random value. \n
/// The Update function uses the seed value to re-key the cipher via the internal key derivation function cSHAKE-256. \n
/// The update functions Key parameter, must be a random key value which is added to the existing key state, if a random provider has been specified it is mixed with new entropy, 
/// and permuted by a cSHAKE instance to generate the new generator key. \n 
/// When using a random provider, the generator can be automatically re-seeded after a specified number of bytes have been generated, using the ReseedThreshold accessor property. \n 
/// The nonce and distribution code are retained and used after the key re-generation operation, so only the key needs to be used in the Update function.</para>
///
/// <description><B>Predictive Resistance:</B></description>
/// <para>Predictive and backtracking resistance prevent an attacker who has gained knowledge of generator state at some time from predicting future or previous outputs from the generator. \n
/// The optional resistance mechanism uses an entropy provider to add seed material to the generator at  periodic intervals, this new seed material is passed through a cSHAKE generator along with the current state, 
/// and the SHAKE permutations pseudo-random output is used to reseed the generator. \n
/// The interval at which this reseeding occurs is 100MB by default, but can be set using the ReseedThreshold() property; once this number of bytes or greater has been generated, the seed is automatically regenerated. \n 
/// Predictive resistance is strongly recommended when producing large amounts of pseudo-random (100MB or greater).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The class constructor can be initialized using an optional entropy provider type name, the default is none.</description></item>
/// <item><description>The entropy provider specified through the constructor, provides a continues stream of entropy to the reseed function, this is strongly recommended with large (+100MB) outputs.</description></item>
/// <item><description>The generator can be initialized with either a SymmetricKey or SymmetricSecure key container class, this class must provide a legally sized key and nonce.</description></item>
/// <item><description>The LegalKeySizes() property contains a list of supported nonce and key and sizes.</description></item>
/// <item><description>There are three LegalKeySizes, minimum, recommended, and maximum, with BCG, the middle value is the recommended seed length for best security; i.e. LegalKeySizes()[1].</description></item>
/// <item><description>The Generate() methods can not be used until the Initialize() function has been called, and the generator has been keyed and is ready to generate pseudo-random output.</description></item>
/// <item><description>This implementation has been both pipelined (AVX128, AVX256, or AVX512) and optionally multi-threaded.</description></item>
/// <item><description>The security of this block cipher CTR generator is the key length to a maximum of the block size (256-bit security maximum).</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
/// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
/// </list>
/// </remarks>
class BCG final : public DrbgBase
{
private:

	// generators internal block size
	static const size_t BLOCK_SIZE = 32;
	// 100mb: default before reseeded internally
	static const size_t DEF_RESEED = 102400000;
	// generator strength is equal to the block size; 256-bits
	static const size_t GEN_STRENGTH = 256;
	// 10gb: maximum before rekey is required
	static const ulong MAX_OUTPUT = 10240000000;
	// 100mb: maximum size of a single request
	static const size_t MAX_REQUEST = 102400000;
	// 10000: maximum reseed calls before exception
	static const size_t MAX_THRESHOLD = 10000;
	// the minimum key length that will initialize the generator
	static const size_t MINKEY_LENGTH = 16;
	// L2 cache reserved estimate
	static const size_t RESERVE_CACHE = 2048;
	// the bcg default info string
	static const std::vector<byte> BCG_INFO;

	class BcgState;
	std::unique_ptr<IProvider> m_bcgProvider;
	std::unique_ptr<BcgState> m_bcgState;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	BCG(const BCG&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	BCG& operator=(const BCG&) = delete;

	/// <summary>
	/// Instantiate the generator using an optional entropy source type
	/// </summary>
	///
	/// <param name="ProviderType">The random provider-type, used to instantiate the entropy source, the default is none</param>
	/// <param name="Parallel">Enable/disable the multi-threading engine, the default is true</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if an unrecognized block cipher type name is used</exception>
	explicit BCG(Providers ProviderType = Providers::None, bool Parallel = true);

	/// <summary>
	/// Instantiate an instance pointer to an entropy source 
	/// </summary>
	/// 
	/// <param name="Provider">Provides an entropy source enabling predictive resistance, can not be null</param>
	/// <param name="Parallel">Enable/disable the multi-threading engine, the default is false</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if a null provider is used</exception>
	BCG(IProvider* Provider, bool Parallel = false);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~BCG() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The generator is ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, the encrypted state is generated using multiple parallel streams.</para>
	/// </summary>
	const bool IsParallel();

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the requested output data array passed from the Generate function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.
	/// IsParallel must be set to true, and generation requests must be of at least this size to trigger multi-threaded generation.</para>
	/// </summary>
	const size_t ParallelBlockSize();

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; this value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(ISymmetricKey)"/> function is called.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	/// <summary>
	/// Read/Write: The maximum output generated before automatic auto-seed generation when using an entropy provider
	/// </summary>
	size_t &ReseedThreshold() override;

	/// <summary>
	/// Read Only: The estimated classical security strength in bits
	/// </summary>
	const size_t SecurityStrength() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with an ISymmetricKey container, containing the key and nonce, and optional info string.
	/// </summary>
	/// 
	/// <param name="Parameters">The ISymmetricKey key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is not a legal-key size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores (times 2 for hyperthreading).</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Update the generators seed value.
	/// <para>Triggers a reseed with the new seed. 
	/// The seed value must be at least equal in size to the seed used to initialize the generator</para>
	/// </summary>
	/// 
	/// <param name="Key">The standard-vector containing the new key material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the seed is too small</exception>
	void Update(const std::vector<byte> &Key) override;

	/// <summary>
	/// Update the generators keying material with a secure-vector key
	/// </summary>
	///
	/// <param name="Key">The secure-vector containing the new key material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is too small</exception>
	void Update(const SecureVector<byte> &Key) override;

private:

	static void Derive(SecureVector<byte> &Key, std::unique_ptr<IProvider> &Provider);
	void Process(SecureVector<byte> &Output, size_t OutOffset, size_t Length);
	static void PrefetchSbox();
	void Transform(SecureVector<byte> &Output, size_t OutOffset, size_t Length, SecureVector<byte> &Counter);
	void Transform256(const SecureVector<byte> &Input, size_t InOffset, SecureVector<byte> &Output, size_t OutOffset);
	void Transform1024(const SecureVector<byte> &Input, size_t InOffset, SecureVector<byte> &Output, size_t OutOffset);
	void Transform2048(const SecureVector<byte> &Input, size_t InOffset, SecureVector<byte> &Output, size_t OutOffset);
	void Transform4096(const SecureVector<byte> &Input, size_t InOffset, SecureVector<byte> &Output, size_t OutOffset);
};

NAMESPACE_DRBGEND
#endif
