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
// Implementation Details:
// An implementation of an HMAC Counter Generator (HCG)
// Written by John Underhill, November 2, 2016
// Updated April 18, 2017
// Contact: develop@vtdev.com

#ifndef CEX_HCG_H
#define CEX_HCG_H

#include "IDrbg.h"
#include "IDigest.h"
#include "IProvider.h"
#include "HMAC.h"

NAMESPACE_DRBG

using Enumeration::Digests;
using Digest::IDigest;
using Provider::IProvider;
using Enumeration::Providers;

/// <summary>
/// An implementation of an HMAC Counter Generator DRBG
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// HCG rnd(Digests::SHA512, [Providers::CSP]);
/// // initialize
/// rnd.Initialize(Seed, [Nonce], [Info]);
/// // generate bytes
/// rnd.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>Hm</B>=hmac_function, <B>P</B>=entropy_provider, <B>R</B>=generator_state, <B>K</B>=input_key, <B>Dk</B>=derived_key, <B>Dc</B>=distribution_code, <B>Sc</B>=state_counter, <B>Kc</B>=seed_counter, <B>Df</B>=derivation_function</para>
/// <para>
/// <description><B>Derive:</B></description>
///  \n
/// Hm(K). the HMAC is first pre-initialized with the input key in the Initialize function. \n
/// LeIncrement the seed counter by the bytes required for the iteration, and mac the state counter, the input key, and a length of pseudo-random bytes from the provider. \n
/// 1) For 1 ≤ j ≤ t, Kc = (Kc + kLen), Dk = Dk || Hm(Kc || K || P). \n
/// 2) Hm(Dk). -re-initialize the HMAC with the derived key. \n
/// 3) R = P(statelen). -generate the initial state using the entropy provider.
/// </para>
///
/// <para><EM>Initialize</EM> \n
/// The Initialize function can take up to 3 inputs; the generator Seed which is the primary key, a Nonce value of 8 bytes used to initialize the state counter,
/// and the distribution code used in the Generate function. \n
///  \n
/// 1) Hm(K). -pre-key the HMAC. \n
/// 2) if (Nonce) Sc = Nonce. -set the state counter to a non-zero secret value (optional, but recommended). \n
/// 3) if (Info) Dc = Info. -set the distribution code (optional, but recommended). \n
/// 4) Dk = Df(Sc || K || P) -extract the primary seed. \n
/// 5) Hm(Dk). -re-initialize the HMAC with the derived key. \n
/// </para>
///
/// <para><EM>Generate</EM> \n
/// LeIncrement the state counter by the bytes requested in each iteration and generate the state bytes to the generator ouput \n
///	1) For 1 ≤ j ≤ t, Sc = (Sc + kLen), output = output || Hm(Sc || R || Dc). \n
/// Loop until requested output size has been generated and written to the output array. \n
/// If the reseed threshold has been exceeded, re-key the HMAC. \n
/// 2) if (Sc > reseed_threshold)  \n
///		K = Hm(Sc || R || Dc). -generate (internal) state for derivation key. \n
///		Dk = Df(K). -extract and re-key the HMAC, and generate a new initial state with the provider.
/// </para>
///
/// <description><B>Overview:</B></description>
/// <para>The HMAC based generator uses a hash function in a keyed HMAC to generate pseudo-random output. \n
/// The HMAC is first initialized with the input seed values, then used in an internal key strengthening/derivation function to extract a key equal to the underlying hash functions internal block size,
/// this is the most secure configuration when using a random HMAC key. \n
/// The key derivation function takes as input a seed counter, (which is incremented by the number of bytes generated in each expansion cycle), the initial seed key, 
/// and uses an entropy provider to pad the input blocks to the HMAC, so that the hash function processes a full block of state in the hash finalizer function. \n
/// In a Merkle–Damgård construction (SHA2), the finalizer appends a code to the end of the last block, (and if the block is full, it processes a block of zero-byte padding with the code), 
/// this is compensated for by subtracting the codes length from the random padding request length when required. \n
/// The generator function uses the re-keyed HMAC to process a state counter, (optionally initialized as a random value array, and incremented on each cycle iteration by the required number of bytes copied from a block), 
/// an initial random state array generated by the random provider, and the optional DistributionCode array, (set either through the property or the Info parameter of the Initialize function). \n
/// The DistributionCode can be applied as a secondary, static source of entropy used by the generate function, making it similar to an HKDF construction, (HCG uses an 8 byte counter instead of 1 byte used by HKDF). 
/// The DistributionCodeMax property is the ideal size for the code, (it also compensates for any hash finalizer code length), this ensures only full blocks are processed by the hash function finalizer. \n
/// The generator copies the HMAC finalized output to the internal state, and the functions output array. 
/// The pseudo-random state array is processed as seed material in the next iteration of the generation cycle, in a continuous transformation process. \n
/// The state counter can be initialized by the Nonce parameter of the Initialize function to an 8 byte secret and random value, (this is strongly recommended). \n
/// The reseed-requests counter is incremented by the number of bytes processed by a generation call, if this value exceeds the ReseedThreshold value (10 * the MAC output size by default),
/// the generator transforms the state to an internal array, (not added to output), and uses that state, along with the reseed counter and entropy provider, to buid a new HMAC key. \n
/// The HMAC is then re-keyed, the reseed-requests counter is reset, and a new initial state is generated by the entropy provider for the next generation cycle.
/// </para>
/// 
/// <description><B>Initialization and Update:</B></description>
/// <para>The Initialize functions have three different parameter options: the Seed which is the primary key, 
/// the Nonce used to initialize the internal state-counter, and the Info which is used in the Generate function. \n
/// The Seed value must be one of the LegalKeySizes() in length, and must be a secret and random value. \n
/// The supported seed-sizes are calculated based on the hash functions internal block size, and can vary depending on which message digest is used to instantiate the generator. \n
/// The eight byte (NonceSize) Nonce value is another secret value, used to initialize the internal state counter to a non-zero random value. \n
/// The Info parameter maps to the DistributionCode() property, and is used as message state when generating the pseudo-random output. \n
/// The DistributionCode is recommended, and for best security, should be secret, random, and equal in length to the DistributionCodeMax() property \n 
/// The Update function uses the seed value to re-key the HMAC via the internal key derivation function. \n
/// The update functions Seed parameter, must be a random seed value equal in length to the seed used to initialize the generator.</para>
///
/// <description><B>Predictive Resistance:</B></description>
/// <para>Predictive and backtracking resistance prevent an attacker who has gained knowledge of generator state at some time from predicting future or previous outputs from the generator. \n
/// The optional resistance mechanism uses an entropy provider to add seed material to the generator, this new seed material is passed through the derivation function along with the current state, 
/// the output hash is used to reseed the generator. \n
/// The default interval at which this reseeding occurs is 1000 times the digest output size in bytes, but can be set using the ReseedThreshold() property; once this number of bytes or greater has been generated, 
/// the seed is regenerated. \n 
/// Predictive resistance is strongly recommended when producing large amounts of pseudo-random (10kb or greater).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The class constructor can either be initialized with message digest and entropy provider instances, or using the Digests and Providers enumeration names.</description></item>
/// <item><description>Digest and provider instances created using the enumeration constructor, are automatically deleted when the class is destroyed.</description></item>
/// <item><description>The generator can be initialized with either a SymmetricKey key container class, or with a Seed and optional inputs of Nonce and Info.</description></item>
/// <item><description>The LegalKeySizes() property contains a list of the supported seed input sizes.</description></item>
/// <item><description>There are three legal seed sizes; the first (smallest) is the minimum required key size, the second the recommended size, and the third is maximum security.</description></item>
/// <item><description>Initializing with a Nonce is recommended; the nonce value must be random, secret, and 8 bytes in length.</description></item>
/// <item><description>The Info value (DistributionCode) is also recommended; for best security, this value should be secret, random, and DistributionCodeMax() in length.</description></item>
/// <item><description>The Generate() methods can not be used until an Initialize() function has been called, and the generator is seeded.</description></item>
/// <item><description>The Update() method requires a Seed of length equal to the seed used to initialize the generator.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">SP800-90A R1</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">SP800-90A</a></description>.</item>
/// <item><description>BouncyCastle <a href="https://github.com/bcgit/bc-java/blob/ae63147936376e85e068c7b63373d4e930c3fe58/core/src/main/java/org/bouncycastle/crypto/prng/DigestRandomGenerator.java">DigestRandomGenerator.java</a>: Section 10.1</description>.</item>
/// <item><description>Security Analysis for <a href="https://tel.archives-ouvertes.fr/tel-01236602/document">Pseudo-Random Numbers Generators</a></description>.</item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
/// </list>
/// </remarks>
class HCG : public IDrbg
{
private:

	static const std::string CLASS_NAME;
	// max-out: 35184372088832, max-request: 65536, max-reseed: 536870912; per sp800aR1, sec. 10.1, table 2
	static const ulong MAX_OUTPUT = 35184372088832;
	static const size_t MAX_REQUEST = 65536;
	static const size_t MAX_RESEED = 536870912;
	static const size_t MINSEED_SIZE = 8;
	static const size_t SEEDCTR_SIZE = 4;
	static const size_t STATECTR_SIZE = 8;

	Mac::HMAC m_hmacEngine;
	bool m_destroyEngine;
	Digests m_digestType;
	std::vector<byte> m_distributionCode;
	size_t m_distributionCodeMax;
	std::vector<byte> m_hmacKey;
	std::vector<byte> m_hmacState;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	IProvider* m_providerSource;
	Providers m_providerType;
	size_t m_reseedCounter;
	size_t m_reseedRequests;
	size_t m_reseedThreshold;
	size_t m_secStrength;
	std::vector<byte> m_seedCtr;
	std::vector<byte> m_stateCtr;

public:

	HCG(const HCG&) = delete;
	HCG& operator=(const HCG&) = delete;
	HCG& operator=(HCG&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get/Set: Reads or Sets the personalization string value in the KDF initialization parameters.
	/// <para>Must be set before <see cref="Initialize(ISymmetricKey)"/> is called.
	/// Changing this code will create a unique distribution of the generator.
	/// Code can be sized as either a zero byte array, or any length up to the DistributionCodeMax size.
	/// For best security, the distribution code should be random, secret, and equal in length to the DistributionCodeMax() size.</para>
	/// </summary>
	std::vector<byte> &DistributionCode() override;

	/// <summary>
	/// Get: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary source of entropy (secret) in the KDF key expansion phase.
	/// For best security, the distribution code should be random, secret, and equal in size to this value.</para>
	/// </summary>
	const size_t DistributionCodeMax() override;

	/// <summary>
	/// Get: The Drbg generators type name
	/// </summary>
	const Drbgs Enumeral() override;

	/// <summary>
	/// Get: Generator is ready to produce random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Get: The legal input seed sizes in bytes
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Get: The maximum number of bytes that can be generated with a generator instance
	/// </summary>
	const ulong MaxOutputSize() override;

	/// <summary>
	/// Get: The maximum number of bytes that can be generated in a single request
	/// </summary>
	const size_t MaxRequestSize() override;

	/// <summary>
	/// Get: The maximum number of times the generator can be reseeded
	/// </summary>
	const size_t MaxReseedCount() override;

	/// <summary>
	/// Get: The Drbg generators class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Get: The size of the nonce counter value in bytes
	/// </summary>
	const size_t NonceSize() override;

	/// <summary>
	/// Get/Set: Generating this amount or greater, triggers a re-seed
	/// </summary>
	size_t &ReseedThreshold() override;

	/// <summary>
	/// Get: The estimated security strength in bits.
	/// <para>This value depends both on the hash function output size, and the number of bits used to seed the generator.</para>
	/// </summary>
	const size_t SecurityStrength() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate the class using a block cipher type name, and an optional entropy source type
	/// </summary>
	///
	/// <param name="DigestType">The hash digests enumeration type name; the default is SHA512</param>
	/// <param name="ProviderType">The enumeration type name of an entropy source; enables predictive resistance</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an unrecognized digest type name is used</exception>
	explicit HCG(Digests DigestType = Digests::SHA512, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Instantiate the class using a digest instance, and an optional entropy source 
	/// </summary>
	/// 
	/// <param name="Digest">The hash digest instance</param>
	/// <param name="Provider">Provides an entropy source; enables predictive resistance, can be null</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if a null digest is used</exception>
	explicit HCG(IDigest* Digest, IProvider* Provider = 0);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~HCG() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	size_t Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional nonce, and info string
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(ISymmetricKey &GenParam) override;

	/// <summary>
	/// Initialize the generator with a seed key
	/// </summary>
	/// 
	/// <param name="Seed">The secret primary key array used to seed the generator; see the LegalKeySizes property for accepted sizes</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Seed) override;

	/// <summary>
	/// Initialize the generator with the seed and nonce arrays
	/// </summary>
	/// 
	/// <param name="Seed">The secret primary key array used to seed the generator; see the LegalKeySizes property for accepted sizes</param>
	/// <param name="Nonce">The secret nonce value used to initialize the state counter; value must be NonceSize() bytes in length</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce) override;

	/// <summary>
	/// Initialize the generator with a key, a nonce array, and an information string or nonce
	/// </summary>
	/// 
	/// <param name="Seed">The secret primary key array used to seed the generator; see the LegalKeySizes property for accepted sizes</param>
	/// <param name="Nonce">The secret nonce value used to initialize the state counter; value must be NonceSize() bytes in length</param>
	/// <param name="Info">The info parameter can be used as a secret salt, or as a distribution code; for best security it should be secret, random, and DistributionCodeMax in length</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info) override;

	/// <summary>
	/// Update the generators keying material, used to refresh the state
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	void Update(const std::vector<byte> &Seed) override;

private:

	void Derive(const std::vector<byte> &Seed);
	void GenerateBlock(std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Increase(std::vector<byte> &Counter, const uint Length);
	void RandomPad(size_t BlockOffset);
	void Scope();
};

NAMESPACE_DRBGEND
#endif
