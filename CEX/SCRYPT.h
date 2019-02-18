// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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
// Updated by January 28, 2019
// Contact: develop@vtdev.com

#ifndef CEX_SCRYPT_H
#define CEX_SCRYPT_H

#include "Digests.h"
#include "IDigest.h"
#include "KdfBase.h"
#include "ParallelOptions.h"
#include "SHA2Digests.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of the Key Derivation Function: SCRYPT
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // set to 10,000 rounds (default: 4000)
/// SCRYPT kdf(Enumeration::Digests::SHA256, 16384, 8, 1);
/// // initialize
/// kdf.Initialize(Key, [Salt]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>SCRYPT is a password-based key derivation function created by Colin Percival, originally for the Tarsnap online backup service. \n
/// SCRYPT uses a combination of an underlying message digest and the Salsa stream cipher permutation function to make it costly to perform large-scale hardware attacks by requiring large amounts of memory
/// to generate an output key. \n
/// Using the same input key, and optional salt, will produce the exact same output. \n
/// It is recommended that a salt value is added along with the key, this strongly mitigates rainbow-table based attacks on the passphrase. \n
/// The minimum key size should align with the expected security level of the generator function. \n
/// For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_LEGALKEY definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
/// 
/// <description><B>Description:</B></description> \n
/// <EM>Legend:</EM> \n
/// <B>P</B>=passphrase, <B>S</B>=salt, <B>N</B>=cpu/memory cost, <B>r</B>=block-size, <B>P</B>=parallelization parameter, <B>DK</B>=derived key \n
/// <para><EM>Generate:</EM> \n
/// 1) Initialize an array B consisting of p blocks of 128 * r octets each: \n
///		B[0] || B[1] || ... || B[p - 1] = PBKDF2 - HMAC - SHA256(P, S, 1, p * 128 * r) \n
/// 2) for i = 0 to p - 1 do: B[i] = scryptROMix(r, B[i], N) \n
/// 3) DK = PBKDF2 - HMAC - SHA256(P, B[0] || B[1] || ... || B[p - 1], 1, dkLen)</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>This implementation only supports the SHA2-256 and SHA2-512 message digests.</description></item>
/// <item><description>SCRYPT can be initialized with a message digest instance, or by using a digests enumeration type name.</description></item>
/// <item><description>The minimum recommended key size is the size the underlying digests output-size in bytes.</description></item>
/// <item><description>The use of a salt value can strongly mitigate some attack vectors targeting the key, and is highly recommended with SCRYPT.</description></item>
/// <item><description>The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>SCRYPT: <a href="https://www.tarsnap.com/scrypt/scrypt.pdf">Stronger Key Derivation</a> via Sequential Memory Hard Functions.</description></item>
/// <item><description>RFC 7914: <a href="https://tools.ietf.org/html/rfc7914">The scrypt Password-Based Key Derivation Function</a>.</description></item>
/// <item><description>Scrypt is <a href="http://eprint.iacr.org/2016/989.pdf">Maximally Memory-Hard</a>.</description></item>
/// </list>
/// </remarks>
class SCRYPT final : public KdfBase
{
private:

	static const size_t MAXGEN_REQUESTS = 1024000;
	static const size_t MEMORY_COST = 8;
#if defined(CEX_ENFORCE_LEGALKEY)

#else

#endif
	static const size_t MINKEY_LENGTH = 6;
	static const size_t MINSALT_LENGTH = 4;

	class ScryptState;
	bool m_isDestroyed;
	bool m_isInitialized;
	ParallelOptions m_parallelProfile;
	std::unique_ptr<IDigest> m_scryptGenerator;
	std::unique_ptr<ScryptState> m_scryptState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SCRYPT(const SCRYPT&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SCRYPT& operator=(const SCRYPT&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SCRYPT() = delete;

	/// <summary>
	/// Instantiates an SCRYPT generator using a message digest type-name
	/// </summary>
	/// 
	/// <param name="DigestType">The hash functions type-name enumeral</param>
	/// <param name="CpuCost">The CPU cost parameter; increasing this value affects the cpu and memory cost.
	/// <para>This value must be evenly divisible by 1024, with the minimum legal size of 1024. 
	/// The minimum recommended size is 16384.</para></param>
	/// <param name="Parallelization">The Parallelization parameter; indicates the number of threads used by the generator. 
	/// <para>Change this value to multiply the cpu cost by this factor, the default value is 1.
	/// Setting this value to 0 will automatically use the number of system processor cores.</para></param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid digest name or parameters are used</exception>
	explicit SCRYPT(SHA2Digests DigestType, size_t CpuCost = 16384, size_t Parallelization = 1);

	/// <summary>
	/// Instantiates an SCRYPT generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// <param name="CpuCost">The CPU cost parameter; increasing this value affects the cpu and memory cost.
	/// <para>This value must be evenly divisible by 1024, with the minimum legal size of 1024. 
	/// The minimum recommended size is 16384.</para></param>
	/// <param name="Parallelization">The Parallelization parameter; indicates the number of threads used by the generator.  
	/// <para>Change this value to multiply the cpu cost by this factor, the default value is 1.
	/// Setting this value to 0 will automatically use the number of system processor cores.</para></param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if a null digest or invalid parameters are used</exception>
	explicit SCRYPT(IDigest* Digest, size_t CpuCost = 16384, size_t Parallelization = 1);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SCRYPT() override;

	//~~~Accessors~~~//

	/// <summary>
	/// The CPU cost parameter; increasing this value affects the cpu and memory cost.
	/// <para>This value must be evenly divisible by 1024, with the minimum legal size of 1024. 
	/// The minimum recommended size is 16384.</para>
	/// </summary>
	size_t &CpuCost();

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this protocol.
	/// Multi-threading and SIMD parallelization can be modified through the ParallelProfile() accessor.</para>
	/// </summary>
	const bool IsParallel();

	/// <summary>
	/// The Parallelization parameter; indicates the number of threads used by the generator. 
	/// <para>Change this value to multiply the cpu cost by this factor, the default value is 1.
	/// Setting this value to 0 will automatically use the number of system processor cores.</para>
	/// </summary>
	size_t &Parallelization();

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill an array with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a secure vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string
	/// </summary>
	/// 
	/// <param name="Parameters">The symmetric key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key values are not a legal size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Reset the internal state; the generator must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	static void Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScryptState> &State, ParallelOptions &Options, std::unique_ptr<IDigest> &Generator);
	static void Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScryptState> &State, ParallelOptions &Options, std::unique_ptr<IDigest> &Generator);
	static void Extract(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Key, std::vector<byte> &Salt, std::unique_ptr<IDigest> &Generator);
	static void MixBlock(std::vector<uint> &X, std::vector<uint> &Y);
	static void MixState(std::vector<uint> &State, size_t StateOffset, size_t N);
};

NAMESPACE_KDFEND
#endif
