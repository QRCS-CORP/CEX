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
// Updated by January 28, 2019
// Contact: develop@vtdev.com

#ifndef CEX_PBKDF2_H
#define CEX_PBKDF2_H

#include "HMAC.h"
#include "IDigest.h"
#include "IKdf.h"
#include "KdfBase.h"
#include "SHA2Digests.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Mac::HMAC;
using Digest::IDigest;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of the Passphrase Based Key Derivation Version 2: PBKDF2
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // set to 10,000 rounds (default: 4000)
/// PBKDF2 kdf(Enumeration::Digests::SHA256, 10000);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>PBKDF2 uses an HMAC as a pseudo-random function to process a passphrase in a time-complexity loop, producing pseudo-random output in a process known as key stretching. \n
/// By increasing the number of iterations in which the internal hashing function is applied, the amount of time required to derive the key becomes more computationally expensive. \n
/// A salt value can be added to the passphrase, this strongly mitigates rainbow-table based attacks on the passphrase. \n
/// The minimum key size should align with the expected security level of the generator function. \n
/// For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_LEGALKEY definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
/// 
/// <description><B>Description:</B></description> \n
/// <EM>Legend:</EM> \n
/// <B>DK</B>=derived-key, <B>c</B>=iterations, <B>hlen</B>=digest-length, <B>dkLen</B>=output-length \n
/// <para><EM>Generate:</EM> \n
/// The function takes as parameters the passphrase, salt, the iterations count, and the output length.
/// DK = PBKDF2(Password, Salt, c, dkLen). \n
/// DK = T1 || T2 || ... || Td klen/hlen \n
/// The function F is the XOR of (c) iterations of chained PRFs \n
/// The first iteration uses the password as the PRF key and salt concatenated with an incrementing counter (i). \n
/// Ti = F(Password, Salt, c, i) \n
/// Subsequent iterations use the passphrase as the key and the output of the previous computation as the salt. \n
/// U2 = PRF(Password, U1), U3 = PRF(Password, U2) ... Uc = PRF(Password, Uc-1).</para> 
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>This implementation only supports the SHA2-256 and SHA2-512 message digests.</description></item>
/// <item><description>PBKDF2 can be instantiated with a message digest instance, or by using a digests enumeration type name.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize() functions before output can be generated.</description></item>
/// <item><description>The minimum key (passphrase) size is 4 bytes, enforcing passwords of at least 32 characters is recommended.</description></item>
/// <item><description>The maximum number of bytes that can be generated is the underlying digests output-size * 255.</description></item>
/// <item><description>The use of a salt value can strongly mitigate some attack vectors targeting the passphrase, and is highly recommended with PBKDF2.</description></item>
/// <item><description>The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure.</description></item>
/// <item><description>The default iterations count is 10000, larger values are recommended for secure server-side password hashing e.g. +20000.</description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>RFC 2898: <a href="http://tools.ietf.org/html/rfc2898">Specification</a>.</description></item>
/// <item><description>RFC 6070: <a href="https://tools.ietf.org/html/rfc6070">Test Vectors</a>.</description></item>
/// <item><description>NIST SP800-132: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf">Recommendation for Password-Based Key Derivation</a>.</description></item>
/// </list>
/// </remarks>
class PBKDF2 final : public KdfBase
{
private:

	static const size_t DEFAULT_ITERATIONS = 10000;
	static const size_t MAXGEN_REQUESTS = 1024000;
#if defined(CEX_ENFORCE_LEGALKEY)

#else

#endif
	static const size_t MINKEY_LENGTH = 4;
	static const size_t MINSALT_LENGTH = 4;

	class Pbkdf2State;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::unique_ptr<HMAC> m_pbkdf2Generator;
	std::unique_ptr<Pbkdf2State> m_pbkdf2State;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	PBKDF2(const PBKDF2&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	PBKDF2& operator=(const PBKDF2&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	PBKDF2() = delete;

	/// <summary>
	/// Instantiates a PBKDF2 generator using a message digest type name
	/// </summary>
	/// 
	/// <param name="DigestType">The hash functions type name enumeral</param>
	/// <param name="Iterations">The number of compression cycles used to produce output; the default is 10000</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid digest name or iterations count is used</exception>
	PBKDF2(SHA2Digests DigestType, uint Iterations = 10000);

	/// <summary>
	/// Instantiates a PBKDF2 generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// <param name="Iterations">The number of compression cycles used to produce output; the default is 10000</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if a null digest or iterations count is used</exception>
	PBKDF2(IDigest* Digest, uint Iterations = 10000);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~PBKDF2() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// The number of compression cycles used to produce output; must be more than zero, 10,000 recommended
	/// </summary>
	uint &Iterations();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill an array with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
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

	static void Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Pbkdf2State> &State, std::unique_ptr<HMAC> &Generator);
	static void Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Pbkdf2State> &State, std::unique_ptr<HMAC> &Generator);
};

NAMESPACE_KDFEND
#endif
