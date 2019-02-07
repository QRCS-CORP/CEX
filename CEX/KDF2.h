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

#ifndef CEX_KDF2_H
#define CEX_KDF2_H

#include "IDigest.h"
#include "IKdf.h"
#include "KdfBase.h"
#include "SHA2Digests.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of the Key Derivation Function Version 2: KDF2
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // set to 10,000 rounds (default: 4000)
/// KDF2 kdf(Enumeration::Digests::SHA256);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>KDF2 uses a hash digest as a pseudo-random function to produce pseudo-random output in a process known as key stretching. \n
/// Using the same input key, and optional salt and information strings, will produce the exact same output. \n
/// It is recommended that a pseudo-random salt value is added along with the key, this mitigates some attacks against the function. \n
/// The minimum key size should align with the expected security level of the generator function. \n
/// For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_KEYMIN definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
/// 
/// <description><B>Description:</B></description> \n
/// <EM>Legend:</EM> \n
/// <B>Z</B>=key, <B>T</B>=output-key, <B>hlen</B>=digest-length, <B>kLen</B>=output-length \n
/// <para><EM>Generate:</EM> \n
/// 1) Set d = ceiling(kLen/hLen). \n
/// 2) Set T = "". \n
/// 3) for Counter = 1 to d-1 do: \n
///		 C = IntegerToString(Counter, 4). \n
///		 T = T || Hash(Z || C || [OtherInfo]). \n
/// 4) Output the first kLen bytes of T as K.</para> 
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>This implementation only supports the SHA2-256 and SHA2-512 message digests.</description></item>
/// <item><description>KDF2 can be instantiated with a message digest instance, or by using the SHA2 digests enumeration type name.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize() function before output can be generated.</description></item>
/// <item><description>The minimum key (passphrase) size is 4 bytes, enforcing passwords of at least 32 characters is recommended.</description></item>
/// <item><description>The maximum number of bytes that can be generated is the underlying digests output-size * 255.</description></item>
/// <item><description>The use of a salt value can strongly mitigate some attack vectors targeting the passphrase, and is highly recommended with KDF2.</description></item>
/// <item><description>The minimum salt size is 4 bytes, however larger pseudo-random salt values are more secure.</description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>ISO18033-2: <a href="http://www.shoup.net/iso/std6.pdf">Chapter 6.2.3 KDF2</a>.</description></item>
/// <item><description>RFC 6070: <a href="https://tools.ietf.org/html/rfc6070">Test Vectors</a>.</description></item>
/// <item><description>NIST SP80056A: Recommendation for Pair-Wise Key Establishment Schemes: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">Chapter 5.8</a>.</description></item>
/// </list>
/// </remarks>
class KDF2 final : public KdfBase
{
private:

	static const size_t MAXGEN_REQUESTS = 255;
	static const size_t MINKEY_LENGTH = 16;
	static const size_t MINSALT_LENGTH = 4;

	class Kdf2State;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::unique_ptr<IDigest> m_kdf2Generator;
	std::unique_ptr<Kdf2State> m_kdf2State;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	KDF2(const KDF2&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	KDF2& operator=(const KDF2&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	KDF2() = delete;

	/// <summary>
	/// Instantiates a KDF2 generator using a message digest type name
	/// </summary>
	/// 
	/// <param name="DigestType">The hash functions type-name enumeral</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid digest type is used</exception>
	explicit KDF2(SHA2Digests DigestType);

	/// <summary>
	/// Instantiates a KDF2 generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if a null digest is used</exception>
	explicit KDF2(IDigest* Digest);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~KDF2() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

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
	/// <param name="KeyParams">The symmetric key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key values are not a legal size</exception>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Reset the internal state; the generator must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	static void Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Kdf2State> &State, std::unique_ptr<IDigest> &Generator);
	static void Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<Kdf2State> &State, std::unique_ptr<IDigest> &Generator);
};

NAMESPACE_KDFEND
#endif
