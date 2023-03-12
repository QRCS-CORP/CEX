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
// Updated by January 28, 2019
// Contact: develop@qscs.ca

#ifndef CEX_HKDF_H
#define CEX_HKDF_H

#include "Digests.h"
#include "HMAC.h"
#include "IDigest.h"
#include "KdfBase.h"
#include "SHA2Digests.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Mac::HMAC;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of the Hash based Key Derivation Function: HKDF
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // use the enumeration constructor
/// HKDF kdf(Enumeration::Digests::SHA2256);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>HKDF uses an HMAC as a mixing function to produce pseudo-random output in a process known as key stretching. \n
/// HKDF has two primary functions; Expand, which expands an input key into a larger key, and Extract, which pre-processes the input key, and optional salt and info parameters into an HMAC key. \n
/// The Extract step is called if the KKDF is initialized with the salt parameter, this compresses the input material to a key used by HMAC. \n
/// For best possible security, the Extract step should be skipped, and HKDF initialized with a key equal in size to the desired security level, and optimally to the HMAC functions internal block-size, 
/// with the Info parameter used as a secondary source of pseudo-random key input. \n
/// If used in this configuration, ideally the Info parameter should be sized to the hash output-size, less one uint8_t of counter and any padding added by the hash functions finalizer. \n
/// Using this formula the HMAC is given the maximum amount of entropy on each expansion cycle without the need to call additional permutation compressions, and the underlying hash function processes only full blocks of input. \n
/// The minimum key size should align with the expected security level of the generator function. \n
/// For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_LEGALKEY definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
/// 
/// <description><B>Description:</B></description> \n
/// <EM>Legend:</EM> \n
/// <B>PRK</B>=pseudorandom key, <B>info</B>=info-string, <B>OKM</B>=output-key, <B>L</B>=output-length \n
/// <para><EM>Extract:</EM> \n
/// PRK = HMAC-Hash(salt, Info)</para>
///
/// <para><EM>Expand:</EM> \n
/// The output OKM is calculated as follows: \n
/// N = ceil(L/HashLen) \n
/// T = T(1) | T(2) | T(3) | ... | T(N) \n
///	OKM = first L octets of T \n
///	where: \n
///	T(0) = empty string (zero length) \n
///	T(1) = HMAC-Hash(PRK, T(0) | info | 0x01) \n
///	T(2) = HMAC-Hash(PRK, T(1) | info | 0x02) \n
///	T(3) = HMAC-Hash(PRK, T(2) | info | 0x03) \n
///	T(N) = HMAC-Hash(PRK, T(N) | info | N) \n
///	... \n
///	The constant concatenated to the end of each T(n) is a single octet counter.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>This implementation only supports the SHA2-256 and SHA2-512 message digests.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>Initializing with a salt parameter will call the HKDF Extract function, this is not recommended.</description></item>
/// <item><description>The Info parameter can be set via a property, and can be used as an additional source of entropy.</description></item>
/// <item><description>The recommended key and salt size is the digests block-size in bytes, the info size should be the HMAC output-size, less 1 uint8_t of counter and any padding added by the digests finalizer.</description></item>
/// <item><description>The minimum recommended key size is the underlying digests output-size in bytes.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Cryptographic Extraction and Key Derivation: <a href="http://eprint.iacr.org/2010/264.pdf">The HKDF Scheme</a></description></item>
/// <item><description><a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description><a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>: HMAC-based Extract-and-Expand Key Derivation Function.</description></item>
/// </list>
/// </remarks>
class HKDF final : public KdfBase
{
private:

	static const size_t MAXGEN_REQUESTS = 255;
	static const size_t MINKEY_LENGTH = 16;
	static const size_t MINSALT_LENGTH = 4;

	class HkdfState;
	std::unique_ptr<HMAC> m_hkdfGenerator;
	std::unique_ptr<HkdfState> m_hkdfState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	HKDF(const HKDF&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	HKDF& operator=(const HKDF&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	HKDF() = delete;

	/// <summary>
	/// Instantiates an HKDF generator using a message digest type name
	/// </summary>
	/// 
	/// <param name="DigestType">The SHA2 hash functions type name enumeral</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid digest type is used</exception>
	explicit HKDF(SHA2Digests DigestType);

	/// <summary>
	/// Instantiates an HKDF generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if a null digest is used</exception>
	explicit HKDF(IDigest* Digest);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~HKDF() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Sets the Info value in the HKDF initialization parameters.
	/// <para>Must be set before Initialize() function is called.</para>
	/// </summary>
	std::vector<uint8_t> &Info();

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// HKDF-Extract function; generate a new key using combined key and salt arrays as input.
	/// </summary>
	/// 
	/// <param name="Key">The key used to initialize the generator</param>
	/// <param name="Salt">The salt value, added to the key</param>
	/// <param name="Output">Receives the newly generated key. 
	/// The array size is the underlying digests output size (32 bytes with SHA2-256, and 64 bytes when using SHA2-512)</param>
	void Extract(const std::vector<uint8_t> &Key, const std::vector<uint8_t> &Salt, std::vector<uint8_t> &Output);

	/// <summary>
	/// HKDF-Extract function; generate a new secure-vector key using combined key and salt arrays as input.
	/// </summary>
	/// 
	/// <param name="Key">The key used to initialize the generator</param>
	/// <param name="Salt">The salt value, added to the key</param>
	/// <param name="Output">Receives the newly generated secure-vector key. 
	/// The array size is the underlying digests output size (32 bytes with SHA2-256, and 64 bytes when using SHA2-512)</param>
	void Extract(const SecureVector<uint8_t> &Key, const SecureVector<uint8_t> &Salt, SecureVector<uint8_t> &Output);

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<uint8_t> &Output) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<uint8_t> &Output) override;

	/// <summary>
	/// Fill an array with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length) override;

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

	static void Expand(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator);
	static void Expand(SecureVector<uint8_t> &Output, size_t OutOffset, size_t Length, std::unique_ptr<HkdfState> &State, std::unique_ptr<HMAC> &Generator);
};

NAMESPACE_KDFEND
#endif

