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
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of an Hash based Key Derivation Function (HKDF). 
// Written by John Underhill, September 19, 2014
// Updated September 30, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_HKDF_H
#define _CEX_HKDF_H

#include "IKdf.h"
#include "Digests.h"
#include "IDigest.h"
#include "HMAC.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Mac::HMAC;

/// <summary>
/// An implementation of an Hash based Key Derivation Function (HKDF)
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// // use the enumeration constructor
/// HKDF kdf(Enumeration::Digests::SHA256);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>HKDF uses an HMAC as a pseudo random function to produce pseudo-random output in a process known as key stretching.<BR></BR>
/// HKDF has two primary functions; Expand, which expands an input key into a larger key, and Extract, which pre-compresses key and optional salt and info parameters into a pseudo random key.<BR></BR>
/// The Extract step is called if the the KDF is initialized with the salt or info parameters, this compresses the input material to a key used by the HMAC.<BR></BR>
/// The Info parameter may also be set via the Info() property, this can be used to bypass the extract step, while adding additional input to the HMAC compression cycle.<BR></BR>
/// For best possible security, the Extract step should be skipped, the KDF is initialized with a key equal in size to the hash functions internal block-size, 
/// and the Info parameter is used as a secondary source of pseudo-random key input.<BR></BR>
/// If used in this configuration, the Info parameter should be sized to the hash block-size, less one byte of counter, and any padding added by the hash functions finalizer.<BR></BR>
/// Using this formula the HMAC is given the maximum amount of entropy on each expansion cycle, and the underlying hash function processes only full blocks of input.</para>
/// 
/// <description><B>Description:</B></description><BR></BR>
/// <EM>Legend:</EM><BR></BR>
/// <B>PRK</B>=pseudorandom key, <B>info</B>=info-string, <B>OKM</B>=output-key, <B>L</B>=output-length<BR></BR>
/// <para><EM>Extract:</EM><BR></BR>
/// PRK = HMAC-Hash(salt, Info)</para>
///
/// <para><EM>Expand:</EM><BR></BR>
/// The output OKM is calculated as follows:<BR></BR>
/// N = ceil(L/HashLen)<BR></BR>
/// T = T(1) | T(2) | T(3) | ... | T(N)<BR></BR>
///	OKM = first L octets of T<BR></BR>
///	where:<BR></BR>
///	T(0) = empty string (zero length)<BR></BR>
///	T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)<BR></BR>
///	T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)<BR></BR>
///	T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)<BR></BR>
///	T(N) = HMAC-Hash(PRK, T(N) | info | N)<BR></BR>
///	...<BR></BR>
///	The constant concatenated to the end of each T(n) is a single octet counter.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>This class can be instantiated with a message digest or HMAC instance, or by using a digests enumeration type name.</description></item>
/// <item><description>The generator must be initialized with a key using one of the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize() function can use a SymmetricKey key container class, or input arrays of Key, and optional Salt and Info.</description></item>
/// <item><description>Initializing with a salt or info parameters will call the HKDF Extract function.</description></item>
/// <item><description>The Info parameter can be set via a property, bypassing the Extract step, and can be used as an additional source of entropy.</description></item>
/// <item><description>The recommended key and salt size is the digests block-size in bytes, the info size should be the block-size, less 1 byte of counter, and any padding added by the digests finalizer.</description></item>
/// <item><description>The minimum recommended key size is the digests output array size in bytes.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Cryptographic Extraction and Key Derivation: <a href="http://eprint.iacr.org/2010/264.pdf">The HKDF Scheme</a></description></item>
/// <item><description><a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description><a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>: HMAC-based Extract-and-Expand Key Derivation Function.</description></item>
/// </list>
/// </remarks>
class HKDF : public IKdf
{
private:

	const size_t MIN_KEYLEN = 16;
	const size_t MIN_SALTLEN = 4;

	HMAC* m_macGenerator;
	size_t m_blockSize;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	byte m_kdfCounter;
	Digests m_kdfDigestType;
	std::vector<byte> m_kdfInfo;
	std::vector<byte> m_kdfState;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_macSize;

public:

	HKDF() = delete;
	HKDF(const HKDF&) = delete;
	HKDF& operator=(const HKDF&) = delete;
	HKDF& operator=(HKDF&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Kdf generators type name
	/// </summary>
	virtual const Kdfs Enumeral() { return Kdfs::HKDF; }

	/// <summary>
	/// Get/Set: Sets the Info value in the HKDF initialization parameters.
	/// <para>Must be set before Initialize() function is called.
	/// Code should be either a zero byte array, or a multiple of the HKDF digest engines return size.</para>
	/// </summary>
	std::vector<byte> &Info() { return m_kdfInfo; }

	/// <summary>
	/// Get: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Available Kdf Key Sizes in bytes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_legalKeySizes; };

	/// <summary>
	/// Minimum recommended initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info should be at least this size.</para>
	/// </summary>
	virtual size_t MinKeySize() { return m_macSize; }

	/// <summary>
	/// Get: The Kdf generators class name
	/// </summary>
	virtual const std::string Name() { return "HKDF"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiates an HKDF generator using a message digest type name
	/// </summary>
	/// 
	/// <param name="DigestType">The hash functions type name enumeral</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if an invalid digest name is used</exception>
	explicit HKDF(Digests DigestType);

	/// <summary>
	/// Instantiates an HKDF generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if a null digest is used</exception>
	explicit HKDF(IDigest* Digest);

	/// <summary>
	/// Instantiates an HKDF generator using an HMAC instance
	/// </summary>
	/// 
	/// <param name="Mac">The initialized HMAC instance</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if a null HMAC is used</exception>
	explicit HKDF(HMAC* Mac);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~HKDF();

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output);

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length);

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional salt, and info string.
	/// <para>The use of a salt or info parameters will call the HKDF Extract function.</para>
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	virtual void Initialize(ISymmetricKey &GenParam);

	/// <summary>
	/// Initialize the generator with a key.
	/// <para>This method initiatialzes HKDF without the Extract step.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	virtual void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the generator with key and salt arrays.
	/// <para>The use of a salt will call the HKDF Extract function.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value containing an additional source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt);

	/// <summary>
	/// Initialize the generator with a key, a salt array, and an information string or nonce.
	/// <para>The use of a salt or info parameters will call the HKDF Extract function.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value used as an additional source of entropy</param>
	/// <param name="Info">The information string or nonce used as a third source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info);

	/// <summary>
	/// Update the generators keying material
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is too small</exception>
	virtual void ReSeed(const std::vector<byte> &Seed);

	/// <summary>
	/// Reset the internal state; Kdf must be re-initialized before it can be used again
	/// </summary>
	virtual void Reset();

private:
	size_t Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output);
	void LoadState();
};

NAMESPACE_KDFEND
#endif

