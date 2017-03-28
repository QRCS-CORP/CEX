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
// Implementation Details:
// An implementation of the Key Derivation Function Version 2 (KDF2).
// Written by John Underhill, September 24, 2014
// Updated September 28, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_KDF2_H
#define _CEX_KDF2_H

#include "IKdf.h"
#include "IDigest.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;

/// <summary>
/// An implementation of the Key Derivation Function Version 2 (KDF2)
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
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
/// <para>KDF2 uses a hash digest as a pseudo random function to produce pseudo-random output in a process known as key stretching. \n
/// Using the same input key, and optional salt and information strings, produces the exact same output. \n
/// It is recommended that a salt value is added along with the key, this mitigates some attacks against the function.</para>
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
/// <item><description>Class can be initialized with a message digest instance, or by using a digests enumeration type name.</description></item>
/// <item><description>The minimum key size is the size the digests return array in bytes, a key equal to the digests block size is recommended.</description></item>
/// <item><description>The use of a salt value can strongly mitigate some attack vectors targeting the key, and is highly recommended with KDF2.</description></item>
/// <item><description>The minimum salt size is 4 bytes, larger (pseudo-random) salt values are more secure.</description></item>
/// <item><description>The generator must be initialized with a key using one of the Initialize() functions before output can be generated.</description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>ISO18033-2: <a href="http://www.shoup.net/iso/std6.pdf">Chapter 6.2.3 KDF2</a>.</description></item>
/// <item><description>RFC 6070: <a href="https://tools.ietf.org/html/rfc6070">Test Vectors</a>.</description></item>
/// <item><description>NIST SP80056A: Recommendation for Pair-Wise Key Establishment Schemes: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">Chapter 5.8</a>.</description></item>
/// </list>
/// </remarks>
class KDF2 : public IKdf
{
private:

	const size_t MIN_SALTLEN = 4;

	IDigest* m_msgDigest;
	size_t m_blockSize;
	bool m_destroyEngine;
	size_t m_hashSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	uint m_kdfCounter;
	Digests m_kdfDigestType;
	std::vector<byte> m_kdfKey;
	std::vector<byte> m_kdfSalt;
	std::vector<SymmetricKeySize> m_legalKeySizes;

public:

	KDF2() = delete;
	KDF2(const KDF2&) = delete;
	KDF2& operator=(const KDF2&) = delete;
	KDF2& operator=(KDF2&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Kdf generators type name
	/// </summary>
	virtual const Kdfs Enumeral() { return Kdfs::KDF2; }

	/// <summary>
	/// Get: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Minimum recommended initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info should be at least this size.</para>
	/// </summary>
	virtual size_t MinKeySize() { return m_blockSize; }

	/// <summary>
	/// Get: Available Kdf Key Sizes in bytes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_legalKeySizes; };

	/// <summary>
	/// Get: The Kdf generators class name
	/// </summary>
	virtual const std::string Name() { return "KDF2"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiates a KDF2 generator using a message digest type name
	/// </summary>
	/// 
	/// <param name="DigestType">The hash functions type-name enumeral</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if an invalid digest name or iterations count is used</exception>
	explicit KDF2(Digests DigestType);

	/// <summary>
	/// Instantiates a KDF2 generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if a null digest is used</exception>
	explicit KDF2(Digest::IDigest* Digest);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~KDF2();

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
	/// <para>The use of a salt value mitigates some attacks against a passphrase, and is highly recommended with KDF2.</para>
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	virtual void Initialize(ISymmetricKey &GenParam);

	/// <summary>
	/// Initialize the generator with a key.
	/// <para>The use of a salt value mitigates some attacks against a passphrase, and is highly recommended with KDF2.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	virtual void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the generator with key and salt arrays
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value containing an additional source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt);

	/// <summary>
	/// Initialize the generator with a key, a salt array, and an information string or nonce
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
	void LoadState();
};

NAMESPACE_KDFEND
#endif
