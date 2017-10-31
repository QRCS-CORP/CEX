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
// An implementation of Passphrase Based Key Derivation Function 2 (PBKDF2).
// Written by John Underhill, September 24, 2014
// Updated September 22, 2016
// Updated April 19, 2017
// Contact: develop@vtdev.com

#ifndef CEX_PBKDF2_H
#define CEX_PBKDF2_H

#include "IKdf.h"
#include "Digests.h"
#include "IDigest.h"
#include "HMAC.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Mac::HMAC;

/// <summary>
/// An implementation of the Passphrase Based Key Derivation Version 2 (PBKDF2)
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
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
/// <para>PBKDF2 uses an HMAC as a pseudo random function to process a passphrase repeatedly, producing pseudo-random output in a process known as key stretching. \n
/// By increasing the number of iterations in which the function is applied, the amount of time required to derive the key becomes more computationally expensive. \n
/// A salt value can be added to the passphrase, this strongly mitigates rainbow-table based attacks on the passphrase.</para>
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
/// <item><description>This class can be instantiated with a message digest or HMAC instance, or by using a digests enumeration type name.</description></item>
/// <item><description>The generator must be initialized with a key using one of the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize() function can use a SymmetricKey key container class, or input arrays of Key, and optional Salt and Info.</description></item>
/// <item><description>The minimum key (passphrase) size is 4 bytes, enforcing passwords of at least 8 characters is recommended.</description></item>
/// <item><description>The maximum number of bytes that can be generated is the digests return size * 255.</description></item>
/// <item><description>The use of a salt value can strongly mitigate some attack vectors targeting the passphrase, and is highly recommended with PBKDF2.</description></item>
/// <item><description>The minimum salt size is 4 bytes, larger (pseudo-random) salt values are more secure.</description></item>
/// <item><description>The default iterations count is 5000, larger values are recommended for secure server-side password hashing e.g. +100,000.</description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>RFC 2898: <a href="http://tools.ietf.org/html/rfc2898">Specification</a>.</description></item>
/// <item><description>RFC 6070: <a href="https://tools.ietf.org/html/rfc6070">Test Vectors</a>.</description></item>
/// <item><description>NIST SP800-132: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf">Recommendation for Password-Based Key Derivation</a>.</description></item>
/// </list>
/// </remarks>
class PBKDF2 final : public IKdf
{
private:

	static const std::string CLASS_NAME;
	static const size_t MIN_PASSLEN = 4;
	static const size_t MIN_SALTLEN = 4;

	std::unique_ptr<HMAC> m_macGenerator;
	size_t m_blockSize;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	uint m_kdfCounter;
	Digests m_kdfDigestType;
	size_t m_kdfIterations;
	std::vector<byte> m_kdfKey;
	std::vector<byte> m_kdfSalt;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_macSize;

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
	/// <param name="Iterations">The number of compression cycles used to produce output; the default is 5000</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if an invalid digest name or iterations count is used</exception>
	PBKDF2(Digests DigestType, size_t Iterations = 5000);

	/// <summary>
	/// Instantiates a PBKDF2 generator using a message digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest instance</param>
	/// <param name="Iterations">The number of compression cycles used to produce output; the default is 5000</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if a null digest or iterations count is used</exception>
	PBKDF2(IDigest* Digest, size_t Iterations = 5000);

	/// <summary>
	/// Instantiates a PBKDF2 generator using an initialized HMAC instance
	/// </summary>
	/// 
	/// <param name="Mac">The initialized HMAC instance</param>
	/// <param name="Iterations">The number of compression cycles used to produce output; the default is 5000</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if a null HMAC, or an invalid iterations count is used</exception>
	PBKDF2(HMAC* Mac, size_t Iterations = 5000);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~PBKDF2() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Kdf generators type name
	/// </summary>
	const Kdfs Enumeral() override;

	/// <summary>
	/// Read Only: Generator is ready to produce random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Available Kdf Key Sizes in bytes
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Minimum recommended initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info should be at least this size.</para>
	/// </summary>
	size_t MinKeySize() override;

	/// <summary>
	/// Read Only: The Kdf generators class name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	size_t Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional salt, and info string.
	/// <para>The use of a salt value mitigates some attacks against a passphrase, and is highly recommended with PBKDF2.</para>
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(ISymmetricKey &GenParam) override;

	/// <summary>
	/// Initialize the generator with a key (password).
	/// <para>The use of a salt value mitigates some attacks against a passphrase, and is highly recommended with PBKDF2.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key (password) array used to seed the generator.
	/// <para>The minimum passphrase size is 4 bytes.</para></param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Key) override;

	/// <summary>
	/// Initialize the generator with key and salt arrays
	/// </summary>
	/// 
	/// <param name="Key">The primary key (password) array used to seed the generator</param>
	/// <param name="Salt">The salt value containing an additional source of entropy</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt) override;

	/// <summary>
	/// Initialize the generator with a key, a salt array, and an information string or nonce
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value used as an additional source of entropy</param>
	/// <param name="Info">The information string or nonce used as a third source of entropy</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info) override;

	/// <summary>
	/// Update the generators salt array.
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void ReSeed(const std::vector<byte> &Seed) override;

	/// <summary>
	/// Reset the internal state; Kdf must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	size_t Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void LoadState();
	void Process(std::vector<byte> &Output, size_t OutOffset);
};

NAMESPACE_KDFEND
#endif
