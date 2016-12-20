// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// Updated October 3, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_HMAC_H
#define _CEX_HMAC_H

#include "IMac.h"
#include "IDigest.h"
#include "Digests.h"

NAMESPACE_MAC

using Enumeration::Digests;
using Digest::IDigest;

/// <summary>
/// An implementation of a Hash based Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Generating a MAC code</description>
/// <code>
/// Mac::HMAC mac(Enumeration::Digests::SHA256);
/// mac.Initialize(Key);
/// mac.ComputeMac(Input, Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>A keyed Hash Message Authentication Code (HMAC) uses a cryptographic hash function with a secret key to verify data integrity and authenticate a message.<br>
/// Any cryptographic hash function may be used in the calculation of an HMAC, including any of the hash functions implemented in this library. 
/// The cryptographic strength of the HMAC depends upon the strength of the underlying hash function, the size of its hash output, and on the size and quality of the key.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><br> 
/// <B>H</B>=hash-function, <B>K</B>=key, <B>K'</B>=derived-key, <B>m</B>=message, <B>^</B>=XOR, <B>||</B>=concatonate<br>
/// <EM>Generate</EM><br>
/// Where opad is the outer padding (0x5c...5c), and ipad is the inner padding (0x36...36), and K' is a secret key, derived from key K.<br>
/// HMAC(K,m) = H((K' ^ opad) || H(K' ^ ipad) || m))</para><br>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Block size is the underlying hash functions internal block size in bytes.</description></item>
/// <item><description>Digest size is the hash functions output code size in bytes.</description></item>
/// <item><description>The key size should be equal or greater than the digests output size, and less or equal to the block-size.</description></item>
/// <item><description>The ComputeMac(Input, Output) method wraps the BlockUpdate(Input, Offset, Length) and DoFinal(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The BlockUpdate(Input, Offset, Length) processes any length of message data, and is used in conjunction with the DoFinal(Output, Offset) method, which returns the final MAC code.</description>/></item>
/// <item><description>After a finalizer call (DoFinal or ComputeMac), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198-1</a>: The Keyed-Hash Message Authentication Code (HMAC).</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">180-4</a>: Secure Hash Standard (SHS).</description></item>
/// <item><description>CRYPTO '06, Lecture <a href="http://cseweb.ucsd.edu/~mihir/papers/hmac-new.pdf">NMAC and HMAC Security</a>: NMAC and HMAC Security Proofs.</description></item>
/// </list>
/// </remarks>
class HMAC : public IMac
{
private:

	const byte IPAD = 0x36;
	const byte OPAD = 0x5C;

	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> m_inputPad;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	IDigest* m_msgDigest;
	Digests m_msgDigestType;
	std::vector<byte> m_outputPad;

public:

	HMAC() = delete;
	HMAC(const HMAC&) = delete;
	HMAC& operator=(const HMAC&) = delete;
	HMAC& operator=(HMAC&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_msgDigest->BlockSize(); }

	/// <summary>
	/// Get: The message digest engine type
	/// </summary>
	const Digests DigestType() { return m_msgDigestType; }

	/// <summary>
	/// Get: Mac generators type name
	/// </summary>
	virtual const Macs Enumeral() { return Macs::HMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() { return m_msgDigest->DigestSize(); }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_legalKeySizes; };

	/// <summary>
	/// Get: Mac generators class name
	/// </summary>
	virtual const std::string Name() { return "HMAC"; }

	//~~~Constructor~~~//
	/// <summary>
	/// Instantiate this class using the digest enumeration name
	/// </summary>
	/// 
	/// <param name="DigestType">The message digest enumeration name</param>
	explicit HMAC(Digests DigestType)
		:
		m_destroyEngine(true),
		m_inputPad(0),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_legalKeySizes(0),
		m_msgDigest(0),
		m_msgDigestType(Digests::None),
		m_outputPad(0)
	{
		m_msgDigest = LoadDigest(DigestType);

		if (m_msgDigest == 0)
			throw CryptoMacException("HMAC:Ctor", "Could not create the digest!");

		LoadState();
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="Digest">Message Digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if a null digest is used</exception>
	explicit HMAC(IDigest* Digest)
		:
		m_destroyEngine(false),
		m_inputPad(0),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_legalKeySizes(0),
		m_msgDigest(Digest),
		m_msgDigestType(Digests::None),
		m_outputPad(0)
	{
		if (Digest == 0)
			throw CryptoMacException("HMAC:Ctor", "The digest can not be null!");

		LoadState();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~HMAC()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the Mac with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The Mac input data array</param>
	/// <param name="InOffset">Starting position with the Input array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key and optional salt and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="MacParam">A SymmetricKey key container class</param>
	virtual void Initialize(ISymmetricKey &MacParam);

	/// <summary>
	/// Initialize the MAC with a key
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	virtual void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the MAC with a key and salt arrays
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt appended to the key as a source of additional entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt);

	/// <summary>
	/// Initialize the MAC generator.
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt appended to the key as a source of additional entropy</param>
	/// <param name="Info">The info parameter appended to the key as a source of additional entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info);

	/// <summary>
	/// Reset to the default state; Mac must be re-initialized after this call
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the digest with 1 byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

private:
	IDigest* LoadDigest(Digests DigestType);
	void LoadState();
	void XorPad(std::vector<byte> &A, byte N);
};

NAMESPACE_MACEND
#endif
