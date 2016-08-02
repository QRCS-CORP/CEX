// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of an Hash based Key Derivation Function (HKDF). 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_HKDF_H
#define _CEXENGINE_HKDF_H

#include "IGenerator.h"
#include "IDigest.h"
#include "HMAC.h"

NAMESPACE_GENERATOR

/// <summary>
/// HKDF: An implementation of an Hash based Key Derivation Function
/// </summary> 
/// 
/// 
/// <seealso cref="CEX::Mac::HMAC"/>
/// <seealso cref="CEX::Digest"/>
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with a Digest or a Mac.</description></item>
/// <item><description>Salt size should be multiple of Digest block size.</description></item>
/// <item><description>Ikm size should be Digest hash return size.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5869">5869</a>: HMAC-based Extract-and-Expand Key Derivation Function.</description></item>
/// </list>
/// </remarks>
class HKDF : public IGenerator
{
private:
	std::vector<byte> m_currentT;
	std::vector<byte> m_digestInfo;
	CEX::Mac::HMAC *m_digestMac;
	size_t m_generatedBytes;
	size_t m_hashSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	size_t m_keySize;
	CEX::Digest::IDigest* m_msgDigest;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const CEX::Enumeration::Generators Enumeral() { return CEX::Enumeration::Generators::HKDF; }

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual size_t KeySize() { return m_keySize; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "HKDF"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize an HKDF Bytes Generator with a message digest
	/// </summary>
	/// 
	/// <param name="Digest">The initialized message digest to be used</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null digest is used</exception>
	explicit HKDF(CEX::Digest::IDigest* Digest)
		:
		m_isDestroyed(false),
		m_currentT(Digest->DigestSize(), 0),
		m_generatedBytes(0),
		m_hashSize(Digest->DigestSize()),
		m_isInitialized(false),
		m_keySize(Digest->BlockSize()),
		m_msgDigest(Digest)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Digest == 0)
			throw CryptoGeneratorException("HKDF:CTor", "The Digest can not be null!");
#endif

		 m_digestMac = new CEX::Mac::HMAC(m_msgDigest);
	}

	/// <summary>
	/// Initialize an HKDF Bytes Generator with an HMAC
	/// </summary>
	/// 
	/// <param name="Hmac">The initialized HMAC to be used</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null HMAC is used</exception>
	explicit HKDF(CEX::Mac::HMAC* Hmac)
		:
		m_currentT(Hmac->MacSize(), 0),
		m_digestMac(Hmac),
		m_generatedBytes(0),
		m_hashSize(Hmac->MacSize()),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_keySize(Hmac->BlockSize()),
		m_msgDigest(0)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Hmac == 0)
			throw CryptoGeneratorException("HKDF:CTor", "The Hmac can not be null!");
#endif
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~HKDF()
	{
		Destroy();
	}

	// *** Public Methods *** //

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
	/// <returns>Number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output);

	/// <summary>
	/// Generate pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within Output array</param>
	/// <param name="Size">Number of bytes to generate</param>
	/// 
	/// <returns>Number of bytes generated</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the output buffer is too small, or the size requested exceeds maximum: 255 * HashLen bytes</exception>
	virtual size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size);

	/// <summary>
	/// Initialize the generator with a Key
	/// </summary>
	/// 
	/// <param name="Ikm">The Key value; minimum size is 2* the digests output size</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Key is too small</exception>
	virtual void Initialize(const std::vector<byte> &Ikm);

	/// <summary>
	/// Initialize the generator with a Salt value and a Key
	/// </summary>
	/// 
	/// <param name="Salt">The Salt value</param>
	/// <param name="Ikm">The Key value</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm);

	/// <summary>
	/// Initialize the generator with a Salt value, a Key, and an Information nonce
	/// </summary>
	/// 
	/// <param name="Salt">The Salt value</param>
	/// <param name="Ikm">The Key value</param>
	/// <param name="Nonce">The Nonce value</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce);

	/// <summary>
	/// Update the Salt material
	/// </summary>
	/// 
	/// <param name="Salt">Pseudo random seed material</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt value is too small</exception>
	virtual void Update(const std::vector<byte> &Salt);

private:
	void Expand();
	void Extract(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, std::vector<byte> &Prk);
};

NAMESPACE_GENERATOREND
#endif

