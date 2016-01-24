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
// SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.
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

using CEX::Mac::HMAC;
using CEX::Digest::IDigest;

/// <summary>
/// HKDF: An implementation of an Hash based Key Derivation Function.
/// <para>HKDF as outlined in RFC 5869</para>
/// </summary> 
/// 
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Mac::HMAC">CEX::Mac::HMAC HMAC</seealso>
/// <seealso cref="CEX::Digest">CEX::Digest Namespace</seealso>
/// <seealso cref="CEX::Digest::IDigest">CEX::Digest::IDigest Interface</seealso>
/// <seealso cref="CEX::Enumeration::Digests">CEX::Enumeration::Digests Enumeration</seealso>
/// 
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>Can be initialized with a Digest or a Mac.</description></item>
/// <item><description>Salt size should be multiple of Digest block size.</description></item>
/// <item><description>Ikm size should be Digest hash return size.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// </list>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>RFC 5869: <see href="http://tools.ietf.org/html/rfc5869">Specification</see>.</description></item>
/// <item><description>HKDF Scheme: <see href="http://tools.ietf.org/html/rfc5869">Whitepaper</see>.</description></item>
/// </list>
/// </remarks>
class HKDF : public IGenerator
{
protected:
	std::vector<byte> _currentT;
	std::vector<byte> _digestInfo;
	HMAC *_digestMac;
	unsigned int _generatedBytes;
	unsigned int _hashSize;
	bool _isDestroyed;
	bool _isInitialized;
	unsigned int _keySize;
	IDigest* _msgDigest;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Generators Enumeral() { return Generators::HKDF; }

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual unsigned int KeySize() { return _keySize; }

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
	HKDF(IDigest* Digest)
		:
		_isDestroyed(false),
		_currentT(Digest->DigestSize(), 0),
		_hashSize(Digest->DigestSize()),
		_isInitialized(false),
		_keySize(Digest->BlockSize())
	{
		if (Digest == 0)
			throw CryptoGeneratorException("HKDF:CTor", "The Digest can not be null!");

		 _digestMac = new HMAC(Digest);
	}

	/// <summary>
	/// Initialize an HKDF Bytes Generator with an HMAC
	/// </summary>
	/// 
	/// <param name="Hmac">The initialized HMAC to be used</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null HMAC is used</exception>
	HKDF(HMAC* Hmac)
		:
		_digestMac(Hmac),
		_isDestroyed(false),
		_currentT(Hmac->MacSize(), 0),
		_hashSize(Hmac->MacSize()),
		_isInitialized(false),
		_keySize(Hmac->BlockSize())
	{
		if (Hmac == 0)
			throw CryptoGeneratorException("HKDF:CTor", "The Hmac can not be null!");
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
	virtual unsigned int Generate(std::vector<byte> &Output);

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
	virtual unsigned int Generate(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size);

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value; must be at least 1* digest block size</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt is too small</exception>
	virtual void Initialize(const std::vector<byte> &Salt);

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value</param>
	/// <param name="Ikm">Key material</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm);

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value</param>
	/// <param name="Ikm">Key material</param>
	/// <param name="Info">Nonce value</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Info);

	/// <summary>
	/// Update the Salt material
	/// </summary>
	/// 
	/// <param name="Salt">Pseudo random seed material</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt value is too small</exception>
	virtual void Update(const std::vector<byte> &Salt);

protected:
	void ExpandNext();
	void Extract(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, std::vector<byte> &Prk);
};

NAMESPACE_GENERATOREND
#endif

