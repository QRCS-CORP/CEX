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

#ifndef _CEXENGINE_KDF2DRBG_H
#define _CEXENGINE_KDF2DRBG_H

#include "IGenerator.h"
#include "IDigest.h"

NAMESPACE_GENERATOR

using CEX::Digest::IDigest;

/// <summary>
/// KDF2Drbg: An implementation of an Hash based Key Derivation Function
/// </summary> 
/// 
/// <example>
/// <description>Example using an <c>IGenerator</c> interface:</description>
/// <code>
/// KDF2Drbg rnd(new SHA512());
/// // initialize
/// rnd.Initialize(Salt, [Ikm], [Nonce]);
/// // generate bytes
///  rnd.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with a Digest.</description></item>
/// <item><description>Salt size should be multiple of Digest block size.</description></item>
/// <item><description>Ikm size should be Digest hash return size.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="table">
/// <item><description>RFC 2898: <a href="http://tools.ietf.org/html/rfc2898">Password-Based Cryptography Specification Version 2.0</a>.</description></item>
/// </list>
/// </remarks>
class KDF2Drbg : public IGenerator
{
private:
	size_t m_hashSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> m_Iv;
	size_t m_blockSize;
	IDigest* m_msgDigest;
	std::vector<byte> m_salt;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Generators Enumeral() { return Generators::KDF2Drbg; }

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: The current state of the initialization Vector
	/// </summary>
	virtual const std::vector<byte> IV() { return m_Iv; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual size_t KeySize() { return m_blockSize; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "KDF2Drbg"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Creates a KDF2 Bytes Generator based on the given hash function
	/// </summary>
	/// 
	/// <param name="Digest">The digest used</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null digest is used</exception>
	explicit KDF2Drbg(CEX::Digest::IDigest* Digest)
		:
		m_blockSize(Digest->BlockSize()),
		m_hashSize(Digest->DigestSize()),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_Iv(0),
		m_msgDigest(Digest),
		m_salt(0)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Digest == 0)
			throw CryptoGeneratorException("HKDF:CTor", "The Digest can not be null!");
#endif
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~KDF2Drbg()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

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
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the output buffer is too small</exception>
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
	size_t GenerateKey(std::vector<byte> &Output, size_t OutOffset, size_t Size);
};

NAMESPACE_GENERATOREND
#endif
