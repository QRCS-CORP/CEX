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
// Implementation Details:
// An implementation of a Counter based Deterministic Random Byte Generator (CTRDRBG). 
// Written by John Underhill, November 21, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_CTRDRBG_H
#define _CEXENGINE_CTRDRBG_H

#include "IGenerator.h"
#include "IBlockCipher.h"

NAMESPACE_GENERATOR

/// <summary>
/// CTRDrbg: An implementation of a Encryption Counter based Deterministic Random Byte Generator
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// CTRDrbg rnd(new RDX());
/// // initialize
/// rnd.Initialize(Salt, [Ikm], [Nonce]);
/// // generate bytes
/// rnd.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block"/>
/// <seealso cref="CEX::Enumeration::BlockCiphers"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with any block cipher.</description></item>
/// <item><description>Parallelized by default on a multi processer system when an input byte array of <see cref="ParallelMinimumSize"/> bytes or larger is used.</description></item>
/// <item><description>Parallelization can be disabled using the <see cref="IsParallel"/> property.</description></item>
/// <item><description>Combination of [Salt, Ikm, Nonce] must be: cipher key size +  cipher block size in length.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
/// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the Codebook-based: Deterministic Random Bit Generator.</description></item>
/// </list>
/// </remarks>
class CTRDrbg : public IGenerator
{
private:
	static constexpr size_t BLOCK_SIZE = 1024;
	static constexpr size_t MAXALLOC_MB100 = 100000000;
	static constexpr size_t PARALLEL_DEFBLOCK = 64000;

	CEX::Cipher::Symmetric::Block::IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	std::vector<byte> m_ctrVector;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	size_t m_keySize;
	bool m_isParallel;
	size_t m_parallelBlockSize;
	size_t m_processorCount;
	std::vector<std::vector<byte>> m_threadVectors;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const CEX::Enumeration::Generators Enumeral() { return CEX::Enumeration::Generators::CTRDrbg; }

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: The current state of the initialization Vector
	/// </summary>
	const std::vector<byte> IV() { return m_ctrVector; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual size_t KeySize() { return m_keySize; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "CTRDrbg"; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	const size_t ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	const size_t ParallelMinimumSize() { return m_processorCount * m_blockSize; }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	const size_t ProcessorCount() { return m_processorCount; }

	// *** Constructor *** //

	/// <summary>
	/// Creates a HKDF Bytes Generator using the given HMAC function
	/// </summary>
	/// 
	/// <param name="Cipher">The Block Cipher instance</param>
	/// <param name="KeySize">The internal ciphers key size; calculated automatically if this value is zero</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null cipher is used</exception>
	CTRDrbg(CEX::Cipher::Symmetric::Block::IBlockCipher* Cipher, const size_t KeySize = 0)
		:
		m_blockCipher(Cipher),
		m_blockSize(Cipher->BlockSize()),
		m_ctrVector(Cipher->BlockSize()),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(PARALLEL_DEFBLOCK),
		m_processorCount(0)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (m_blockCipher == 0)
			throw CryptoGeneratorException("CTRDrbg:CTor", "The Cipher can not be null!");
#endif

		// default the 256 bit key size
		if (KeySize == 0)
		{
			m_keySize = 32;
		}
		else
		{
#if defined(CPPEXCEPTIONS_ENABLED)
			if (!IsValidKeySize(KeySize))
				throw CryptoGeneratorException("CTRDrbg:CTor", "The key size must be a ciphers legal key size!");
#endif
			m_keySize = KeySize;
		}

		SetScope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CTRDrbg()
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
	/// <param name="OutOffset">Position within Output array</param>
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
	/// <param name="Ikm">The Key value</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt is too small</exception>
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
	/// <param name="Salt">Salt value; size must be at least cipher key size + cipher block size</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt is too small</exception>
	virtual void Update(const std::vector<byte> &Salt);

private:
	void Generate(std::vector<byte> &Output, const size_t OutOffset, const size_t Length, std::vector<byte> &Counter);
	void Increment(std::vector<byte> &Counter);
	void Increase(const std::vector<byte> &Counter, const size_t Size, std::vector<byte> &Buffer);
	bool IsValidKeySize(const size_t KeySize = 0);
	void SetScope();
	void Transform(std::vector<byte> &Output, size_t OutOffset);
};

NAMESPACE_GENERATOREND
#endif
