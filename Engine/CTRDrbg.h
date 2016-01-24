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

using CEX::Cipher::Symmetric::Block::IBlockCipher;

/// <summary>
/// CTRDrbg: An implementation of a Encryption Counter based Deterministic Random Byte Generator.
/// <para>A Block Cipher Counter DRBG as outlined in NIST document: SP800-90A</para>
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
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block">CEX::Cipher::Symmetric::Block Namespace</seealso>
/// <seealso cref="CEX::Enumeration::BlockCiphers">CEX::Enumeration::BlockCiphers Enumeration</seealso>
/// 
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>Can be initialized with any block <see cref="CEX::Enumeration::BlockCiphers">cipher</see>.</description></item>
/// <item><description>Parallelized by default on a multi processer system when an input byte array of <see cref="ParallelMinimumSize"/> bytes or larger is used.</description></item>
/// <item><description>Parallelization can be disabled using the <see cref="IsParallel"/> property.</description></item>
/// <item><description>Combination of [Salt, Ikm, Nonce] must be: cipher key size +  cipher block size in length.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// </list>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
/// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
/// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
/// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
/// </list>
/// </remarks>
class CTRDrbg : public IGenerator
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 1024;
	static constexpr unsigned int MAXALLOC_MB100 = 100000000;
	static constexpr unsigned int PARALLEL_DEFBLOCK = 64000;

	IBlockCipher* _blockCipher;
	unsigned int _blockSize;
	std::vector<byte> _ctrVector;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	unsigned int _keySize;
	bool _isParallel;
	unsigned int _parallelBlockSize;
	unsigned int _processorCount;
	std::vector<std::vector<byte>> _threadVectors;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Generators Enumeral() { return Generators::CTRDrbg; }

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() { return _isParallel; }

	/// <summary>
	/// Get: The current state of the initialization Vector
	/// </summary>
	virtual const std::vector<byte> IV() { return _ctrVector; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual unsigned int KeySize() { return _keySize; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	virtual unsigned int &ParallelBlockSize() { return _parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual const unsigned int ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const unsigned int ParallelMinimumSize() { return _processorCount * _blockSize; }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const unsigned int ProcessorCount() { return _processorCount; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "CTRDrbg"; }

	// *** Constructor *** //

	/// <summary>
	/// Creates a HKDF Bytes Generator using the given HMAC function
	/// </summary>
	/// 
	/// <param name="Hmac">The HMAC digest used</param>
	/// <param name="KeySize">The internal ciphers key size; calculated automatically if this value is zero</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null cipher is used</exception>
	CTRDrbg(IBlockCipher* Cipher, const unsigned int KeySize = 0)
		:
		_blockCipher(Cipher),
		_blockSize(Cipher->BlockSize()),
		_ctrVector(Cipher->BlockSize()),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_isParallel(false),
		_parallelBlockSize(PARALLEL_DEFBLOCK),
		_processorCount(0)
	{
		if (_blockCipher == 0)
			throw CryptoGeneratorException("CTRDrbg:CTor", "The Cipher can not be null!");

		// default the 256 bit key size
		if (KeySize == 0)
		{
			_keySize = 32;
		}
		else
		{
			if (!IsValidKeySize(KeySize))
				throw CryptoGeneratorException("CTRDrbg:CTor", "The key size must be a ciphers legal key size!");
			else
				_keySize = KeySize;
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
	virtual unsigned int Generate(std::vector<byte> &Output);

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
	virtual unsigned int Generate(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size);

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value; size must be at least cipher key size + cipher block size</param>
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
	/// <param name="Nonce">Nonce value</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce);

	/// <summary>
	/// Update the Salt material
	/// </summary>
	/// 
	/// <param name="Salt">Salt value; size must be at least cipher key size + cipher block size</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt is too small</exception>
	virtual void Update(const std::vector<byte> &Salt);

protected:
	void Generate(const unsigned int Length, std::vector<byte> &Counter, std::vector<byte> &Output, const unsigned int OutOffset);
	void Increment(std::vector<byte> &Counter);
	void Increase(const std::vector<byte> &Counter, const unsigned int Size, std::vector<byte> &Buffer);
	bool IsValidKeySize(const unsigned int KeySize = 0);
	void SetScope();
	void Transform(std::vector<byte> &Output, unsigned int OutOffset);
};

NAMESPACE_GENERATOREND
#endif
