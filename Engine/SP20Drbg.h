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
// An implementation of a Salsa20 Counter based Deterministic Random Byte Generator (SP20Drbg). 
// Written by John Underhill, November 21, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SP20DRBG_H
#define _CEXENGINE_SP20DRBG_H

#include "IGenerator.h"

NAMESPACE_GENERATOR

/// <summary>
/// SP20Drbg: A parallelized Salsa20 deterministic random byte generator implementation.
/// <para>A Salsa20 key stream, parallelized and extended to use up to 30 rounds of diffusion.</para>
/// </summary>
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// SP20Drbg rnd(20);
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
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
/// <item><description>Block size is 64 bytes wide.</description></item>
/// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
/// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
/// </list>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>Salsa20 <see href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</see>.</description></item>
/// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/design.pdf">Design</see>.</description></item>
/// <item><description>Salsa20 <see href="http://cr.yp.to/snuffle/security.pdf">Security</see>.</description></item>
/// </list>
/// 
/// </remarks>
class SP20Drbg : public IGenerator
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 64;
	static constexpr unsigned int DEFAULT_ROUNDS = 20;
	static constexpr unsigned int KEY_SIZE = 32;
	static constexpr unsigned int MAXALLOC_MB100 = 100000000;
	static constexpr unsigned int MAX_PARALLEL = 1024000;
	static constexpr unsigned int MAX_ROUNDS = 30;
	static constexpr unsigned int MIN_PARALLEL = 1024;
	static constexpr unsigned int MIN_ROUNDS = 8;
	static constexpr unsigned int PARALLEL_CHUNK = 1024;
	static constexpr unsigned int PARALLEL_DEFBLOCK = 64000;
	static constexpr const char *SIGMA = "expand 32-byte k";
	static constexpr unsigned int STATE_SIZE = 16;
	static constexpr unsigned int VECTOR_SIZE = 8;

	std::vector<uint> _ctrVector;
	std::vector<byte> _dstCode;
	bool _isDestroyed;
	bool _isInitialized;
	bool _isParallel;
	std::vector<unsigned int> _legalKeySizes;
	std::vector<unsigned int> _legalRounds;
	unsigned int _parallelBlockSize;
	unsigned int _processorCount;
	unsigned int _rndCount;
	std::vector<std::vector<uint>> _threadVectors;
	std::vector<uint> _wrkState;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Generators Enumeral() { return Generators::SP20Drbg; }

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
	virtual const std::vector<uint> IV() { return _ctrVector; }

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual unsigned int KeySize() { return KEY_SIZE; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<unsigned int>&LegalKeySizes() { return _legalKeySizes; };

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<unsigned int> &LegalRounds() { return _legalRounds; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "SP20Drbg"; }

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
	virtual const unsigned int ParallelMinimumSize() { return _processorCount * (STATE_SIZE * 4); }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const unsigned int ProcessorCount() { return _processorCount; }

	/// <summary>
	/// Get: Initialization vector size
	/// </summary>
	virtual const unsigned int VectorSize() { return VECTOR_SIZE; }

	// *** Constructor *** //

	/// <summary>
	/// Creates a HKDF Bytes Generator based on the given HMAC function
	/// </summary>
	/// 
	/// <param name="Hmac">The HMAC digest used</param>
	/// <param name="DestroyEngine">Destroy the digest engine when the finalizer is called</param>
	SP20Drbg(unsigned int Rounds = 20)
		:
		_ctrVector(2, 0),
		_dstCode(0),
		_isDestroyed(false),
		_isInitialized(false),
		_isParallel(false),
		_parallelBlockSize(PARALLEL_DEFBLOCK),
		_processorCount(0),
		_rndCount(Rounds),
		_wrkState(14, 0)
	{
		_legalKeySizes = { 16, 32 };
		_legalRounds = { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 };
		SetScope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SP20Drbg()
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
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the output buffer is too small</exception>
	virtual unsigned int Generate(std::vector<byte> &Output, unsigned int OutOffset, unsigned int Size);

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value; must be either 24 or 40 bytes</param>
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
	/// <param name="Salt">Pseudo random seed material</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if the Salt value is too small</exception>
	virtual void Update(const std::vector<byte> &Salt);

protected:
	void Generate(const unsigned int Length, std::vector<uint> &Counter, std::vector<byte> &Output, const unsigned int OutOffset);
	void Increase(const std::vector<uint> &Counter, const unsigned int Size, std::vector<uint> &Vector);
	void Increment(std::vector<uint> &Counter);
	void SalsaCore(std::vector<byte> &Output, const unsigned int OutOffset, const std::vector<uint> &Counter);
	void SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv);
	void SetScope();
	void Transform(std::vector<byte> &Output, unsigned int OutOffset);
};

NAMESPACE_GENERATOREND
#endif
