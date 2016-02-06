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
// Implementation Details:</description>
// An implementation of a Digest Counter based Deterministic Random Byte Generator (DGTDRBG),
// based on the NIST <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Hash_DRBG</see>, SP800-90A Appendix E1. 
// Written by John Underhill, January 09, 2014

#ifndef _CEXENGINE_DGCDRBG_H
#define _CEXENGINE_DGCDRBG_H

#include "IGenerator.h"
#include "IDigest.h"
#include <mutex>

NAMESPACE_GENERATOR

/// <summary>
/// DGTDRBG: An implementation of a Digest Counter based Deterministic Random Byte Generator.
/// <para>A Digest Counter DRBG as outlined in NIST document: SP800-90A</para>
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// DGTDRBG rnd(new SHA512());
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
/// <seealso cref="CEX::Digest"/>
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with any <see cref="CEX::Enumeration::Digests">digest</see>.</description></item>
/// <item><description>Combination of [Salt, Ikm, Nonce] must be at least: digest block size + counter (8 bytes) size in length.</description></item>
/// <item><description>Nonce and Ikm are optional, (but recommended).</description></item>
/// <item><description>Output buffer is 4 * the digest return size.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST SP800-90A: <see href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">Appendix E1.</see></description></item>
/// <item><description>NIST SP800-90B: <see href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">Recommendation for the Entropy Sources Used for Random Bit Generation</see>.</description></item>
/// <item><description>NIST Fips 140-2: <see href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Security Requirments For Cryptographic Modules</see>.</description></item>
/// <item><description>NIST SP800-22 1a: <see href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications</see>.</description></item>
/// <item><description>Security Bounds for the NIST Codebook-based: <see href="http://eprint.iacr.org/2006/379.pdf">Deterministic Random Bit Generator</see>.</description></item>
/// </list>
/// </remarks>
class DGCDrbg : public IGenerator
{
protected:
	static constexpr unsigned int COUNTER_SIZE = 8;
	static constexpr unsigned int CYCLE_COUNT = 10;

	std::vector<byte> _dgtSeed;
	std::vector<byte> _dgtState;
	bool _isDestroyed;
	bool _isInitialized;
	unsigned int _keySize;
	CEX::Digest::IDigest* _msgDigest;
	std::mutex _mtxLock;
	long _seedCtr;
	long _stateCtr;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const CEX::Enumeration::Generators Enumeral() { return CEX::Enumeration::Generators::DGCDrbg; }

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
	virtual const char *Name() { return "DGCDrbg"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="Digest">Hash function</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if a null digest is used</exception>
	DGCDrbg(CEX::Digest::IDigest* Digest)
		:
		_dgtSeed(Digest->DigestSize()),
		_dgtState(Digest->DigestSize()),
		_isDestroyed(false),
		_isInitialized(false),
		_keySize(Digest->BlockSize() + COUNTER_SIZE),
		_msgDigest(Digest),
		_stateCtr(1),
		_seedCtr(1)
	{
		if (Digest == 0)
			throw CryptoGeneratorException("DGCDrbg:Ctor", "Digest can not be null!");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~DGCDrbg()
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
	/// <param name="Salt">Salt value; salt must be at least 1* block size + counter size of 8 bytes</param>
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
	virtual void Update(const std::vector<byte> &Seed);

protected:
	void CycleSeed();
	void GenerateState();
	void IncrementCounter(long Counter);
	void UpdateCounter(long Counter);
	void UpdateSeed(std::vector<byte> Salt);
};

NAMESPACE_GENERATOREND
#endif
