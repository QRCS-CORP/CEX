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

#ifndef _CEXENGINE_PBPRNG_H
#define _CEXENGINE_PBPRNG_H

#include "IRandom.h"
#include "IDigest.h"
#include "PBKDF2.h"
#include "Digests.h"
#include "IntUtils.h"
NAMESPACE_PRNG

using CEX::Enumeration::Digests;

/// <summary>
/// PBPRng: An implementation of a passphrase based PKCS#5 random number generator.
/// <para>Implements PKCS#5 as defined in RFC 2898</para>
/// </summary>
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// PBPRng rnd(new SHA512(), PassPhrase, Salt);
/// int x = rnd.Next();
/// </code>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Mac::HMAC">CEX::Mac HMAC</seealso>
/// <seealso cref="CEX::Digest::IDigest">CEX::Digest IDigest Interface</seealso>
/// <seealso cref="CEX::Enumeration::Digests">CEX::Enumeration Digests Enumeration</seealso>
/// 
/// <remarks>
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>RFC 2898: <see href="http://tools.ietf.org/html/rfc2898">Specification</see>.</description></item>
/// </list>
/// </remarks>
class PPBPrng : public IRandom
{
protected:
	static constexpr unsigned int PKCS_ITERATIONS = 2;
	static constexpr unsigned int BUFFER_SIZE = 1024;

	unsigned int _bufferIndex;
	unsigned int _bufferSize;
	std::vector<byte> _byteBuffer;
	CEX::Digest::IDigest* _digestEngine;
	unsigned int _digestIterations;
	Digests _digestType;
	bool _isDestroyed;
	CEX::Generator::PBKDF2* _rngGenerator;
	std::vector<byte> _stateSeed;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const Prngs Enumeral() { return Prngs::PPBPrng; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "PPBPrng"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
	/// <param name="Iterations">The number of transformation iterations performed by the digest with PBKDF2 (default is 10,000)</param>
	/// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the seed or buffer size is too small; (min. seed = 2* digest hash size, min. buffer 64 bytes)</exception>
	PPBPrng(std::vector<byte> &Seed, int Iterations = PKCS_ITERATIONS, Digests DigestEngine = Digests::SHA512, unsigned int BufferSize = BUFFER_SIZE)
		:
		_bufferIndex(0),
		_bufferSize(BufferSize),
		_byteBuffer(BufferSize),
		_digestIterations(Iterations),
		_digestType(DigestEngine),
		_isDestroyed(false),
		_stateSeed(Seed)
	{
		if (Iterations == 0)
			throw CryptoRandomException("DGCPrng:Ctor", "Iterations can not be zero; at least 1 iteration is required!");
		if (GetMinimumSeedSize(DigestEngine) < Seed.size())
			throw CryptoRandomException("DGCPrng:Ctor", "The state seed is too small! must be at least digests block size!");
		if (BufferSize < 64)
			throw CryptoRandomException("DGCPrng:Ctor", "BufferSize must be at least 64 bytes!");

		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~PPBPrng()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Size">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	virtual std::vector<byte> GetBytes(unsigned int Size);

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	virtual void GetBytes(std::vector<byte> &Data);

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random 32bit integer</returns>
	virtual unsigned int Next();

	/// <summary>
	/// Get an pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	virtual unsigned int Next(unsigned int Maximum);

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	virtual unsigned int Next(unsigned int Minimum, unsigned int Maximum);

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random 64bit integer</returns>
	virtual ulong NextLong();

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 64bit integer</returns>
	virtual ulong NextLong(ulong Maximum);

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 64bit integer</returns>
	virtual ulong NextLong(ulong Minimum, ulong Maximum);

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	virtual void Reset();

protected:
	std::vector<byte> GetBits(std::vector<byte> Data, ulong Maximum);
	std::vector<byte> GetByteRange(ulong Maximum);
	CEX::Digest::IDigest* GetInstance(Digests RngEngine);
	unsigned int GetMinimumSeedSize(Digests RngEngine);
};

NAMESPACE_PRNGEND
#endif