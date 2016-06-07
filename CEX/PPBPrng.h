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
#include "DigestFromName.h"
#include "IntUtils.h"
#include "PBKDF2.h"

NAMESPACE_PRNG

/// <summary>
/// PBPRng: An implementation of a passphrase based PKCS#5 random number generator
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
/// <seealso cref="CEX::Mac::HMAC"/>
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2898">2898</a>: Password-Based Cryptography Specification Version 2.0.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2898">2898</a>: Specification.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>, Section D.3: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list>
/// </remarks>
class PPBPrng : public IRandom
{
private:
	static constexpr size_t PKCS_ITERATIONS = 2;
	static constexpr size_t BUFFER_SIZE = 1024;

	size_t m_bufferIndex;
	size_t m_bufferSize;
	std::vector<byte> m_byteBuffer;
	CEX::Digest::IDigest* m_digestEngine;
	size_t m_digestIterations;
	CEX::Enumeration::Digests m_digestType;
	bool m_isDestroyed;
	CEX::Generator::PBKDF2* m_rngGenerator;
	std::vector<byte> m_stateSeed;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const CEX::Enumeration::Prngs Enumeral() { return CEX::Enumeration::Prngs::PPBPrng; }

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
	PPBPrng(std::vector<byte> &Seed, int Iterations = PKCS_ITERATIONS, CEX::Enumeration::Digests DigestEngine = CEX::Enumeration::Digests::SHA512, size_t BufferSize = BUFFER_SIZE)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_digestIterations(Iterations),
		m_digestType(DigestEngine),
		m_isDestroyed(false),
		m_stateSeed(Seed)
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
	virtual std::vector<byte> GetBytes(size_t Size);

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
	virtual uint Next();

	/// <summary>
	/// Get an pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	virtual uint Next(uint Maximum);

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	virtual uint Next(uint Minimum, uint Maximum);

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

private:
	std::vector<byte> GetBits(std::vector<byte> Data, ulong Maximum);
	std::vector<byte> GetByteRange(ulong Maximum);
	CEX::Digest::IDigest* GetInstance(CEX::Enumeration::Digests RngEngine);
	uint GetMinimumSeedSize(CEX::Enumeration::Digests RngEngine);
};

NAMESPACE_PRNGEND
#endif