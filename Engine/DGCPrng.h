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

#ifndef _CEXENGINE_DGCPRNG_H
#define _CEXENGINE_DGCPRNG_H

#include "IRandom.h"
#include "DGCDrbg.h"
#include "IDigest.h"
#include "ISeed.h"

NAMESPACE_PRNG

/// <summary>
/// DGCPrng: An implementation of a Digest Counter based Random Number Generator
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// DGCPrng rnd([Digests], [SeedGenerators], [Buffer Size]);
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Digest"/>
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with any digest.</description></item>
/// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
/// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf">SP800-90A</a>: Appendix E1.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf">SP800-22 1a</a>: A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications.</description></item>
/// <item><description>NIST <a href="http://eprint.iacr.org/2006/379.pdf">Security Bounds</a> for the NIST Codebook-based: Deterministic Random Bit Generator.</description></item>
/// </list>
/// 
/// </remarks>
class DGCPrng : public IRandom
{
private:
	static constexpr unsigned int BUFFER_SIZE = 1024;

	unsigned int _bufferIndex = 0;
	unsigned int _bufferSize = 0;
	std::vector<byte> _byteBuffer;
	CEX::Digest::IDigest* _digestEngine;
	CEX::Enumeration::Digests _digestType;
	bool _isDestroyed;
	CEX::Generator::DGCDrbg* _rngGenerator;
	CEX::Seed::ISeed* _seedGenerator;
	CEX::Enumeration::SeedGenerators _seedType;
	std::vector<byte> _stateSeed;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const CEX::Enumeration::Prngs Enumeral() { return CEX::Enumeration::Prngs::DGCPrng; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "DGCPrng"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="SeedEngine">The Seed engine used to create the salt (default is CSPRsg)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	DGCPrng(CEX::Enumeration::Digests DigestEngine = CEX::Enumeration::Digests::Keccak512, CEX::Enumeration::SeedGenerators SeedEngine = CEX::Enumeration::SeedGenerators::CSPRsg, unsigned int BufferSize = BUFFER_SIZE)
		:
		_bufferIndex(0),
		_bufferSize(BufferSize),
		_byteBuffer(BufferSize),
		_digestType(DigestEngine),
		_isDestroyed(false),
		_seedType(SeedEngine)
	{
		if (BufferSize < 64)
			throw CryptoRandomException("DGCPrng:Ctor", "BufferSize must be at least 64 bytes!");

		Reset();
	}

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
	/// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the seed is null or buffer size is too small; (min. seed = digest blocksize + 8)</exception>
	DGCPrng(std::vector<byte> Seed, CEX::Enumeration::Digests DigestEngine = CEX::Enumeration::Digests::Keccak512, unsigned int BufferSize = BUFFER_SIZE)
		:
		_bufferIndex(0),
		_bufferSize(BufferSize),
		_byteBuffer(BufferSize),
		_digestType(DigestEngine),
		_isDestroyed(false)
	{
		if (Seed.size() == 0)
			throw CryptoRandomException("DGCPrng:Ctor", "Seed can not be null!");
		if (GetMinimumSeedSize(DigestEngine) < Seed.size())
			throw CryptoRandomException("DGCPrng:Ctor", "The state seed is too small! must be at least digest block size + 8 bytes");
		if (BufferSize < 128)
			throw CryptoRandomException("DGCPrng:Ctor", "BufferSize must be at least 128 bytes!");

		_seedType = CEX::Enumeration::SeedGenerators::CSPRsg;
		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~DGCPrng()
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

private:
	std::vector<byte> GetBits(std::vector<byte> Data, ulong Maximum);
	std::vector<byte> GetByteRange(ulong Maximum);
	CEX::Digest::IDigest* GetInstance(CEX::Enumeration::Digests RngEngine);
	unsigned int GetMinimumSeedSize(CEX::Enumeration::Digests RngEngine);
	CEX::Seed::ISeed* GetSeedGenerator(CEX::Enumeration::SeedGenerators SeedEngine);
};

NAMESPACE_PRNGEND
#endif