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
// An implementation of a Counter based Cryptographically Secure Pseudo Random Number Generator (CTRPrng). 
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_CTRPRNG_H
#define _CEXENGINE_CTRPRNG_H

#include "IRandom.h"
#include "CTRDrbg.h"
#include "IBlockCipher.h"
#include "IRandom.h"
#include "ISeed.h"

NAMESPACE_PRNG

/// <summary>
/// CTRPrng: An implementation of a Encryption Counter based Deterministic Random Number Generator
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// CTRPrng rnd([BlockCiphers], [SeedGenerators]);
/// // get random int
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block"/>
/// <seealso cref="CEX::Seed"/>
/// <seealso cref="CEX::Enumeration::BlockCiphers"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Can be initialized with any block cipher.</description></item>
/// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
/// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
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
class CTRPrng : public IRandom
{
private:
	static constexpr size_t BUFFER_SIZE = 4096;

	std::vector<byte> m_byteBuffer;
	size_t m_bufferIndex;
	size_t m_bufferSize = 0;
	size_t m_keySize = 0;
	bool m_isDestroyed;
	CEX::Enumeration::BlockCiphers m_engineType;
	CEX::Cipher::Symmetric::Block::IBlockCipher* m_rngEngine;
	CEX::Generator::CTRDrbg* m_rngGenerator;
	CEX::Seed::ISeed* m_seedGenerator;
	CEX::Enumeration::SeedGenerators m_seedType;
	std::vector<byte>  m_stateSeed;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const CEX::Enumeration::Prngs Enumeral() { return CEX::Enumeration::Prngs::CTRPrng; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "CTRPrng"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	/// 
	/// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
	/// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// <param name="KeySize">The key size (in bytes) of the symmetric cipher; a <c>0</c> value will auto size the key</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	CTRPrng(CEX::Enumeration::BlockCiphers BlockEngine = CEX::Enumeration::BlockCiphers::RHX, CEX::Enumeration::SeedGenerators SeedEngine = CEX::Enumeration::SeedGenerators::CSPRsg, size_t BufferSize = BUFFER_SIZE, size_t KeySize = 0)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_engineType(BlockEngine),
		m_isDestroyed(false),
		m_seedType(SeedEngine)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (BufferSize < 64)
			throw CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!");
#endif
		if (KeySize > 0)
			m_keySize = KeySize;
		else
			m_keySize = GetKeySize(BlockEngine);

		Reset();
	}

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
	/// <param name="BlockEngine">The block cipher that powers the rng (default is RDX)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the seed is null or too small</exception>
	CTRPrng(std::vector<byte> &Seed, CEX::Enumeration::BlockCiphers BlockEngine = CEX::Enumeration::BlockCiphers::RHX, size_t BufferSize = 4096)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_engineType(BlockEngine),
		m_isDestroyed(false),
		m_stateSeed(Seed)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (BufferSize < 64)
			throw CryptoRandomException("CTRPrng:Ctor", "Buffer size must be at least 64 bytes!");
		if (Seed.size() == 0)
			throw CryptoRandomException("CTRPrng:Ctor", "Seed can not be null or empty!");
		if (GetKeySize(BlockEngine) < Seed.size())
			throw CryptoRandomException("CTRPrng:Ctor", "The state seed is too small! must be at least the size of the cipher key/iv");
#endif
		m_keySize = GetKeySize(BlockEngine);

		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CTRPrng()
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
	CEX::Cipher::Symmetric::Block::IBlockCipher* GetCipher(CEX::Enumeration::BlockCiphers RngEngine);
	uint GetKeySize(CEX::Enumeration::BlockCiphers CipherEngine);
	CEX::Seed::ISeed* GetSeedGenerator(CEX::Enumeration::SeedGenerators SeedEngine);
};

NAMESPACE_PRNGEND
#endif