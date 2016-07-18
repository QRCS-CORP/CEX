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

#ifndef _CEXENGINE_SP20PRNG_H
#define _CEXENGINE_SP20PRNG_H

#include "IRandom.h"
#include "ISeed.h"
#include "SP20Drbg.h"

NAMESPACE_PRNG

/// <summary>
/// SP20Prng: An implementation of a Encryption Counter based Deterministic Random Number Generator
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// SP20Prng rnd([SeedGenerators], [Buffer Size], [Key Size], [Rounds Count]);
/// // get random int
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
/// <item><description>Block size is 64 bytes wide.</description></item>
/// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
/// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">eSTREAM Phase 3</a>.</description></item>
/// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
/// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
/// </list>
/// </remarks>
class SP20Prng : public IRandom
{
private:
	static constexpr size_t BUFFER_SIZE = 4096;

	size_t m_bufferIndex;
	size_t m_bufferSize = 0;
	std::vector<byte>  m_byteBuffer;
	size_t m_dfnRounds;
	size_t m_keySize = 0;
	bool m_isDestroyed;
	CEX::Generator::SP20Drbg* m_rngGenerator;
	CEX::Seed::ISeed* m_seedGenerator;
	CEX::Enumeration::SeedGenerators m_seedType;
	std::vector<byte>  m_stateSeed;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const CEX::Enumeration::Prngs Enumeral() { return CEX::Enumeration::Prngs::SP20Prng; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "SP20Prng"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="SeedEngine">The Seed engine used to create keyng material (default is CSPRsg)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// <param name="KeySize">The size of the seed to generate in bytes; can be 32 for a 128 bit key or 48 for a 256 bit key</param>
	/// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the buffer or key size invalid, or rounds count is out of range (rounds 10-30, min. buffer 64 bytes)</exception>
	SP20Prng(CEX::Enumeration::SeedGenerators SeedEngine = CEX::Enumeration::SeedGenerators::CSPRsg, size_t BufferSize = BUFFER_SIZE, size_t KeySize = 40, size_t Rounds = 20)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_dfnRounds(Rounds),
		m_keySize(KeySize),
		m_isDestroyed(false),
		m_seedType(SeedEngine)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (BufferSize < 64)
			throw CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!");
		if (KeySize != 24 && KeySize != 40)
			throw CryptoRandomException("SP20Prng:CTor", "Seed size must be 32 or 48 bytes (key + iv)!");
		if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
			throw CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!");
#endif

		Reset();
	}

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + iv of 16 bytes)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// <param name="Rounds">The number of diffusion rounds to use when generating the key stream</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoRandomException">Thrown if the buffer or key size invalid, or rounds count is out of range</exception>
	SP20Prng(std::vector<byte> Seed, size_t BufferSize = BUFFER_SIZE, size_t Rounds = 20)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_dfnRounds(Rounds),
		m_keySize(Seed.size()),
		m_isDestroyed(false)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (BufferSize < 64)
			throw CryptoRandomException("SP20Prng:CTor", "Buffer size must be at least 64 bytes!");
		if (Seed.size() != 32 && Seed.size() != 48)
			throw CryptoRandomException("SP20Prng:CTor", "Seed size must be 32 or 48 bytes (key + iv)!");
		if (Rounds < 10 || Rounds > 30 || Rounds % 2 > 0)
			throw CryptoRandomException("SP20Prng:CTor", "Rounds must be an even number between 10 and 30!");
#endif
		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SP20Prng()
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
	CEX::Seed::ISeed* GetSeedGenerator(CEX::Enumeration::SeedGenerators SeedEngine);
};

NAMESPACE_PRNGEND
#endif