// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// An implementation of a Counter based Cryptographically Secure Pseudo Random Number Generator (CMR). 
// Written by John Underhill, January 6, 2014
// Contact: develop@vtdev.com

#ifndef _CEX_CMR_H
#define _CEX_CMR_H

#include "IPrng.h"
#include "BlockCiphers.h"
#include "CMG.h"
#include "IProvider.h"
#include "Providers.h"

NAMESPACE_PRNG

using Enumeration::BlockCiphers;
using Provider::IProvider;
using Enumeration::Providers;

/// <summary>
/// An implementation of a block cipher Counter Mode Pseudo-Random Number Generator
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// CMR rnd([BlockCiphers], [Providers]);
/// // get random int
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the Counter Mode Generator (CMG) drbg implementation.</description></item>
/// <item><description>Can be initialized with any of the implemented block ciphers.</description></item>
/// <item><description>Can use either a random seed generator for initialization, or a user supplied Seed array.</description></item>
/// <item><description>Using the same seed value will produce the same random output.</description></item>
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
class CMR : public IPrng
{
private:
	const size_t BLOCK_SIZE = 16;
	const size_t BUFFER_DEF = 4096;
	const size_t BUFFER_MIN = 64;

	std::vector<byte> m_byteBuffer;
	size_t m_bufferIndex;
	size_t m_bufferSize = 0;
	bool m_isDestroyed;
	BlockCiphers m_engineType;
	Drbg::CMG* m_rngGenerator;
	Providers m_pvdType;
	std::vector<byte>  m_stateSeed;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The random generators type name
	/// </summary>
	virtual const Prngs Enumeral() { return Prngs::CMR; }

	/// <summary>
	/// Get: The random generators class name
	/// </summary>
	virtual const std::string Name() { return "CMR"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher that powers the rng (default is RHX)</param>
	/// <param name="ProviderType">The Seed engine used to create keyng material (default is CSP)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	CMR(BlockCiphers CipherType = BlockCiphers::RHX, Providers ProviderType = Providers::CSP, size_t BufferSize = 4096)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_engineType(CipherType),
		m_isDestroyed(false),
		m_pvdType(ProviderType)
	{
		if (BufferSize < BUFFER_MIN)
			throw CryptoRandomException("CMR:Ctor", "Buffer size must be at least 64 bytes!");

		Reset();
	}

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
	/// <param name="CipherType">The block cipher that powers the rng (default is RDX)</param>
	/// <param name="BufferSize">The size of the cache of random bytes (must be more than 1024 to enable parallel processing)</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the seed is null or too small</exception>
	CMR(std::vector<byte> &Seed, BlockCiphers CipherType = BlockCiphers::RHX, size_t BufferSize = 4096)
		:
		m_bufferIndex(0),
		m_bufferSize(BufferSize),
		m_byteBuffer(BufferSize),
		m_engineType(CipherType),
		m_isDestroyed(false),
		m_stateSeed(Seed)
	{
		if (BufferSize < BUFFER_MIN)
			throw CryptoRandomException("CMR:Ctor", "Buffer size must be at least 64 bytes!");
		if (Seed.size() == 0)
			throw CryptoRandomException("CMR:Ctor", "Seed can not be null or empty!");

		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CMR()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

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
	std::vector<byte> GetBits(std::vector<byte> &Data, ulong Maximum);
	std::vector<byte> GetByteRange(ulong Maximum);
	IProvider* LoadProvider(Providers ProviderType);
};

NAMESPACE_PRNGEND
#endif