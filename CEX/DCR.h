// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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

#ifndef _CEX_DGCPRNG_H
#define _CEX_DGCPRNG_H

#include "IPrng.h"
#include "DCG.h"
#include "Digests.h"
#include "Providers.h"

NAMESPACE_PRNG

using Enumeration::Digests;
using Enumeration::Providers;

/// <summary>
/// An implementation of a Digest Counter based Random Number Generator
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// DCR rnd([Digests], [Providers], [Buffer Size]);
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the Digest Counter mode Generator (DCG) drbg implementation.</description></item>
/// <item><description>Can be initialized with any of the implemented hash digests.</description></item>
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
class DCR : public IPrng
{
private:
	const size_t BUFFER_SIZE = 1024;
	const size_t BUFFER_MIN = 64;

	size_t m_bufferIndex = 0;
	size_t m_bufferSize = 0;
	std::vector<byte> m_byteBuffer;
	Digests m_digestType;
	bool m_isDestroyed;
	Drbg::DCG* m_rngGenerator;
	Providers m_pvdType;
	std::vector<byte> m_stateSeed;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The random generators type name
	/// </summary>
	virtual const Prngs Enumeral() { return Prngs::DCR; }

	/// <summary>
	/// Get: The random generators class name
	/// </summary>
	virtual const std::string Name() { return "DCR"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="SeedEngine">The Seed engine used to create the salt (default is CSPR)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 64 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	DCR(Digests DigestEngine = Digests::Keccak512, Providers SeedEngine = Providers::CSP, size_t BufferSize = 1024);

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
	/// <param name="DigestEngine">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 64 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the seed is null or buffer size is too small; (min. seed = digest blocksize + 8)</exception>
	explicit DCR(std::vector<byte> Seed, Digests DigestEngine = Digests::Keccak512, size_t BufferSize = 1024);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~DCR();

	//~~~Public Functions~~~//

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
	virtual void GetBytes(std::vector<byte> &Output);

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
	uint GetMinimumSeedSize(Digests RngEngine);
};

NAMESPACE_PRNGEND
#endif