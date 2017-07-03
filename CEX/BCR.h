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
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// An implementation of a Block cipher Counter based Generator (BCR). 
// Written by John Underhill, January 6, 2014
// Contact: develop@vtdev.com

#ifndef _CEX_BCR_H
#define _CEX_BCR_H

#include "BlockCiphers.h"
#include "BCG.h"
#include "IPrng.h"
#include "Providers.h"

NAMESPACE_PRNG

using Enumeration::BlockCiphers;
using Enumeration::Providers;

/// <summary>
/// An implementation of a Block cipher Counter mode PRNG.
/// <para>Note* as of version 1.0.0.2, the order of the Minimum and Maximum parameters on the NextIntXX api has changed, it is now with the Maximum parameter first, ex. NextInt16(max, min).</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// BCR rnd([BlockCiphers], [Providers]);
/// // get random int
/// int num = rnd.Next([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the Counter Mode Generator (BCG) drbg implementation.</description></item>
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
class BCR : public IPrng
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t BUFFER_DEF = 4096;
	static const size_t BUFFER_MIN = 64;
	static const std::string CLASS_NAME;

	size_t m_bufferIndex;
	BlockCiphers m_engineType;
	bool m_isDestroyed;
	bool m_isParallel;
	Providers m_pvdType;
	std::vector<byte>  m_rndSeed;
	Drbg::BCG* m_rngGenerator;
	std::vector<byte> m_rngBuffer;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The random generators type name
	/// </summary>
	const Prngs Enumeral() override;

	/// <summary>
	/// Get: The random generators class name
	/// </summary>
	const std::string Name() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher that powers the rng (default is AHX)</param>
	/// <param name="ProviderType">The Seed engine used to create keyng material (default is none)</param>
	/// <param name="Parallel">Run the underlying CTR mode generator in parallel mode</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	BCR(BlockCiphers CipherType = BlockCiphers::AHX, Providers ProviderType = Providers::None, bool Parallel = true);

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is key size + counter 16)</param>
	/// <param name="CipherType">The block cipher that powers the rng (default is AHX)</param>
	/// <param name="Parallel">Run the underlying CTR mode generator in parallel mode</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the seed is null or too small</exception>
	BCR(std::vector<byte> &Seed, BlockCiphers CipherType = BlockCiphers::AHX, bool Parallel = true);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~BCR() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Size">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	std::vector<byte> GetBytes(size_t Size) override;

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	void GetBytes(std::vector<byte> &Output) override;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUShort() override;

	/// <summary>
	/// Get an pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUShort(ushort Maximum) override;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUShort(ushort Maximum, ushort Minimum) override;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint Next() override;

	/// <summary>
	/// Get an pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint Next(uint Maximum) override;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint Next(uint Maximum, uint Minimum) override;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextULong() override;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextULong(ulong Maximum) override;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextULong(ulong Maximum, ulong Minimum) override;

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	void Reset() override;

private:

	std::vector<byte> GetBits(std::vector<byte> &Data, ulong Maximum);
	std::vector<byte> GetByteRange(ulong Maximum);
};

NAMESPACE_PRNGEND
#endif