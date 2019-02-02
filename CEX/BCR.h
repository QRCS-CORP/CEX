// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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
// Updated by January 28, 2019
// Contact: develop@vtdev.com

#ifndef CEX_BCR_H
#define CEX_BCR_H

#include "PrngBase.h"
#include "BlockCiphers.h"
#include "IDrbg.h"
#include "Providers.h"

NAMESPACE_PRNG

using Enumeration::BlockCiphers;
using Drbg::IDrbg;
using Enumeration::Providers;

/// <summary>
/// An implementation of a Block cipher Counter mode PRNG.
/// <para>Uses a keyed block cipher run in counter mode to generate pseudo-random output..</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo-random integer:</description>
/// <code>
/// BCR rnd([BlockCiphers], [Providers]);
/// // get random int
/// int num = rnd.NextUInt32([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the Counter Mode Generator (BCG) DRBG implementation.</description></item>
/// <item><description>Can be initialized with any of the implemented block-ciphers run in CTR mode.</description></item>
/// <item><description>Uses an internal entropy provider to seed the underlying DRBG.</description></item>
/// <item><description>The underlying DRBG instance can be optionally multi-threaded through the constructors Parallel parameter.</description></item>
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
class BCR final : public PrngBase
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t BUFFER_DEF = 4096;
	static const size_t BUFFER_MIN = 64;

	bool m_isDestroyed;
	bool m_isParallel;
	Providers m_pvdType;
	std::unique_ptr<IDrbg> m_rngGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	BCR(const BCR&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	BCR& operator=(const BCR&) = delete;

	/// <summary>
	/// Initialize this class with parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher that powers the rng; default is RHX</param>
	/// <param name="ProviderType">The random provider used to create keyng material; default is ACP</param>
	/// <param name="Parallel">Run the underlying CTR mode generator in parallel mode; default is sequential operation</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the cipher or provider type is invalid</exception>
	BCR(BlockCiphers CipherType = BlockCiphers::AES, Providers ProviderType = Providers::ACP, bool Parallel = false);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~BCR() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider can not be instantiated</exception>
	void Reset() override;

private:

	static void GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator);
	static void GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IDrbg> &Generator);
};

NAMESPACE_PRNGEND
#endif
