// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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

#ifndef CEX_CSR_H
#define CEX_CSR_H

#include "IPrng.h"
#include "CSG.h"
#include "Providers.h"

NAMESPACE_PRNG

using Enumeration::ShakeModes;
using Enumeration::Providers;

/// <summary>
/// An implementation of an cSHAKE based PRNG.
/// <para>Note* as of version 1.0.0.2, the order of the Minimum and Maximum parameters on the NextIntXX api has changed, it is now with the Maximum parameter first, ex. NextInt16(max, min).</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// CSR rnd([ShakeModes], [Providers], [Buffer Size]);
/// int num = rnd.NextUInt32([Minimum], [Maximum]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the cSHAKE Generator (CSG) drbg implementation.</description></item>
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
class CSR final : public IPrng
{
private:
	static const size_t BUFFER_SIZE = 1024;
	static const size_t MIN_BUFLEN = 168;
	static const std::string CLASS_NAME;

	size_t m_bufferIndex;
	bool m_isDestroyed;
	Providers m_pvdType;
	std::vector<byte> m_rndSeed;
	std::vector<byte> m_rngBuffer;
	std::unique_ptr<Drbg::CSG> m_rngGenerator;
	ShakeModes m_shakeType;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CSR(const CSR&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CSR& operator=(const CSR&) = delete;

	/// <summary>
	/// Initialize the class with parameters
	/// </summary>
	/// 
	/// <param name="ShakeModeType">The underlying SHAKE instance type</param>
	/// <param name="SeedEngine">The random provider used to seed the rng</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 64 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the buffer size is too small (min. 64)</exception>
	explicit CSR(ShakeModes ShakeModeType = ShakeModes::SHAKE256, Providers SeedEngine = Providers::ACP, size_t BufferSize = 1024);

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
	/// <param name="ShakeModeType">The underlying SHAKE instance type</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 64 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the seed is null or buffer size is too small; (min. seed = digest blocksize + 8)</exception>
	explicit CSR(std::vector<byte> Seed, ShakeModes ShakeModeType = ShakeModes::SHAKE256, size_t BufferSize = 1024);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CSR() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The random generators type name
	/// </summary>
	const Prngs Enumeral() override;

	/// <summary>
	/// Read Only: The random generators implementation name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	std::vector<byte> Generate(size_t Length) override;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16() override;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint NextUInt32() override;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextUInt64() override;

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	void Reset() override;
};

NAMESPACE_PRNGEND
#endif
