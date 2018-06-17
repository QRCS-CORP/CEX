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

#ifndef CEX_PBR_H
#define CEX_PBR_H

#include "IPrng.h"
#include "Digests.h"
#include "PBKDF2.h"

NAMESPACE_PRNG

using Enumeration::Digests;

/// <summary>
/// An implementation of a Passphrase Based PRNG.
/// <para>Note* as of version 1.0.0.2, the order of the Minimum and Maximum parameters on the NextIntXX api has changed, it is now with the Maximum parameter first, ex. NextInt16(max, min).</para>
/// </summary>
/// 
/// <example>
/// <description>Example of generating a pseudo random integer:</description>
/// <code>
/// PBPRng rnd(new SHA512(), PassPhrase, Salt);
/// int x = rnd.NextUInt32();
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Wraps the PBKDF2 key derivation implementation.</description></item>
/// <item><description>Can be initialized with any of the implemented hash digests.</description></item>
/// <item><description>Can use either a random seed generator for initialization, or a user supplied seed array.</description></item>
/// <item><description>Numbers generated with the same seed will produce the same random output.</description></item>
/// </list>
/// 
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
class PBR final : public IPrng
{
private:

	static const std::string CLASS_NAME;
	static const size_t MIN_BUFLEN = 64;

	size_t m_bufferIndex;
	size_t m_bufferSize;
	size_t m_digestIterations;
	Digests m_digestType;
	bool m_isDestroyed;
	std::vector<byte> m_rndSeed;
	std::vector<byte> m_rngBuffer;
	std::unique_ptr<Kdf::PBKDF2> m_rngGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	PBR() = delete;

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	PBR(const PBR&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	PBR& operator=(const PBR&) = delete;

	/// <summary>
	/// Initialize the class with a Seed; note: the same seed will produce the same random output
	/// </summary>
	/// 
	/// <param name="Seed">The Seed bytes used to initialize the digest counter; (min. length is digest blocksize + 8)</param>
	/// <param name="Iterations">The number of transformation iterations performed by the digest with PBKDF2 (default is 10,000)</param>
	/// <param name="DigestType">The digest that powers the rng (default is Keccak512)</param>
	/// <param name="BufferSize">The size of the internal state buffer in bytes; must be at least 128 bytes size (default is 1024)</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the seed or buffer size is too small; (min. seed = 2* digest hash size, min. buffer 64 bytes)</exception>
	explicit PBR(std::vector<byte> &Seed, int Iterations = 5000, Digests DigestType = Digests::SHA512, size_t BufferSize = 1024);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~PBR() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The random generators type name
	/// </summary>
	const Prngs Enumeral() override;

	/// <summary>
	/// Read Only: The random generators class name
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

private:

	uint GetMinimumSeedSize(Digests RngEngine);
};

NAMESPACE_PRNGEND
#endif
