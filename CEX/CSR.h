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

#include "PrngBase.h"
#include "IDrbg.h"
#include "Providers.h"
#include "ShakeModes.h"

NAMESPACE_PRNG

using Drbg::IDrbg;
using Enumeration::Providers;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of an cSHAKE based PRNG.
/// <para>Uses a keyed instance of cSHAKE to generate pseudo-random output..</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of generating a pseudo-random integer:</description>
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
/// <item><description>Can be initialized with any of the implemented cSHAKE pseudo-random generators.</description></item>
/// <item><description>Uses an internal entropy provider to seed the underlying DRBG.</description></item>
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
class CSR final : public PrngBase
{
private:

	static const size_t BUFFER_SIZE = 1024;
	static const size_t MIN_BUFLEN = 168;
	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	Providers m_pvdType;
	std::unique_ptr<IDrbg> m_rngGenerator;
	ShakeModes m_shakeModeType;

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
	/// <param name="ShakeModeType">The underlying SHAKE instance type; default is SHAKE512</param>
	/// <param name="ProviderType">The random provider used to create keyng material; default is ACP</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the shake or provider type is invalid</exception>
	CSR(ShakeModes ShakeModeType = ShakeModes::SHAKE512, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CSR() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The random generators implementation name
	/// </summary>
	const std::string Name() override;

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
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the output array is too small</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	//// 
	/// <exception cref="CryptoRandomException">Thrown if the output array is too small</exception>
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
