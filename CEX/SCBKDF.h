// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
// Updated by July 26, 2020
// Contact: develop@vtdev.com

#ifndef CEX_SCBKDF_H
#define CEX_SCBKDF_H

#include "IKdf.h"
#include "KdfBase.h"
#include "Keccak.h"
#include "ShakeModes.h"

NAMESPACE_KDF

using Digest::Keccak;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of the SHAKE Cost Based Key Derivation Function: SCBKDF
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // set to 10,000 rounds default with 1GB memory maximum
/// SCBKDF kdf(10000, 1000);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para></para>
/// 
/// <description><B>Description:</B></description> \n
/// <EM>Legend:</EM> \n
/// p=input, k=key, F=permutation, h=output, c=cpucost, m=memcost, s=state
/// <B>k</B>key, <B>p</B>=salt, <B>h</B>=output, <B>c</B>=cpu-cost, <B>m</B>=memory-cost, <B>h</B>=output, <B>s</B>= state, <B>F</B>=Permutation\n
/// <para><EM>Generate:</EM> \n
/// The function takes as parameters the key, the plain-text (p), the iterations count (c), and the memory cost (m).
/// h = SCBKDF(k, p, c, m). \n
/// for i... n \n
///		s=F(s) \n
///		if (slen < m) \n
///			s += s \n</para> 
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description></description></item>
/// <item><description></description></item>
/// <item><description></description></item>
/// <item><description></description></item>
/// </list>
/// 
/// <description><B>Guiding Publications:</B></description>
/// <list type="number">
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class SCBKDF final : public KdfBase
{
private:

	static const size_t DEFAULT_ITERATIONS = 10000;
	static const size_t MAXGEN_REQUESTS = 1024000;

	class ScbkdfState;
	std::unique_ptr<ScbkdfState> m_scbkdfState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SCBKDF(const SCBKDF&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SCBKDF& operator=(const SCBKDF&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	SCBKDF() = delete;

	/// <summary>
	/// Instantiates a SCBKDF generator
	/// </summary>
	///
	/// <param name="ShakeMode">The SHAKE base mode</param>
	/// <param name="CpuCost">The number of compression cycles used in a derivation</param>
	/// <param name="MemoryCost">The maximum amount of memory cost used by the KDF in Megabytes</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid cpu or memory cost value is used</exception>
	SCBKDF(ShakeModes ShakeMode, size_t CpuCost = 10000, size_t MemoryCost= 0);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SCBKDF() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// The number of compression cycles used to produce output; must be more than zero, 10,000 recommended
	/// </summary>
	size_t &CpuCost();

	/// <summary>
	/// The maximum amount of memory cost used by the KDF in Megabytes
	/// </summary>
	size_t &MemoryCost();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill an array with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string
	/// </summary>
	/// 
	/// <param name="Parameters">The symmetric key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key values are not a legal size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Reset the internal state; the generator must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	static void Expand(std::unique_ptr<ScbkdfState> &State);
	static void Extract(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScbkdfState> &State);
	static void Permute(std::unique_ptr<ScbkdfState> &State);
};

NAMESPACE_KDFEND
#endif
