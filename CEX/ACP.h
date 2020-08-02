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
// Updated by January 28, 2019
// Contact: develop@vtdev.com

#ifndef CEX_ACP_H
#define CEX_ACP_H

#include "SHAKE.h"
#include "ProviderBase.h"

NAMESPACE_PROVIDER

using Kdf::SHAKE;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of an Auto Collection seed Provider
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std::vector&lt;byte&gt; output(32);
/// ACP gen;
/// gen.Generate(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>The Auto Collection Provider is a two stage entropy provider; it first collects system sources of entropy, and then uses them to initialize a cSHAKE pseudo-random generator. \n 
/// The first stage combines RdRand, cpu/memory jitter, and the system random provider, with high resolution timers and statistics for various hardware devices and system operations. \n
/// These sources of entropy are compressed and used to create the cSHAKE-512 XOF functions key and customization arrays.
/// </para>
/// 
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>ANSI <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/rng/EntropySources.pdf">X9.82: </a>Entropy and Entropy Sources in X9.82.</description></item>
/// </list> 
/// </remarks>
class ACP final : public ProviderBase
{
private:

	static const size_t DEF_STATECAP = 1024;
	static const bool HAS_RDRAND;
	static const ShakeModes SHAKE_MODE = ShakeModes::SHAKE512;
	static const bool HAS_TSC;

#if defined(CEX_FIPS140_ENABLED)
	std::unique_ptr<ProviderSelfTest> m_pvdSelfTest;
#endif
	std::unique_ptr<SHAKE> m_rngGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ACP(const ACP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ACP& operator=(const ACP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	ACP();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ACP() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
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
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
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
	/// Reset the internal state
	/// </summary>
	/// 
	/// <exception cref="CryptoRandomException">Thrown on entropy collection failure</exception>
	void Reset() override;

private:

	bool FipsTest();
	static std::vector<byte> Collect();
	static std::vector<byte> Compress(std::vector<byte> &State);
	static void Filter(std::vector<byte> &State);
	static void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<SHAKE> &Generator);
	static std::vector<byte> MemoryInfo();
	static std::vector<byte> ProcessInfo();
	static std::vector<byte> SystemInfo();
	static std::vector<byte> TimeInfo();
};

NAMESPACE_PROVIDEREND
#endif
