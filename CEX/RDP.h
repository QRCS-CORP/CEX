// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
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
// Contact: develop@qscs.ca

#ifndef CEX_RDP_H
#define CEX_RDP_H

#include "ProviderBase.h"
#include "DrandEngines.h"

NAMESPACE_PROVIDER

using Enumeration::DrandEngines;

/// <summary>
/// An implementation of the Intel RDRAND digital random number generator
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std::vector&lt;uint8_t&gt; output(32);
/// RDP gen;
/// gen.Generate(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>The RDRAND DRNG uses thermal noise to generate random bits that are buffered into a shift register, then fed into a CBC-MAC to condition the bytes.
/// The output from the CBC-MAC is obtained using the RDSEED api. \n
/// To accommodate large sampling, the system has a built in CTR_DRBG, (as specified in SP800-90), which is continuously reseeded with the output from RDSEED.
/// The output from the CTR Drbg is obtained using the RDRAND api. \n
/// There is some controversy surrounding the security of this mechanism, though the design appears to be sound, and has been reviewed by external auditors, 
/// it is still a proprietary closed system. \n
/// The entropy source itself must therefore be considered to be a 'black box', a source that can not be verified directly, and so must be considered to be of low entropy value. \n
/// For this reason, the DRNG should not be used as the sole source of entropy when creating secret keys, but should be used in concert with other sources of entropy, such as the auto-seed collection provider ACP.</para>
/// 
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description>Intel Digital Random Number Digital Random Number Generator: <a href="https://software.intel.com/sites/default/files/m/d/4/1/d/8/441_Intel_R__DRNG_Software_Implementation_Guide_final_Aug7.pdf">DRNG</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>ANSI <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/rng/EntropySources.pdf">X9.82: </a>Entropy and Entropy Sources in X9.82.</description></item>
/// <item><description>A Provable Security Analysis of Intel's <a href="http://terashima.us/rdrand-ec2015.pdf">Secure Key RNG</a>.</description></item>
/// </list> 
/// </remarks>
class RDP final : public ProviderBase
{
private:

	// the number of times to read from the RDRAND/RDSEED RNGs; each read generates 32 bits of output
	static const size_t RNG_POLLS = 32;
	// RDRAND is guaranteed to generate a random number within 10 retries on a working CPU
	static const size_t RDR_RETRY = 10;
	// RdSeed is not guaranteed to generate a random number within a specific number of retries
	static const size_t RDS_RETRY = 1000;
	static const size_t SEED_MAX = 64 * 1000 * 1000;
	static const size_t RDR_SUCCESS = 1;

#if defined(CEX_FIPS140_ENABLED)
	std::unique_ptr<ProviderSelfTest> m_pvdSelfTest;
#endif
	DrandEngines m_randType;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RDP(const RDP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RDP& operator=(const RDP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class with parameters
	/// </summary>
	///
	/// <param name="DrandType">The providers random output engine configuration type; RdRand (post processed by CTR_DRBG), or RdSeed (conditioned seed value)</param>
	RDP(DrandEngines DrandType = DrandEngines::RdRand);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~RDP() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<uint8_t> &Output) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<uint8_t> &Output) override;

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset() override;

private:

	static DrandEngines Capability();
	bool FipsTest();
	static void Generate(uint8_t* Output, size_t Length, DrandEngines DrandType);
};

NAMESPACE_PROVIDEREND
#endif
