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
// 
// Implementation Details:
// An implementation of a cSHAKE Generator (CSG)
// Written by John Underhill, February 23, 2018
// Updated: May 14, 2018
// Updated: February 9, 2019
// Contact: develop@vtdev.com

#ifndef CEX_CSG_H
#define CEX_CSG_H

#include "DrbgBase.h"
#include "IProvider.h"
#include "Keccak.h"
#include "SHAKE.h"
#include "ShakeModes.h"

NAMESPACE_DRBG

using Digest::Keccak;
using Provider::IProvider;
using Enumeration::Providers;
using Kdf::SHAKE;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of an cSHAKE Generator DRBG: CSG
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// CSG gen(ShakeModes::SHAKE256, [Providers::ACP]);
/// // initialize
/// gen.Initialize(Key, [Nonce], [Info]);
/// // generate bytes
/// gen.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para><EM>Overview</EM> \n
/// A DRBG using the customized SHAKE XOF function cSHAKE as the primary pseudo-random generation function. \n
/// This DRBG uses an optional entropy provider to implement predictive resistance, and can optionally run in SIMD parallel mode, processing 4 or 8 blocks simutaneously using AVX2 or AVX512 instructions.
/// CSG can use any of the implemented SHAKE modes, SHAKE-128, SHAKE-256, or the experimental SHAKE-512, and SHAKE-1024 modes.
/// </para>
///
/// <para><EM>Generate</EM> \n
/// If an entropy provider is specified, the generate function employs a state counter, that will automatically trigger the addition of new seeding material to the cSHAKE instance after a user defined maximum threshold has been exceeded. \n
/// Use the ReseedThreshold parameter to tune the auto re-seed interval. \n
/// If the Parallel option is set through the constructor parameters, an SIMD parallel instance is created, this generator uses SIMD instructions to generate pseudo-random output. \n
/// If AVX2 instructions are available on the compiling machine then the generator processes four SHAKE streams simultaneously, if AVX512 instructions are available, the generator processes eight streams.
/// </para>
///
/// <description><B>Predictive Resistance:</B></description>
/// <para>Predictive and backtracking resistance prevent an attacker who has gained knowledge of generator state at some time from predicting future or previous outputs from the generator. \n
/// The optional resistance mechanism uses an entropy provider to add seed material to the generator, this new seed material is added to the current state. \n
/// The default interval at which this reseeding occurs is once for every megabyte of output generated, but can be set using the ReseedThreshold() property; once this number of bytes or greater has been generated, 
/// new seed material is added to the generator. \n 
/// Predictive resistance is strongly recommended when producing large amounts of pseudo-random (100MB or greater).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The class constructor can either be initialized with a SHAKE mode enumeration type and entropy provider instance, or using the ShakeModes and Providers enumeration names.</description></item>
/// <item><description>The provider instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The generator can be initialized with either a SymmetricKey or SymmetricSecureKey key container class, or with a Key and optional inputs of Nonce and Info.</description></item>
/// <item><description>The LegalKeySizes property contains a list of the recommended key input sizes.</description></item>
/// <item><description>Initializing with the Nonce and Info values is recommended because this pre-initializes the SHAKE state, creating an instance of cSHAKE</description></item>
/// <item><description>The Generate methods can not be used until an Initialize function has been called and the generator is seeded.</description></item>
/// <item><description>The Update method adds new seeding material to the SHAKE state, this can be done automatically by specifying a random provider, or manually through this function.</description></item>
/// <item><description>The maximum amount of pseudo-random data that can be requested from the generator in a single call is fixed at 100 megabytes.</description></item>
/// <item><description>The maximum output from a generator instance before it must be re-initialized with a new key is fixed at 10 Gigabytes.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Fips-202: The <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard</a></description>.</item>
/// <item><description>SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class CSG final : public DrbgBase
{
private:

	// the buffer size in bytes
	static const size_t BUFFER_SIZE = Keccak::KECCAK_STATE_SIZE * sizeof(ulong);
	// 100mb: default before reseeded internally
	static const size_t DEF_RESEED = 102400000;
	// 10gb: maximum before rekey is required
	static const ulong MAX_OUTPUT = 10240000000;
	// 100mb: maximum size of a single request
	static const size_t MAX_REQUEST = 102400000;
	// 1024: maximum reseed calls before exception
	static const size_t MAX_THRESHOLD = 1024;
	// the minimum key length that will initialize the generator
	static const size_t MINKEY_LENGTH = 16;

	class CsgState;
	std::unique_ptr<IProvider> m_csgProvider;
	std::unique_ptr<CsgState> m_csgState;
	bool m_isDestroyed;
	bool m_isInitialized;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CSG(const CSG&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CSG& operator=(const CSG&) = delete;

	/// <summary>
	/// Default constructor: default constructor is restricted, this function has been deleted
	/// </summary>
	CSG() = delete;

	/// <summary>
	/// Instantiate the class using a SHAKE mode, and an optional entropy source type names
	/// </summary>
	///
	/// <param name="ShakeModeType">The underlying SHAKE implementation mode type</param>
	/// <param name="ProviderType">The enumeration type name of an entropy source enabling predictive resistance, the default is ACP</param>
	/// <param name="Parallel">If supported, enables vectorized multi-lane generation using the highest supported instruction set AVX512/AVX2</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if an unrecognized digest type name is used</exception>
	explicit CSG(ShakeModes ShakeModeType, Providers ProviderType = Providers::ACP, bool Parallel = false);

	/// <summary>
	/// Instantiate the class using a SHAKE mode type, and an optional instance pointer to an entropy source 
	/// </summary>
	/// 
	/// <param name="ShakeModeType">The underlying shake implementation mode type</param>
	/// <param name="Provider">Provides an entropy source enabling predictive resistance, can be null</param>
	/// <param name="Parallel">If supported, enables vectorized multi-lane generation using the highest supported instruction set AVX512/AVX2</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if a null digest is used</exception>
	CSG(ShakeModes ShakeModeType, IProvider* Provider, bool Parallel = false);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CSG() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The generator has AVX2 or AVX512 instructions and can process in multi-lane generation mode
	/// </summary>
	static const bool HasMultiLane();

	/// <summary>
	/// Read Only: Generator is ready to produce random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: The number of available SIMD lanes
	/// </summary>
	static const size_t LaneCount();

	/// <summary>
	/// Read/Write: The maximum output generated between auto-seed generation when using an entropy provider
	/// </summary>
	size_t &ReseedThreshold() override;

	/// <summary>
	/// Read Only: The estimated classical security strength in bits
	/// </summary>
	const size_t SecurityStrength() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	void Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional nonce, and info string
	/// </summary>
	/// 
	/// <param name="Parameters">The ISymmetricKey key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is not a legal-key size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Update the generators keying material with a standard-vector key
	/// </summary>
	///
	/// <param name="Key">The standard-vector containing the new key material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is too small</exception>
	void Update(const std::vector<byte> &Key) override;

	/// <summary>
	/// Update the generators keying material with a secure-vector key
	/// </summary>
	///
	/// <param name="Key">The secure-vector containing the new key material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is too small</exception>
	void Update(const SecureVector<byte> &Key) override;

private:

	static void Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::unique_ptr<CsgState> &State);
	static void Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name, std::unique_ptr<CsgState> &State);
	static void Derive(std::unique_ptr<IProvider> &Provider, std::unique_ptr<CsgState> &State);
	static void Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<CsgState> &State);
	static void Fill(std::unique_ptr<CsgState> &State);
	static void Permute(std::unique_ptr<CsgState> &State);
	static void PermuteW(std::unique_ptr<CsgState> &State);
	static void Reset(std::unique_ptr<CsgState> &State);
};

NAMESPACE_DRBGEND
#endif
