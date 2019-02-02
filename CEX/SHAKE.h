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

#ifndef CEX_SHAKE_H
#define CEX_SHAKE_H

#include "Digests.h"
#include "IDigest.h"
#include "KdfBase.h"
#include "ShakeModes.h"

NAMESPACE_KDF

using Enumeration::Digests;
using Digest::IDigest;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of the SHAKE and cSHAKE 128/256/512/1024 XOF functions
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo-random bytes:</description>
/// <code>
/// // initialize with a 256bit shake mode-rate
/// SHAKE kdf(ShakeModes::SHAKE256);
/// // initialize with a key for shake, or use salt and info for cshake
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The SHAKE/cSHAKE family of XOF (Extended Output Function) functions use the Keccak sponge and permutation functions to generate a pseudo-random output. \n
/// Typically SHAKE has been implemented as a message digest function, as an alternative to SHA-3, but in this implementation it is used to generate keying material like a traditional KDF. \n
/// The cSHAKE/SHAKE 128 and 256 bit modes are standard implementations, the SHAKE512 and SHAKE1024 modes are original constructs, and should be considered experimental.</para>
/// 
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>The SHAKE512 and SHAKE1024 versions are unofficial variants, and should be considered as only for experimental use.</description></item>
/// <item><description>Initialize the Kdf using only a key for SHAKE, or use salt and info secret-keys to enable the custom [cSHAKE] variant of the function.</description></item>
/// <item><description>This class can be instantiated with a SHAKE mode type name (SHAKE128/256/512/1024), the default is SHAKE256.</description></item>
/// <item><description>The SHAKE128 and SHAKE256 modes are standard implementations, the SHAKE512 and SHAKE1024 variants are original extensions.</description></item>
/// <item><description>The generator must be initialized with a key using one of the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize() function can use a SymmetricKey or SymmetricSecureKey key container class, or input arrays of Key, and optional Customization and Information vectors.</description></item>
/// <item><description>Initializing with customization or information parameters will create a custom distribtion of the generator by pre-initalizing the state to unique values, this is recommnded.</description></item>
/// <item><description>The recommended total Key size is the digests internal rate-size in bytes; the minumum recommended key size is the permutations output size (SHAKE128=16, SHAKE256=32, SHAKE512=64, SHAKE1024=128 bytes.</description></item>
/// <item><description>The internal block sizes (the amount of input that triggers the permutation function) in bytes are: SHAKE128=168, SHAKE256=136, with SHAKE512 and SHAKE1024 both using 72 bytes.</description></item>
/// <item><description>The CEX_KECCAK_STRONG macro contained in the CexConfig file halves the input rate of SHAKE-1024 to 288-bits (36 bytes), to create an optionally more diffused output.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class SHAKE final : public KdfBase
{
private:

	static const size_t BUFFER_SIZE = 200;
	static const byte CSHAKE_DOMAIN = 0x04;
	static const size_t MAXGEN_REQUESTS = 1024000;
#if defined(CEX_ENFORCE_KEYMIN)

#else

#endif
	static const size_t MINKEY_LENGTH = 4;
	static const size_t MINSALT_LENGTH = 4;
	static const byte SHAKE_DOMAIN = 0x1F;
	static const size_t STATE_SIZE = 25;

	class ShakeState;
	bool m_isInitialized;
	std::unique_ptr<ShakeState> m_shakeState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SHAKE(const SHAKE&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SHAKE& operator=(const SHAKE&) = delete;

	/// <summary>
	/// Instantiates a SHAKE generator using a shake mode type name.
	/// <para>The default is the SHAKE256 mode.</para>
	/// </summary>
	/// 
	/// <param name="ShakeModeType">The SHAKE security mode type</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid mode type is used</exception>
	explicit SHAKE(ShakeModes ShakeModeType = ShakeModes::SHAKE256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHAKE() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random output
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: The estimated security level in bits of the selected SHAKE mode
	/// </summary>
	const size_t SecurityLevel();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a secure vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a secure vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional customization, and information strings
	/// </summary>
	/// 
	/// <param name="KeyParams">The symmetric key container containing the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key values are not a legal size</exception>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Initialize the SHAKE generator with a standard vector key
	/// </summary>
	/// 
	/// <param name="Key">The standard vector key used to initialize the generator</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is illegaly sized</exception>
	void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the SHAKE generator with a secure vector key
	/// </summary>
	/// 
	/// <param name="Key">The secure vector key used to initialize the generator</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is illegaly sized</exception>
	void Initialize(const SecureVector<byte> &Key);

	/// <summary>
	/// Initialize the SHAKE generator with a standard vector key, using length and offset parameters
	/// </summary>
	/// 
	/// <param name="Key">The standard vector key used to initialize the generator</param>
	/// <param name="Offset">The starting position within the key vector</param>
	/// <param name="Length">The number of key bytes to use</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	void Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length);

	/// <summary>
	/// Initialize the SHAKE generator with a secure vector key, using length and offset parameters
	/// </summary>
	/// 
	/// <param name="Key">The secure vector key used to initialize the generator</param>
	/// <param name="Offset">The starting position within the key vector</param>
	/// <param name="Length">The number of key bytes to use</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	void Initialize(const SecureVector<byte> &Key, size_t Offset, size_t Length);

	/// <summary>
	/// Initialize the SHAKE generator with standard vector key and customization arrays.
	/// <para>This method initiatializes cSHAKE using the Customization vector as the pre-initialization parameter.</para>
	/// </summary>
	/// 
	/// <param name="Key">The standard vector key used to initialize the generator</param>
	/// <param name="Customization">The customization standard vector used to create a unique generator output</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if either the key or customization array is illegaly sized</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization);

	/// <summary>
	/// Initialize the SHAKE generator with secure vector key and customization arrays.
	/// <para>This method initiatializes cSHAKE using the Customization vector as the pre-initialization parameter.</para>
	/// </summary>
	/// 
	/// <param name="Key">The secure vector key used to initialize the generator</param>
	/// <param name="Customization">The customization secure vector used to create a unique generator output</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if either the key or customization array is illegaly sized</exception>
	void Initialize(const SecureVector<byte> &Key, const SecureVector<byte> &Customization);

	/// <summary>
	/// Initialize the cSHAKE generator with key, customization, and name standard vectors.
	/// <para>This method initiatializes cSHAKE using the Customization and Name vectors as the pre-initialization parameters.</para>
	/// </summary>
	/// 
	/// <param name="Key">The standard vector key used to initialize the generator</param>
	/// <param name="Customization">The customization standard vector used to create a unique generator output</param>
	/// <param name="Information">The information customization standard vector</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if either the key, customization, or name array is illegaly sized</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Customization, const std::vector<byte> &Information);

	/// <summary>
	/// Initialize the cSHAKE generator with key, customization, and information secure vectors.
	/// <para>This method initiatializes cSHAKE using the Customization and Information vectors as the pre-initialization parameters.</para>
	/// </summary>
	/// 
	/// <param name="Key">The secure vector key used to initialize the generator</param>
	/// <param name="Customization">The secure vector customization used to create a unique generator output</param>
	/// <param name="Information">The information customization secure vector</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if either the key, customization, or name array is illegaly sized</exception>
	void Initialize(const SecureVector<byte> &Key, const SecureVector<byte> &Customization, const SecureVector<byte> &Information);

	/// <summary>
	/// Reset the internal state; SHAKE must be initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	static void Customize(const std::vector<byte> &Customization, const std::vector<byte> &Information, std::unique_ptr<ShakeState> &State);
	static void Expand(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<ShakeState> &State);
	static void Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ShakeState> &State);
	static void FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::unique_ptr<ShakeState> &State);
	static void Permute(std::unique_ptr<ShakeState> &State);
};

NAMESPACE_KDFEND
#endif

