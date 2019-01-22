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
//
// Implementation Details:
// An implementation of an Hash based Key Derivation Function (SHAKE). 
// Written by John Underhill, December 12, 2017

#ifndef CEX_SHAKE_H
#define CEX_SHAKE_H

#include "IKdf.h"
#include "Digests.h"
#include "IDigest.h"
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
/// <description>Generate an array of pseudo random bytes:</description>
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
/// Typically SHAKE has been implemented as a message digest function, as an alternative to SHA-3, but in this implementation it is used 
/// to generate keying material like a traditional KDF. \n
/// The cSHAKE/SHAKE 128 and 256 bit modes are standard implementations, the SHAKE512 and SHAKE1024 modes are original constructs, and should be considered experimental.</para>
/// 
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>The SHAKE512 and SHAKE1024 versions are unofficial variants, and should be considered as only for experimental use.</description></item>
/// <item><description>Initialize the Kdf using only a key for SHAKE, or use salt and info secret-keys to enable the custom [cSHAKE] variant of the function.</description></item>
/// <item><description>This class can be instantiated with a Keccak mode type name (SHAKE128/256/512/1024), the default is SHAKE256.</description></item>
/// <item><description>The SHAKE128 and SHAKE256 modes are standard implementations, the SHAKE512 and SHAKE1024 variants are original extensions.</description></item>
/// <item><description>The generator must be initialized with a key using one of the Initialize() functions before output can be generated.</description></item>
/// <item><description>The Initialize() function can use a SymmetricKey key container class, or input arrays of Key, and optional Salt and Info.</description></item>
/// <item><description>Initializing with a salt or info parameters will append those values to the Key.</description></item>
/// <item><description>The recommended total Key size is the digests internal block-size in bytes; the minumum key size is half of the digests blocksize.</description></item>
/// <item><description>The internal block sizes in bytes are: SHAKE128 =168, SHAKE256 =136, with SHAKE512 and SHAKE1024 both using 72 bytes.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class SHAKE final : public IKdf
{
private:

	static const size_t BUFFER_SIZE = 200;
	static const std::string CLASS_NAME;
	static const byte CSHAKE_DOMAIN = 0x04;
	static const size_t MIN_KEYLEN = 4;
	static const byte SHAKE_DOMAIN = 0x1F;
	static const size_t STATE_SIZE = 25;

	size_t m_blockSize;
	byte m_domainCode;
	size_t m_hashSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::array<ulong, STATE_SIZE> m_kdfState;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	ShakeModes m_shakeMode;

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
	/// Instantiates a SHAKE generator using a message digest type name.
	/// <para>The default is the SHAKE256 mode.</para>
	/// </summary>
	/// 
	/// <param name="ShakeModeType">The SHAKE mode type</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if an invalid mode type is used</exception>
	explicit SHAKE(ShakeModes ShakeModeType = ShakeModes::SHAKE256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHAKE() override;

	//~~~Accessors~~~//

	/// <summary>
	/// The internal block size in bytes
	/// </summary>
	const size_t BlockSize();

	/// <summary>
	/// Read Only: The Kdf generators type name
	/// </summary>
	const Kdfs Enumeral() override;

	/// <summary>
	/// Read Only: Generator is ready to produce random
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Available Kdf Key Sizes in bytes
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Minimum recommended initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info should be at least this size.</para>
	/// </summary>
	const size_t MinKeySize() override;

	/// <summary>
	/// Read Only: The Kdf generators class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The absorbtion rate; input size in bytes of one block
	/// </summary>
	const size_t SecurityLevel();

	//~~~Public Functions~~~//

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	size_t Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional salt, and info string.
	/// <para>The use of a salt or info parameters will call the SHAKE Extract function.</para>
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(ISymmetricKey &GenParam) override;

	/// <summary>
	/// Initialize the SHAKE generator with a key, using length and offset arguments
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Offset">The starting position within the key array</param>
	/// <param name="Length">The number of key bytes to use</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length) override;

	/// <summary>
	/// Initialize the SHAKE generator with a key
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(const std::vector<byte> &Key) override;

	/// <summary>
	/// Initialize the cSHAKE generator with key and salt arrays.
	/// <para>This method initiatialzes cSHAKE using the Salt array as the customization parameter.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value used as a customization string</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt) override;

	/// <summary>
	/// Initialize the cSHAKE generator with a key, a salt array, and an information string.
	/// <para>This method initiatialzes cSHAKE using the Salt array as the customization parameter, and the Info as the name parameter.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt array used as a customization string</param>
	/// <param name="Info">The Info array used as a name string</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info) override;

	/// <summary>
	/// Update the generators keying material
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void ReSeed(const std::vector<byte> &Seed) override;

	/// <summary>
	/// Reset the internal state; Kdf must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	void Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name);
	void Expand(std::vector<byte> &Output, size_t Offset, size_t Length);
	void FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length);
	void LoadState();
	void Permute(std::array<ulong, STATE_SIZE> &State);
};

NAMESPACE_KDFEND
#endif

