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
//
// 
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
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
/// An implementation of the SHAKE-128/256/512/1024 XOF function
/// </summary> 
/// 
/// <example>
/// <description>Generate an array of pseudo random bytes:</description>
/// <code>
/// // initialize with a shake mode type
/// SHAKE kdf(ShakeModes::SHAKE128);
/// // initialize
/// kdf.Initialize(Key, [Salt], [Info]);
/// // generate bytes
/// kdf.Generate(Output, [Offset], [Size]);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The SHAKE XOF (Extended Output Function) variants use the Keccak sponge and permutation functions to generate a pseudo-random output. \n
/// Typically SHAKE has been implemented as a message digest function, as an alternative to SHA-3, but in this implementation it is used 
/// to generate keing material like a traditional KDF. \n
/// The SHAKE128 and SHAKE256 modes are standard implementations, the SHAKE512 and SHAKE1024 modes are original constructs, and should be considered experimental.</para>
/// 
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>The SHAKE512 and SHAKE1024 versions are unofficial variants, and should be considered as only for experimental use.</description></item>
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

	static const std::string CLASS_NAME;
	static const byte SHAKE_DOMAIN = 0x1F;
	static const byte CSHAKE_DOMAIN = 0x04;

	size_t m_blockSize;
	byte m_domainCode;
	size_t m_hashSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::array<ulong, 25> m_kdfState;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	ShakeModes m_shakeType;

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
	/// <param name="ShakeType">The SHAKE mode type</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if an invalid mode type is used</exception>
	explicit SHAKE(ShakeModes ShakeMode = ShakeModes::SHAKE256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHAKE() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The Keccak function-domain separator code.
	/// <para>This code differentiates Keccak function types, the default code is 0x1F (SHAKE)</para>
	/// </summary>
	byte &DomainCode();

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
	size_t MinKeySize() override;

	/// <summary>
	/// Read Only: The Kdf generators class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The absorbtion rate; input size in bytes of one block
	/// </summary>
	const size_t Rate();

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the internal state with a custom domain string.
	/// <para>Adds one permutation cycle (simplified cSHAKE). 
	/// The domain string must be set before initialization, and must be less than 196 bytes in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The custom domain string byte array</param>
	void DomainString(std::vector<byte> &Input);

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if more than 255 * HashLen bytes of output is requested</exception>
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
	/// <exception cref="Exception::CryptoKdfException">Thrown if more than 255 * HashLen bytes of output is requested</exception>
	size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key, and optional salt, and info string.
	/// <para>The use of a salt or info parameters will call the SHAKE Extract function.</para>
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(ISymmetricKey &GenParam) override;

	/// <summary>
	/// Initialize the generator with a key
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	void Initialize(const std::vector<byte> &Key) override;

	/// <summary>
	/// Initialize the generator with key and salt arrays.
	/// <para>This method initiatialzes SHAKE using the Salt array postfixed to the key array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value containing an additional source of entropy</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt) override;

	/// <summary>
	/// Initialize the generator with a key, a salt array, and an information string or nonce.
	/// <para>This method initiatialzes SHAKE using the Salt and Info arrays postfixed to the key array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value used as an additional source of entropy</param>
	/// <param name="Info">The information string which contains the domain separator code</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info) override;

	/// <summary>
	/// Update the generators keying material
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the seed is not a legal seed size</exception>
	void ReSeed(const std::vector<byte> &Seed) override;

	/// <summary>
	/// Reset the internal state; Kdf must be re-initialized before it can be used again
	/// </summary>
	void Reset() override;

private:

	template<typename Array>
	inline static void AbsorbBlock(const Array &Input, size_t InOffset, size_t Length, std::array<ulong, 25> &State)
	{
		for (size_t i = 0; i < Length / sizeof(ulong); ++i)
		{
			State[i] ^= IntUtils::LeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
		}
	}

	void FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length);
	void Expand(std::vector<byte> &Output, size_t Offset, size_t Length);
	void LoadState();
	void Permute(std::array<ulong, 25> &State);
};

NAMESPACE_KDFEND
#endif

