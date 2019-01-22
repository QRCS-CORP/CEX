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
// 
// Implementation Details:
// An implementation of a keyed Keccak MAC function (KMAC).
// Written by John Underhill, March 2, 2018
// Contact: develop@vtdev.com

#ifndef CEX_KMAC_H
#define CEX_KMAC_H

#include "IMac.h"
#include "Digests.h"
#include "ShakeModes.h"

NAMESPACE_MAC

using Enumeration::ShakeModes;

/// <summary>
/// An implementation of the Keccak based Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Generating a MAC code</description>
/// <code>
/// KMAC mac(Enumeration::ShakeModes::AHX);
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>A keyed Keccak Message Authentication Code generator (KMAC) uses the Keccak cryptographic hash function (cSHAKE) with a secret key to verify data integrity and authenticate a message. \n
/// The cryptographic strength of KMAC depends upon the strength of the underlying cSHAKE function, the size of its hash output, and on the size and quality of the key.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The MAC output size is variable; changing the output array size will also change the code array values.</description></item>
/// <item><description>The MAC return size is derived from the size of the Output array, less the value of any offset parameter.</description></item>
/// <item><description>Block size is the underlying SHAKE functions internal block size in bytes.</description></item>
/// <item><description>Digest size is the underlying hash functions natural output code size in bytes.</description></item>
/// <item><description>The key size should be equal or greater than the digests output size, and less or equal to the block-size.</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which returns the final MAC code.</description>/></item>
/// <item><description>After a finalizer call (Finalize or Compute), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Fips-202: The <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard</a></description>.</item>
/// <item><description>SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></description></item>
/// </list>
/// </remarks>
class KMAC final : public IMac
{
private:

	static const size_t BUFFER_SIZE = 200;
	static const std::string CLASS_NAME;
	static const size_t DOMAIN_CODE = 0x04;
	static const size_t MIN_KEYSIZE = 4;
	static const size_t STATE_SIZE = 25;

	size_t m_blockSize;
	std::vector<byte> m_distCode;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::array<ulong, STATE_SIZE> m_kdfState;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_macSize;
	std::array<byte, BUFFER_SIZE> m_msgBuffer;
	size_t m_msgLength;
	ShakeModes m_shakeMode;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	KMAC(const KMAC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	KMAC& operator=(const KMAC&) = delete;

	/// <summary>
	/// Constructor: instantiate this class using the digest enumeration name
	/// </summary>
	/// 
	/// <param name="ShakeModeType">The underlying SHAKE implementation mode</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid SHAKE mode is selected</exception>
	explicit KMAC(ShakeModes ShakeModeType = ShakeModes::SHAKE256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~KMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Digests internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read/Write: Reads or Sets the personalization string value in the KDF initialization parameters, the default is 'KMAC'.
	/// <para>Must be set before <see cref="Initialize(ISymmetricKey)"/> is called.
	/// Changing this code will create a unique distribution of the generator.
	/// Code can be sized as either a zero byte array, or any length up to the DistributionCodeMax size.
	/// For best security, the distribution code should be random, secret, and equal in length to the DistributionCodeMax() size.</para>
	/// </summary>
	std::vector<byte> &DistributionCode();

	/// <summary>
	/// Read Only: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary source of entropy (secret) in the KDF key expansion phase.
	/// For best security, the distribution code should be random, secret, and equal in size to this value.</para>
	/// </summary>
	const size_t DistributionCodeMax();

	/// <summary>
	/// Read Only: Mac generators type name
	/// </summary>
	const Macs Enumeral() override;

	/// <summary>
	/// Read Only: Mac is ready to digest data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Read Only: Size of returned mac in bytes
	/// </summary>
	const size_t TagSize() override;

	/// <summary>
	/// Read Only: Mac generators class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The underlying cSHAKE security setting
	/// </summary>
	const ShakeModes ShakeMode();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array; can be any size, will create a MAC code equal to the output array size - offset</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized</exception>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array; can be any size, will create a MAC code equal to the output array size - offset</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key array to initialize the MAC.
	/// The key size should be one of the LegalKeySizes; the digests input block size is recommended.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key is not a legal size</exception>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Reset to the default state; Mac must be re-initialized after this call
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the Mac with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte to process</param>
	void Update(byte Input) override;

	/// <summary>
	/// Update the Mac with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data array to process</param>
	/// <param name="InOffset">Starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	void Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name);
	void LoadKey(const std::vector<byte> &Key);
	void Permute(std::array<ulong, 25> &State);
	void Scope();
	void Squeeze(std::array<ulong, 25> &State, std::vector<byte> &Output, size_t OutOffset, size_t Length);
};

NAMESPACE_MACEND
#endif
