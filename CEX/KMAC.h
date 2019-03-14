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
// An implementation of a keyed Keccak MAC function (KMAC).
// Written by John G. Underhill, March 2, 2018
// Updated February 6, 2018
// Contact: develop@vtdev.com

#ifndef CEX_KMAC_H
#define CEX_KMAC_H

#include "MacBase.h"
#include "Digests.h"
#include "KmacModes.h"

NAMESPACE_MAC

using Enumeration::KmacModes;

/// <summary>
/// An implementation of the Keccak based Message Authentication Code generator: KMAC
/// </summary>
/// 
/// <example>
/// <description>Generating a MAC code</description>
/// <code>
/// KMAC mac(Enumeration::KmacModes::KMAC256);
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>A keyed Keccak Message Authentication Code generator (KMAC) that uses the Keccak cryptographic permutation function with a secret key to verify data integrity and authenticate a message. \n
/// The cryptographic strength of KMAC depends upon the strength of the rate setting of the underlying permutation function, the size of its hash output, and on the size and quality of the key. \n
/// The minimum key size should align with the expected security level of the generator function. \n
/// For example, KMAC256 should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_LEGALKEY definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The MAC tag size is variable; changing the KmacMode will change the size of the MAC output, the selected length is stored in the TagSize accessor property.</description></item>
/// <item><description>Block size is the underlying Keccak permutation functions internal rate-size in bytes.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize function before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>The key size should be at least equal to the initialized MAC variants security size; 128/256/512/1024 (16/32/64/128 bytes).</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code.</description>/></item>
/// <item><description>After a finalizer call the MAC should be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Fips-202: The <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard</a></description>.</item>
/// <item><description>SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></description></item>
/// </list>
/// </remarks>
class KMAC final : public MacBase
{
private:

	static const size_t BUFFER_SIZE = 200;
	static const size_t DOMAIN_CODE = 0x04;
	static const size_t MINKEY_LENGTH = 16;
	static const size_t MINSALT_LENGTH = 4;
	static const size_t STATE_SIZE = 25;

	class KmacState;
	bool m_isInitialized;
	std::unique_ptr<KmacState> m_kmacState;

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
	/// Constructor: instantiate this class using the KMAC type enumeration name
	/// </summary>
	/// 
	/// <param name="KmacModeType">The underlying KMAC type implementation mode</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid KMAC mode is selected</exception>
	explicit KMAC(KmacModes KmacModeType = KmacModes::KMAC256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~KMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary source of entropy (secret) in the KDF key expansion phase.
	/// For best security, the distribution code should be random, secret, and equal in size to this value.</para>
	/// </summary>
	const size_t DistributionCodeMax();

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: The underlying KMAC mode setting
	/// </summary>
	const KmacModes KmacMode();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process a vector of bytes and return the MAC code
	/// </summary>
	///
	/// <param name="Input">The input vector to process</param>
	/// <param name="Output">The output vector containing the MAC code</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Completes processing and returns the MAC code in a standard-vector
	/// </summary>
	///
	/// <param name="Output">The output standard-vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Completes processing and returns the MAC code in a secure-vector
	/// </summary>
	///
	/// <param name="Output">The output secure-vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(SecureVector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with an ISymmetricKey key container.
	/// <para>Can accept either the SymmetricKey or SymmetricSecureKey container to load keying material.
	/// Uses a key, salt, and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="Parameters">An ISymmetricKey key interface, which can accept either a SymmetricKey or SymmetricSecureKey container</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the key is not a legal size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Reset internal state to the pre-initialization defaults.
	/// <para>Internal state is zeroised, and MAC generator must be reinitialized again before being used.</para>
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the Mac with a length of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data vector to process</param>
	/// <param name="InOffset">The starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the input array is too small</exception>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	static void Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name, std::unique_ptr<KmacState> &State);
	static void LoadKey(const std::vector<byte> &Key, std::unique_ptr<KmacState> &State);
	static void Permute(std::unique_ptr<KmacState> &State);
	static void Squeeze(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<KmacState> &State);
};

NAMESPACE_MACEND
#endif
