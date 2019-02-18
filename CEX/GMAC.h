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
// An implementation of a Galois/Counter Message Authentication Code generator(GMAC).
// Updated February 3, 2019
// Contact: develop@vtdev.com

#ifndef CEX_GMAC_H
#define CEX_GMAC_H

#include "BlockCiphers.h"
#include "CMUL.h"
#include "IBlockCipher.h"
#include "MacBase.h"

NAMESPACE_MAC

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Numeric::CMUL;
using Cipher::Block::IBlockCipher;

/// <summary>
/// An implementation of a Galois/Counter Message Authentication Code generator: GMAC
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// GMAC mac(BlockCiphers::AES);
/// SymmetricKey kp(Key, Nonce);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Cipher-based Message Authentication Code (GMAC), is a block-cipher based message authentication code generator. \n
/// It can use any of the block ciphers in this library to provide assurance of message authenticity and the integrity of binary data. \n
/// GMAC used in conjunction with a secure cipher mode (CTR) and is the basis of the Galois/Counter Mode (GCM). \n
/// When GMAC is used as a stand-alone MAC code generator, it is suitable for use in an Encrypt-then-MAC generic composition configuration, 
/// or as an inexpensive tag generator, but should not be used solely as a PRF for pseudo-random generation.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>H</B>=hash-key, <B>A</B>=plain-text, <B>C</B>=cipher-text, <B>m</B>=message-length, <B>n</B>=ciphertext-length, <B>||</B>=OR, <B>^</B>=XOR</para>
/// <para><EM>MAC Function</EM> \n
/// 1) for i = 1...m-1, (Xi-1 ^ Ai) * H. \n
/// 2) for i = m (Xi-1 ^ (Am || 0<sup>128-v</sup>)) * H. \n
/// 3) for i = m+1...m-1, (Xi-1 ^ Ci-m) * H. \n
/// 4) for i = m + n (Xm+n-1 ^ (Cn || 0<sup>128-u</sup>)) * H. \n
/// 5) for i = m + n + 1 (Xm+n ^ (len(A)||len(C))) * H. \n</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>MAC return size is the underlying ciphers block-size, in this library that is always 16 bytes, this length can be truncated by the caller, but that is not recommended.</description></item>
/// <item><description>The recommended Key and Nonce sizes are contained in the LegalKeySizes property.</description></item>
/// <item><description>The key size is fixed at 16 bytes, the nonce value is variable but must be at least 12 bytes in length.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize function before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code.</description>/></item>
/// <item><description>After a finalizer call the MAC should be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The GMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-GMAC Algorithm.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// </list>
/// </remarks>
class GMAC final : public MacBase
{
private:

	static const bool HAS_CMUL;
	static const size_t MINKEY_LENGTH = 16;
	static const size_t MINSALT_LENGTH = 12;

	class GmacState;
	std::unique_ptr<IBlockCipher> m_blockCipher;
	std::unique_ptr<GmacState> m_gmacState;
	bool m_isDestroyed;
	bool m_isInitialized;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	GMAC(const GMAC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	GMAC& operator=(const GMAC&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	GMAC() = delete;

	/// <summary>
	/// Initialize the class with the block cipher type enumeration name
	/// </summary>
	///
	/// <param name="CipherType">The block cipher type enumeration name</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block cipher type is selected</exception>
	explicit GMAC(BlockCiphers CipherType);

	/// <summary>
	/// Initialize this class with a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">Instance of the block cipher</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the block cipher is null</exception>
	explicit GMAC(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~GMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The block cipher engine type
	/// </summary>
	const BlockCiphers CipherType();

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	const bool IsInitialized() override;

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
	/// Completes processing and returns the MAC code in a standard vector
	/// </summary>
	///
	/// <param name="Output">The output standard vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Completes processing and returns the MAC code in a secure vector
	/// </summary>
	///
	/// <param name="Output">The output secure vector receiving the MAC code</param>
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

	//~~~Private Functions~~~//

	static void Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::unique_ptr<GmacState> &State);
	static bool HasCMUL();
	static void Multiply(std::unique_ptr<GmacState> &State, std::array<byte, CMUL::CMUL_BLOCK_SIZE> &Output);
	static void Permute(std::array<ulong, Numeric::CMUL::CMUL_STATE_SIZE> &State, std::array<byte, CMUL::CMUL_BLOCK_SIZE> &Output);
	static void PreCompute(std::unique_ptr<GmacState> &State, std::array<byte, CMUL::CMUL_BLOCK_SIZE> &Output, size_t Counter, size_t Length);
};

NAMESPACE_MACEND
#endif
