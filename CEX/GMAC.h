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
// Implementation Details:
// An implementation of a Galois/Counter Message Authentication Code generator(GMAC).
// Written by John Underhill, February 14, 2017
// Contact: develop@vtdev.com

#ifndef CEX_GMAC_H
#define CEX_GMAC_H

#include "BlockCiphers.h"
#include "GHASH.h"
#include "IBlockCipher.h"
#include "IMac.h"

NAMESPACE_MAC

using Enumeration::BlockCiphers;
using Cipher::Symmetric::Block::IBlockCipher;

/// <summary>
/// An implementation of a Galois/Counter Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// GMAC mac(Enumeration::BlockCiphers::AHX);
/// SymmetricKey kp(Key, Nonce);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Cipher-based Message Authentication Code (GMAC), is a block-cipher based message authentication code algorithm. \n
/// It can use any of the block ciphers in this library to provide assurance of message authenticity and the integrity of binary data.
/// GMAC used in conjunction with a secure cipher mode (CTR) is the basis of the Galois/Counter Mode (GCM). \n
/// When GCM is used as a stand-alone MAC code generator, it is suitable for use in an Encrypt-then-MAC generic composition configuration, 
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
/// <item><description>MAC return size is the underlying ciphers block-size; e.g. for AES, 16 bytes, and can be truncated by the caller.</description></item>
/// <item><description>With the Initialize(ISymmetricKey) method, use the symmetric-key's Key parameter as the cipher key, and the Nonce parameter as the initialization vector.</description></item>
/// <item><description>The recommended Key and Nonce sizes are contained in the LegalKeySizes property.</description></item>
/// <item><description>The Initialize(Key, Salt, Info) method assigns the Info array to an HX extended ciphers DistributionCode property; used by the secure key schedule.</description></item>
/// <item><description>After a finalizer call (Finalize or Compute), the Mac functions message state is reset and must be re-initialized with a new nonce or key/nonce pair.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The GMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-GMAC Algorithm.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// </list>
/// </remarks>
class GMAC : public IMac
{
private:

	static const std::string CLASS_NAME;
	static const size_t BLOCK_SIZE = 16;
	static const size_t TAG_MINLEN = 8;

	IBlockCipher* m_blockCipher;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	GHASH* m_gmacHash;
	std::vector<byte> m_gmacNonce;
	std::vector<ulong> m_gmacKey;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::vector<byte> m_msgBuffer;
	std::vector<byte> m_msgCode;
	size_t m_msgCounter;
	size_t m_msgOffset;

public:

	GMAC() = delete;
	GMAC(const GMAC&) = delete;
	GMAC& operator=(const GMAC&) = delete;
	GMAC& operator=(GMAC&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Macs internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Get: The block cipher engine type
	/// </summary>
	const BlockCiphers CipherType();

	/// <summary>
	/// Get: Mac generators type name
	/// </summary>
	const Macs Enumeral() override;

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	const size_t MacSize() override;

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Get: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Get: Mac generators class name
	/// </summary>
	const std::string Name() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class with the block cipher enumeration name
	/// </summary>
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block size is used</exception>
	explicit GMAC(BlockCiphers CipherType);

	/// <summary>
	/// Initialize this class with a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">Instance of the block cipher</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if an invalid Mac or block size is used</exception>
	explicit GMAC(IBlockCipher* Cipher);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~GMAC() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with a symmetric key container.
	/// <para>Uses a key, and nonce arrays to initialize the MAC.
	/// The key size must be one of the block ciphers legal key sizes.
	/// The recommended Nonce size is 12 bytes, but can be a minimum of 8 bytes, to an unlimited maximum size.
	/// The Info param is processed only by an HX enabled cipher as the DistributionCode.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Reset to the default state; Mac code and buffer are zeroised, but key is still loaded
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

	void Scope();
};

NAMESPACE_MACEND
#endif