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
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// Updated December 20, 2016
// Updated December 23, 2018
// Contact: develop@vtdev.com

#ifndef CEX_CMAC_H
#define CEX_CMAC_H

#include "IMac.h"
#include "BlockCiphers.h"
#include "ICipherMode.h"
#include "SymmetricSecureKey.h"

NAMESPACE_MAC

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Cipher::Block::IBlockCipher;
using Cipher::Block::Mode::ICipherMode;
using Cipher::SymmetricSecureKey;

/// <summary>
/// An implementation of a symmetric Cipher based Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CMAC mac(Enumeration::BlockCiphers::AHX);
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Cipher-based Message Authentication Code (CMAC), sometimes known as OMAC, is a block cipher-based message authentication code algorithm. \n
/// It can use any of the block ciphers in this library to provide assurance of message authenticity and the integrity of binary data.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>CIPH</B>=encryption-function, <B>K</B>=key, <B>b</B>=block-size, <B>M</B>=message, <B>K1,K2</B>=subkeys, <B>^</B>=XOR, <B>ls</B>=left-shift</para>
/// <para><EM>Subkey Generation</EM> \n
/// 1) Let L = CIPHK(0b). \n
/// 2)	 If MSB1(L) = 0, then K1 = L ls 1; \n
/// Else K1 = (L ls 1) ^ Rb \n
/// 3)	 If MSB1(K1) = 0, then K2 = K1 ls 1; \n
/// Else K2 = (K1 ls 1) ^ Rb.</para>
///
/// <para><EM>MAC Function</EM> \n
/// 1) Apply the subkey generation process to K to produce K1 and K2. \n
/// 2) If Mlen = 0, let n = 1; else, let n = ⎡Mlen / b⎤. \n
/// 3) Let M1, M2, ..., Mn - 1, Mn*, denote the unique sequence of bit strings such that M = M1 || M2 || ... || Mn - 1 || Mn*, where M1, M2, ..., Mn - 1 are complete blocks. \n
/// 4) If Mn* is a complete block, let Mn = K1 ^ Mn*; else, let Mn = K2 ^ (Mn* || 10j), where j = nb - Mlen - 1. \n
/// 5) Let C0 = 0b. \n
/// 6) For i = 1 to n, let Ci = CIPHK(Ci - 1 ^ Mi). \n
/// 7) Let T = MSBTlen(Cn). \n
/// 8) Return T.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Never reuse a ciphers key for the CMAC function, this is insecure and strongly discouraged.</description></item>
/// <item><description>MAC return size is the underlying ciphers block-size; e.g. for AES, 16 bytes, and can be truncated by the caller.</description></item>
/// <item><description>With the Initialize(Key) method, the key must be at least the ciphers block-size plus the minimum key size in length.</description></item>
/// <item><description>The Initialize(Key, Salt), and Initialize(Key, Salt, Info) methods, use the Key parameter as the cipher key, and the Salt as the initialization vector.</description></item>
/// <item><description>The Initialize(Key, Salt, Info) method assigns the Info array to an HX extended ciphers DistributionCode property; used by the secure key schedule to create an encryption domain.</description></item>
/// <item><description>After a finalizer call (Finalize or Compute), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The CMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-CMAC Algorithm.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// </list>
/// </remarks>
class CMAC final : public IMac
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const std::string CLASS_NAME;
	static const byte CT87 = 0x87;
	static const byte CT1B = 0x1b;

	std::unique_ptr<ICipherMode> m_cipherMode;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::unique_ptr<SymmetricSecureKey> m_keys;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_macSize;
	std::vector<byte> m_msgBuffer;
	std::vector<byte> m_msgCode;
	size_t m_msgLength;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CMAC(const CMAC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CMAC& operator=(const CMAC&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CMAC() = delete;

	/// <summary>
	/// Initialize the class with the block cipher enumeration name
	/// </summary>
	///
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="CipherExtensionType">The extended HX ciphers key schedule KDF</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block cipher type is selected</exception>
	explicit CMAC(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None);

	/// <summary>
	/// Initialize this class with a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized instance of the block-cipher</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if the block cipher is null</exception>
	explicit CMAC(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Macs internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The block cipher engine type
	/// </summary>
	const BlockCiphers CipherType();

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
	/// Read Only: Mac generators implementation name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with a symmetric key container.
	/// <para>Uses a key, and optional info arrays to initialize the MAC.
	/// The key size must be one of the block ciphers legal key sizes.
	/// The Info param is processed only by an HX enabled cipher as the DistributionCode.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if an invalid keyk size is used</exception>
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

	std::vector<byte> GenerateSubkey(std::vector<byte> &Input);
	void Pad(std::vector<byte> &Input, size_t Offset, size_t Length);
	void Scope();
};

NAMESPACE_MACEND
#endif
