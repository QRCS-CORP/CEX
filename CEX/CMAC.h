// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// Updated October 3, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_CMAC_H
#define _CEX_CMAC_H

#include "IMac.h"
#include "BlockCiphers.h"
#include "ICipherMode.h"

NAMESPACE_MAC

using Enumeration::BlockCiphers;
using Cipher::Symmetric::Block::IBlockCipher;
using Cipher::Symmetric::Block::Mode::ICipherMode;

/// <summary>
/// An implementation of a Cipher based Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CMAC mac(Enumeration::BlockCiphers::AHX);
/// mac.Initialize(Key, Nonce);
/// mac.ComputeMac(Input, Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Cipher-based Message Authentication Code (CMAC), sometimes known as OMAC, is a block cipher-based message authentication code algorithm.<br>
/// It can use any of the block ciphers in this library to provide assurance of message authenticity and the integrity of binary data.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><br> 
/// <B>CIPH</B>=encryption-function, <B>K</B>=key, <B>b</B>=block-size, <B>M</B>=message, <B>K1,K2</B>=subkeys, <B>^</B>=XOR, <B>ls</B>=left-shift</para>
/// <para><EM>Subkey Generation</EM><br>
/// 1) Let L = CIPHK(0b).<br>
/// 2)	 If MSB1(L) = 0, then K1 = L ls 1;<br>
/// Else K1 = (L ls 1) ^ Rb<br>
/// 3)	 If MSB1(K1) = 0, then K2 = K1 ls 1;<br>
/// Else K2 = (K1 ls 1) ^ Rb.</para>
///
/// <para><EM>MAC Function</EM><br>
/// 1) Apply the subkey generation process to K to produce K1 and K2.<br>
/// 2) If Mlen = 0, let n = 1; else, let n = ⎡Mlen / b⎤.<br>
/// 3) Let M1, M2, ..., Mn - 1, Mn*, denote the unique sequence of bit strings such that M = M1 || M2 || ... || Mn - 1 || Mn*, where M1, M2, ..., Mn - 1 are complete blocks.<br>
/// 4) If Mn* is a complete block, let Mn = K1 ^ Mn*; else, let Mn = K2 ^ (Mn* || 10j), where j = nb - Mlen - 1.<br>
/// 5) Let C0 = 0b.<br>
/// 6) For i = 1 to n, let Ci = CIPHK(Ci - 1 ^ Mi).<br>
/// 7) Let T = MSBTlen(Cn).<br>
/// 8) Return T.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Never reuse a ciphers key and iv for the MAC function, this is insecure and strongly discouraged.</description></item>
/// <item><description>MAC return size is the underlying ciphers block-size; e.g. for AES, 16 bytes.</description></item>
/// <item><description>With the Initialize(Key) method, the key must be at least the ciphers block-size plus the minimum key size in length.</description></item>
/// <item><description>The Initialize(Key, Salt), and Initialize(Key, Salt, Info) methods, use the Key parameter as the cipher key, and the Salt as the initialization vector.</description></item>
/// <item><description>The Initialize(Key, Salt, Info) method assigns the Info array to an HX extended ciphers DistributionCode property; used by the secure key schedule.</description></item>
/// <item><description>After a finalizer call (DoFinal or ComputeMac), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The CMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-CMAC Algorithm.</description></item>
/// </list>
/// </remarks>
class CMAC : public IMac
{
private:

	const byte CT87 = (byte)0x87;
	const byte CT1B = (byte)0x1b;

	ICipherMode* m_cipherMode;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> m_K1; 
	std::vector<byte> m_K2;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_macSize;
	std::vector<byte> m_msgCode;
	std::vector<byte> m_wrkBuffer;
	size_t m_wrkOffset;

public:

	CMAC() = delete;
	CMAC(const CMAC&) = delete;
	CMAC& operator=(const CMAC&) = delete;
	CMAC& operator=(CMAC&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Macs internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_cipherMode->BlockSize(); }

	/// <summary>
	/// Get: Mac generators type name
	/// </summary>
	virtual const Macs Enumeral() { return Macs::CMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() { return m_macSize; }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_legalKeySizes; };

	/// <summary>
	/// Get: Mac generators class name
	/// </summary>
	virtual const std::string Name() { return "CMAC"; }

	//~~~Constructor~~~//
	/// <summary>
	/// Initialize the class with the block cipher enumeration name
	/// </summary>
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block size is used</exception>
	explicit CMAC(BlockCiphers CipherType)
		:
		m_cipherType(CipherType),
		m_destroyEngine(true),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_legalKeySizes(0),
		m_macSize(0),
		m_msgCode(0),
		m_wrkBuffer(0),
		m_wrkOffset(0)
	{
		if (CipherType == BlockCiphers::None)
			throw CryptoMacException("CMAC:Ctor", "The cipher type name is invalid!");

		m_cipherMode = LoadCipher(CipherType);
		LoadState();
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	///
	/// <param name="Cipher">Instance of the block cipher</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if an invalid Mac or block size is used</exception>
	explicit CMAC(IBlockCipher* Cipher)
		:
		m_cipherType(Cipher->Enumeral()),
		m_destroyEngine(false),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_legalKeySizes(0),
		m_macSize(0),
		m_msgCode(0),
		m_wrkBuffer(0),
		m_wrkOffset(0)
	{
		if (Cipher == 0)
			throw CryptoMacException("CMAC:Ctor", "Cipher can not be null!");

		m_cipherMode = LoadCipher(Cipher);
		LoadState();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CMAC()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the Mac with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The Mac input data array</param>
	/// <param name="InOffset">Starting position with the Input array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Get: The block cipher engine type
	/// </summary>
	const BlockCiphers CipherType() { return m_cipherType; }

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key, salt, and optional info arrays to initialize the MAC.
	/// The Salt parameter is used as the underlying cipher modes initialization vector, and must be at least block-size in length.</para>
	/// </summary>
	/// 
	/// <param name="MacParam">A SymmetricKey key container class</param>
	virtual void Initialize(ISymmetricKey &MacParam);

	/// <summary>
	/// Initialize the MAC with a key.
	/// <para>The key must be at least the minimum legal key size, plus the ciphers block-size in length.</para>
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	virtual void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the MAC with key and salt arrays.
	/// <para>The key must be at least the minimum legal key size, and the salt must be the ciphers block-size in length.</para>
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt or initialization vector</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt);

	/// <summary>
	/// Initialize the MAC generator with key, salt, and info arrays.
	/// <para>The key must be a legal key size, and the salt must be the ciphers block-size in length.
	/// The info parameter is only used on HX extended mode ciphers.</para>
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt used as the cipher modes initialization vector</param>
	/// <param name="Info">The info parameter appended to the key as a source of additional entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info);

	/// <summary>
	/// Reset to the default state; Mac must be re-initialized after this call
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

private:
	std::vector<byte> GenerateSubkey(std::vector<byte> &Input);
	ICipherMode* LoadCipher(Enumeration::BlockCiphers CipherType);
	ICipherMode* LoadCipher(IBlockCipher* Cipher);
	void LoadState();

};

NAMESPACE_MACEND
#endif