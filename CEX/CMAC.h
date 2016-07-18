// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_CMAC_H
#define _CEXENGINE_CMAC_H

#include "IMac.h"
#include "ICipherMode.h"
#include "BlockCiphers.h"

NAMESPACE_MAC

/// <summary>
/// An implementation of a Cipher based Message Authentication Code
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CEX::Cipher::Symmetric::Block::RDX* eng;
/// CEX::Mac::CMAC cmac1(eng);
/// hmac1.Initialize(key, [IV]);
/// hmac1.ComputeMac(Input, Output);
/// delete cpr;
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block"/>
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>MAC return size must be a divisible of 8.</description></item>
/// <item><description>MAC return size can be no longer than the Cipher Block size.</description></item>
/// <item><description>Valid Cipher block sizes are 8 and 16 byte wide.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The CMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-CMAC Algorithm.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4494">4494</a>: The AES-CMAC-96 Algorithm and Its Use with IPsec.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4615">4493</a>: The AES-CMAC-PRF-128 Algorithm for the Internet Key Exchange Protocol (IKE).</description></item>
/// </list>
/// </remarks>
class CMAC : public IMac
{
private:
	static constexpr byte CT87 = (byte)0x87;
	static constexpr byte CT1B = (byte)0x1b;

	size_t m_blockSize;
	CEX::Common::KeyParams m_cipherKey;
	CEX::Cipher::Symmetric::Block::Mode::ICipherMode* m_cipherMode;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<byte> K1; 
	std::vector<byte> K2;
	size_t m_macSize;
	std::vector<byte> m_msgCode;
	std::vector<byte> m_wrkBuffer;
	size_t m_wrkOffset;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Macs internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const CEX::Enumeration::Macs Enumeral() { return CEX::Enumeration::Macs::CMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() { return m_macSize; }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "CMAC"; }

	// *** Constructor *** //
	/// <summary>
	/// Initialize the class with the block cipher enumeration name
	/// </summary>
	/// <param name="EngineType">The block cipher enumeration name</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block size is used</exception>
	CMAC(CEX::Enumeration::BlockCiphers EngineType)
		:
		m_blockSize(0),
		m_cipherKey(),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_macSize(0),
		m_msgCode(0),
		m_wrkBuffer(0),
		m_wrkOffset(0)
	{
		CreateCipher(EngineType);
#if defined(ENABLE_CPPEXCEPTIONS)
		if (m_cipherMode == 0)
			throw CryptoMacException("CMAC:Ctor", "Could not create the cipher!");
		if (m_cipherMode->BlockSize() != 16 && m_cipherMode->BlockSize() != 32)
			throw CryptoMacException("CMAC:Ctor", "Block size must be 128 or 256 bits!");
#endif

		m_blockSize = m_cipherMode->BlockSize();
		m_macSize = m_cipherMode->BlockSize();
		m_msgCode.resize(m_cipherMode->BlockSize());
		m_wrkBuffer.resize(m_cipherMode->BlockSize());
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	///
	/// <param name="Cipher">Instance of the block cipher</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoMacException">Thrown if an invalid Mac or block size is used</exception>
	CMAC(CEX::Cipher::Symmetric::Block::IBlockCipher* Cipher)
		:
		m_blockSize(Cipher->BlockSize()),
		m_cipherKey(),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_macSize(Cipher->BlockSize()),
		m_msgCode(Cipher->BlockSize()),
		m_wrkBuffer(Cipher->BlockSize()),
		m_wrkOffset(0)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (Cipher == 0)
			throw CryptoMacException("CMAC:Ctor", "Cipher can not be null!");
		if (Cipher->BlockSize() != 16 && Cipher->BlockSize() != 32)
			throw CryptoMacException("CMAC:Ctor", "Block size must be 128 or 256 bits!");
#endif
		LoadCipher(Cipher);
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CMAC()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">Offset within Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Get the Mac hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The output message code</param>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Process the last block of data
	/// </summary>
	/// 
	/// <param name="Output">The hash value return</param>
	/// <param name="OutOffset">The offset in the data</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Initialize the Cipher MAC generator.
	/// <para>Uses a Key and optional IV field to initialize the cipher.</para>
	/// </summary>
	/// 
	/// <param name="MacKey">A byte array containing the cipher Key. 
	/// <para>Key size must be one of the <c>LegalKeySizes</c> of the underlying cipher.</para>
	/// </param>
	/// <param name="IV">A byte array containing the CBC mode Initialization Vector.
	/// <para>IV size must be the ciphers blocksize.</para></param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid Key size is chosen</exception>
	virtual void Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV);

	/// <summary>
	/// Reset the internal state
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
	void CreateCipher(CEX::Enumeration::BlockCiphers Cipher);
	void LoadCipher(CEX::Cipher::Symmetric::Block::IBlockCipher* Cipher);
};

NAMESPACE_MACEND
#endif