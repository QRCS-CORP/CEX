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
// An implementation of a Output FeedBack Mode (OFB).
// Written by John Underhill, January 2, 2015
// Updated September 16, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_OFB_H
#define _CEX_OFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements a Output FeedBack Mode (OFB)
/// </summary>
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// OFB cipher(BlockCiphers::AHX);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
///
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Output Feedback Mode (OFB) is a similar construction to the CFB mode, and allows encryption of various block sizes.<br>
/// It differs in that the output of the encryption block function, (rather than the ciphertext), serves as the feedback register.<br>
/// The cipher is initialized by copying the initialization vector to an internal register, prepended by zeroes.<br>
/// During a transformation, this register is encrypted by the underlying cipher into a buffer, the buffer is then XOR'd with the input message block to produce the ciphertext.<br>
/// The vector block is then rotated so that the latter half of the vector is shifted to the start of the array, and the buffer is moved to the end of the array.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><br> 
/// C=ciphertext, P=plaintext, K=key, E=encrypt, ^=XOR<br>
/// <EM>Encryption</EM><br>
/// I1 ← IV. For 1 ≤ j ≤ u, given plaintext block Pj:<br>
/// (a) Oj ← EK(Ij). -Compute the block cipher output.<br>
/// (b) Tj ← the r leftmost bits of Oj. -Assume the leftmost is identified as bit 1.<br>
/// (c) Cj ← Pj ^ Tj. -Transmit the r-bit ciphertext block Cj.<br>
/// (d) Ij+1 ← 2r · Ij + Tj mod 2n. -Update the block cipher input for the next block.<br>
/// <EM>Decryption</EM><br>
/// I1 ← IV . For 1 ≤ j ≤ u, upon receiving Cj:<br>
/// Pj ← Cj ^ Tj, where Tj, Oj, and Ij are computed as an encryption cycle; K(C).</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description></description></item>
/// <item><description>A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name.</description></item>
/// <item><description>A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The DecryptBlock and EncryptBlock functions can only be accessed through the class instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(bool, SymmetricKey) function has been called.</description></item>
/// <item><description>Due to block chain depenencies in OFB mode, neither the encryption or decryption functions can be processed in parallel.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>FIPS <a href="http://csrc.nist.gov/publications/fips/fips81/fips81.htm">PUB81</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class OFB : public ICipherMode
{
private:

	IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	bool m_hasAVX2;
	bool m_hasSSE;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isParallel;
	std::vector<byte> m_ofbBuffer;
	std::vector<byte> m_ofbVector;
	size_t m_parallelBlockSize;
	size_t m_processorCount;

public:

	OFB(const OFB&) = delete;
	OFB& operator=(const OFB&) = delete;
	OFB& operator=(OFB&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: Block size of internal cipher in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: The block ciphers formal type name
	/// </summary>
	virtual BlockCiphers CipherType() { return m_cipherType; }

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() { return m_blockCipher; }

	/// <summary>
	/// Get: The cipher modes type name
	/// </summary>
	virtual const CipherModes Enumeral() { return CipherModes::OFB; }

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX2() { return m_hasAVX2; }

	/// <summary>
	/// Get: Returns True if the cipher supports SSE SIMD intrinsics
	/// </summary>
	virtual const bool HasSSE() { return m_hasSSE; }

	/// <summary>
	/// Get: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() { return m_isEncryption; }

	/// <summary>
	/// Get: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get/Set: Enable automatic processor parallelization (Not supported in this mode)
	/// </summary>
	virtual bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: The cipher modes class name
	/// </summary>
	virtual const std::string Name() { return "OFB"; }

	/// <summary>
	/// Get: Parallel block size (Not used in this mode)
	/// </summary>
	virtual size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing (Not used in this mode)
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return 0; }

	/// <summary>
	/// Get: The smallest valid input block byte length, when using multi-threaded processing (Not used in this mode)
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return 0; }

	/// <summary>
	/// Get: Available system processor core count
	/// </summary>
	virtual const size_t ProcessorCount() { return m_processorCount; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name
	/// </summary>
	///
	/// <param name="CipherType">The formal enumeration name of a block cipher</param>
	/// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an undefined block cipher type name is used, or the specified register size is invalid</exception>
	explicit OFB(BlockCiphers CipherType, size_t RegisterSize = 16)
		:
		m_blockCipher(0),
		m_blockSize(RegisterSize),
		m_cipherType(CipherType),
		m_destroyEngine(true),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_ofbBuffer(0),
		m_ofbVector(0),
		m_parallelBlockSize(0),
		m_processorCount(0)
	{
		if (CipherType == BlockCiphers::None)
			throw CryptoCipherModeException("OFB:CTor", "The Cipher type can not be zero!");
		if (RegisterSize == 0)
			throw CryptoCipherModeException("OFB:CTor", "The RegisterSize can not be zero!");

		LoadState();

		if (RegisterSize > m_blockCipher->BlockSize())
			throw CryptoCipherModeException("OFB:CTor", "The RegisterSize can not be more than the ciphers block size!");
	}

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">Uninitialized block cipher instance; can not be null</param>
	/// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size; default value is 16 bytes.</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a null block cipher is used, or the specified register size is invalid</exception>
	explicit OFB(IBlockCipher* Cipher, size_t RegisterSize = 16)
		:
		m_blockCipher(Cipher),
		m_blockSize(RegisterSize),
		m_cipherType(Cipher->Enumeral()),
		m_destroyEngine(false),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_ofbBuffer(Cipher->BlockSize()),
		m_ofbVector(Cipher->BlockSize()),
		m_parallelBlockSize(0),
		m_processorCount(0)
	{
		if (m_blockCipher == 0)
			throw CryptoCipherModeException("OFB:CTor", "The Cipher can not be null!");
		if (m_blockSize < 1)
			throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block must be in bits and a multiple of 8.");
		if (m_blockSize > m_blockCipher->BlockSize())
			throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block size can not be larger than Cipher block size.");

		LoadState();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~OFB()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if state could not be destroyed</exception>
	virtual void Destroy();

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encrypts one block of bytes beginning at a zero index.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encrypts one block of bytes at the designated offsets.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the Block Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, False to decrypt</param>
	/// <param name="KeyParam">SymmetricKey containing the encryption Key and Initialization Vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key or Nonce is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParam);

	/// <summary>
	/// Transform a block of bytes. 
	/// <para>Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encrypts one block of bytes beginning at a zero index.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes with offset parameters. 
	/// <para>Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encrypts one block of bytes at the designated offsets.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	IBlockCipher* LoadCipher(BlockCiphers CipherType);
	void LoadState();
	void Scope();
};

NAMESPACE_MODEEND
#endif
