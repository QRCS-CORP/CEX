﻿// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
// An implementation of a Output FeedBack Mode (OFB).
// Written by John G. Underhill, January 2, 2015
// Updated September 16, 2016
// Updated April 18, 2017
// Updated October 14, 2017
// Updated March 02, 2019
// Contact: develop@qscs.ca

#ifndef CEX_OFB_H
#define CEX_OFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// OFB: An implementation of a Output FeedBack Mode
/// </summary>
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// OFB cipher(BlockCiphers::AES);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
///
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Output Feedback Mode (OFB) is a similar construction to the CFB mode, and allows encryption of various block sizes. \n
/// It differs in that the output of the encryption block function, (rather than the ciphertext), serves as the feedback register. \n
/// The cipher is initialized by copying the initialization vector to an internal register, prepended by zeroes. \n
/// During a transformation, this register is encrypted by the underlying cipher into a buffer, the buffer is then XOR'd with the input message block to produce the ciphertext. \n
/// The vector block is then rotated so that the latter half of the vector is shifted to the start of the array, and the buffer is moved to the end of the array.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// C=ciphertext, P=plaintext, K=key, E=encrypt, ^=XOR \n
/// <EM>Encryption</EM> \n
/// I1 ← IV. For 1 ≤ j ≤ u, given plaintext block Pj: \n
/// (a) Oj ← EK(Ij). -Compute the block-cipher output. \n
/// (b) Tj ← the r leftmost bits of Oj. -Assume the leftmost is identified as bit 1. \n
/// (c) Cj ← Pj ^ Tj. -Transmit the r-bit ciphertext block Cj. \n
/// (d) Ij+1 ← 2r · Ij + Tj mod 2n. -Update the block-cipher input for the next block. \n
/// <EM>Decryption</EM> \n
/// I1 ← IV . For 1 ≤ j ≤ u, upon receiving Cj: \n
/// Pj ← Cj ^ Tj, where Tj, Oj, and Ij are computed as an encryption cycle; K(C).</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description></description></item>
/// <item><description>A cipher mode constructor can either be initialized with a block-cipher instance, or using the block-ciphers enumeration name.</description></item>
/// <item><description>A block-cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The class public functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(bool, ISymmetricKey) function has been called.</description></item>
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
class OFB final : public ICipherMode
{
private:

	static const size_t BLOCK_SIZE = 16;

	class OfbState;
	std::unique_ptr<OfbState> m_ofbState;
	std::unique_ptr<IBlockCipher> m_blockCipher;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	OFB(const OFB&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	OFB& operator=(const OFB&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	OFB() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher enumeration name
	/// </summary>
	///
	/// <param name="CipherType">The enumeration type name of a block-cipher</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an undefined block-cipher type name is used, or the specified register size is invalid</exception>
	explicit OFB(BlockCiphers CipherType);

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher instance pointer
	/// </summary>
	///
	/// <param name="Cipher">The uninitialized block-cipher instance; can not be null</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block-cipher is used, or the specified register size is invalid</exception>
	explicit OFB(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~OFB() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The ciphers internal block-size in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The block ciphers enumeration type name
	/// </summary>
	const BlockCiphers CipherType() override;

	/// <summary>
	/// Read Only: A pointer to the underlying block-cipher instance
	/// </summary>
	IBlockCipher* Engine() override;

	/// <summary>
	/// Read Only: The cipher modes enumeration type name
	/// </summary>
	const CipherModes Enumeral() override;

	/// <summary>
	/// Read Only: The operation mode, returns true if initialized for encryption, false for decryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Read Only: The block-cipher mode has been keyed and is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Parallel processing is not supported with OFB mode</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: A vector of allowed cipher-mode input key uint8_t-sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The cipher-modes formal class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the uint8_t-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes (Not supported in this mode)
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of cipher-text bytes</param>
	/// <param name="Output">The output vector of plain-text bytes</param>
	void DecryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output) override;

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of cipher-text bytes</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of plain-text bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	void DecryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset) override;

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of plain-text bytes</param>
	/// <param name="Output">The output vector of cipher-text bytes</param>
	void EncryptBlock(const std::vector<uint8_t> &Input, std::vector<uint8_t> &Output) override;

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of plain-text bytes</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of cipher-text bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	void EncryptBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the cipher-mode instance
	/// </summary>
	/// 
	/// <param name="Encryption">Operation mode, true if cipher is used for encryption, false to decrypt</param>
	/// <param name="Parameters">SymmetricKey containing the encryption Key and Initialization Vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid key or nonce is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>OFB does not support multi-threaded operation.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	/// <param name="Length">The number of bytes to transform</param>
	void Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length) override;

private:

	void Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
};

NAMESPACE_MODEEND
#endif
