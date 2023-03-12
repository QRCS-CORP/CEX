﻿// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
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
// An implementation of a Cipher Block Chaining Mode (CBC).
// Written by John G. Underhill, September 24, 2014
// Updated September 1, 2016
// Updated April 18, 2017
// Updated October 14, 2017
// Updated March 1, 2019
// Contact: develop@qscs.ca

#ifndef CEX_CBC_H
#define CEX_CBC_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// CBC: An implementation of a Cipher Block Chaining Mode
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// CBC cipher(BlockCiphers::AES);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Cipher Block Chaining cipher mode wraps a symmetric block-cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output. \n
/// The mechanism used in CBC mode can be described as XOR chaining of message input blocks; the first block is XOR'd with the initialization vector, then encrypted with the underlying symmetric cipher.
/// The second block is XOR'd with the first encrypted block, then encrypted, and all subsequent blocks follow this pattern. \n
/// The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>D</B>=decrypt, <B>^</B>=XOR \n
/// <EM>Encryption</EM> \n
/// C0 ← IV. For 1 ≤ j ≤ t, Cj ← EK(Cj−1 ^ Pj). \n
/// <EM>Decryption</EM> \n
/// C0 ← IV. For 1 ≤ j ≤ t, Pj ← Cj−1 ^ E<SUP>−1</SUP>K(Cj).</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption function of the CBC mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded.
/// The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores. \n
/// This is achieved by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>A cipher mode constructor can either be initialized with a block-cipher instance, or using the block ciphers enumeration name.</description></item>
/// <item><description>A block-cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The class functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The DecryptBlock, Decrypt512, Decrypt1024  EncryptBlock, Encrypt512, Encrypt1024 functions can be accessed through the class instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(bool, ISymmetricKey) function has been called.</description></item>
/// <item><description>In CBC mode, only the decryption function can be processed in parallel.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>Parallel processing is enabled on decryption by passing an input block of at least ParallelBlockSize() to the transform; this can be disabled by setting IsParallel() to false in the ParallelProfile() accessor.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class CBC final : public ICipherMode
{
private:

	static const size_t BLOCK_SIZE = 16;

	class CbcState;
	std::unique_ptr<CbcState> m_cbcState;
	std::unique_ptr<IBlockCipher> m_blockCipher;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CBC(const CBC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CBC& operator=(const CBC&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CBC() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher type name
	/// </summary>
	///
	/// <param name="CipherType">The enumeration type name of the block-cipher variant</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an undefined block-cipher type name is used</exception>
	explicit CBC(BlockCiphers CipherType);

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher instance
	/// </summary>
	///
	/// <param name="Cipher">The uninitialized block-cipher instance; can not be null</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block-cipher is used</exception>
	explicit CBC(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CBC() override;

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
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
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
	/// Read Only: The CBC initialization vector (exposed for CMAC)
	/// </summary>
	std::vector<uint8_t> &IV();

	/// <summary>
	/// Read Only: Parallel block size; the uint8_t-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Contains parallel and SIMD capability flags and sizes
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
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// Parallel processing is limited to the Decryption function only, the Encryption function will process ParallelBlockSize() blocks in sequential mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
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

	void Decrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void DecryptParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void DecryptSegment(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, std::vector<uint8_t> &Iv, size_t BlockCount);
	void Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length);
};

NAMESPACE_MODEEND
#endif
