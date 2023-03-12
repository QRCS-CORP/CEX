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
// An implementation of an Electronic CodeBook Mode (ECB).
// Written by John G. Underhill, September 24, 2014
// Updated September 16, 2016
// Updated April 18, 2017
// Updated October 14, 2017
// Updated March 1, 2019
// Contact: develop@qscs.ca

#ifndef CEX_ECB_H
#define CEX_ECB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// ECB: An implementation of an Electronic CodeBook Mode
/// <para>ECB is an Insecure Mode; used only for testing purposes.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// ECB cipher(BlockCiphers::AES);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
///
/// <example>
/// <description>Encrypting using parallel processing:</description>
/// <code>
/// ECB cipher(new AES());
/// // enable parallel and define parallel input block size
/// cipher.IsParallel() = true;
/// // calculated automatically based on cache size, but overridable
/// cipher.ParallelBlockSize() = ProcessorCount() * 32000;
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt one parallel sized block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Electronic Code Book cipher processes message input directly through the underlying block-cipher. 
/// No Initialization Vector is used, and the output from each block does not effect the output of any other block. \n
/// For this reason, ECB is not considered a secure cipher mode, and should never be used in the transformation of real data, but only for debugging and performance testing.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>D</B>=decrypt \n
/// <EM>Encryption</EM> \n
/// For 1 ≤ j ≤ t, Cj ← EK(Pj). \n
/// <EM>Decryption</EM> \n
/// For 1 ≤ j ≤ t, Pj ← E<SUP>−1</SUP>K(Cj).</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the ECB mode be multi-threaded. This is achieved by processing multiple blocks of cipher-text independently across threads. \n 
/// The ECB parallel mode also leverages SIMD instructions to 'double parallelize' those segments. A block of cipher-text assigned to a thread
/// uses SIMD instructions to decrypt 4 or 8 blocks in parallel per cycle, depending on which framework is runtime available, 128 or 256 SIMD instructions.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>ECB is not a secure mode, and should only be used for testing, timing, or as a base class; i.e. when constructing an authenticated mode.</description></item>
/// <item><description>Encryption and decryption can both be pipelined (SSE3-128 or AVX-256), and multi-threaded.</description></item>
/// <item><description>If the system supports Parallel processing, and IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property; parallel processing can be disabled by setting IsParallel() to false in the ParallelProfile() accessor.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class ECB final : public ICipherMode
{
private:

	static const size_t BLOCK_SIZE = 16;

	class EcbState;
	std::unique_ptr<EcbState> m_ecbState;
	std::unique_ptr<IBlockCipher> m_blockCipher;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ECB(const ECB&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ECB& operator=(const ECB&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	ECB() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher type name
	/// </summary>
	///
	/// <param name="CipherType">The enumeration type name of the block-cipher</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a undefined block-cipher type name is used</exception>
	explicit ECB(BlockCiphers CipherType);

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher instance
	/// </summary>
	///
	/// <param name="Cipher">The uninitialized block-cipher instance; can not be null</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block-cipher is used</exception>
	explicit ECB(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ECB() override;

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
	/// Initialize the Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">Operation mode, true if cipher is used for encryption, false to decrypt</param>
	/// <param name="Parameters">SymmetricKey containing the encryption Key</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, runs in sequential mode. 
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
	void Encrypt128(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void Generate(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t BlockCount);
	bool IsRijndael();
	void ProcessParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void ProcessSequential(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length);
};

NAMESPACE_MODEEND
#endif
