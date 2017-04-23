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
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
//
// Implementation Details:
// An implementation of an Electronic CodeBook Mode (ECB).
// Written by John Underhill, September 24, 2014
// Updated September 16, 2016
// Updated April 18, 2017
// Contact: develop@vtdev.com

#ifndef _CEX_ECB_H
#define _CEX_ECB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// An implementation of an Electronic CodeBook Mode
/// <para>ECB is an Insecure Mode; used only for testing purposes.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// ECB cipher(BlockCiphers::AHX);
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
/// ECB cipher(new AHX());
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
/// <para>The Electronic Code Book cipher processes message input directly through the underlying block cipher. 
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
/// <item><description>If the system supports Parallel processing, IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize() can be changed through the ParallelProfile() property</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize = N - (N % .ParallelMinimumSize);</c></description></item>
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
	static const std::string CLASS_NAME;

	IBlockCipher* m_blockCipher;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isLoaded;
	ParallelOptions m_parallelProfile;

public:

	ECB(const ECB&) = delete;
	ECB& operator=(const ECB&) = delete;
	ECB& operator=(ECB&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: Block size of internal cipher in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Get: The block ciphers formal type name
	/// </summary>
	const BlockCiphers CipherType() override;

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	IBlockCipher* Engine() override;

	/// <summary>
	/// Get: The cipher modes type name
	/// </summary>
	const CipherModes Enumeral() override;

	/// <summary>
	/// Get: True if initialized for encryption, False for decryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Get: The Block Cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Get: Array of allowed cipher input key byte-sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Get: The cipher modes class name
	/// </summary>
	const std::string &Name() override;

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Get/Set: Parallel and SIMD capability flags and sizes (Not supported in this mode)
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name
	/// </summary>
	///
	/// <param name="CipherType">The formal enumeration name of a block cipher</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a undefined block cipher type name is used</exception>
	explicit ECB(BlockCiphers CipherType);

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized Block Cipher instance; can not be null</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit ECB(IBlockCipher* Cipher);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~ECB() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the Input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the Output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if state could not be destroyed</exception>
	void Destroy() override;

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, False to decrypt</param>
	/// <param name="KeyParams">SymmetricKey containing the encryption Key</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// <param name="Length">The number of bytes to transform</param>
	void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) override;

private:

	void Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t BlockCount);
	void ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Scope();
};

NAMESPACE_MODEEND
#endif