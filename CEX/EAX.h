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
// An implementation of an Electronic CodeBook Mode (EAX).
// Written by John Underhill, September 24, 2014
// Updated September 16, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_EAX_H
#define _CEX_EAX_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements an Electronic CodeBook Mode (EAX) 
/// <para>EAX is an Insecure Mode; used only for testing purposes.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// EAX cipher(BlockCiphers::AHX);
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
/// EAX cipher(new AHX());
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
/// No Initialization Vector is used, and the output from each block does not effect the output of any other block.<br>
/// For this reason, EAX is not considered a secure cipher mode, and should never be used in the transformation of real data, but only for debugging and performance testing.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><br> 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt<br>
/// <EM>Encryption</EM><br>
/// For 1 ≤ j ≤ t, Cj ← EK(Pj).<br>
/// <EM>Decryption</EM><br>
/// For 1 ≤ j ≤ t, Pj ← E<SUP>−1</SUP>K(Cj).</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the EAX mode be multi-threaded. This is acheived by processing multiple blocks of cipher-text independently across threads.<br> 
/// The EAX parallel mode also leverages SIMD instructions to 'double parallelize' those segments. A block of cipher-text assigned to a thread
/// uses SIMD instructions to decrypt 4 or 8 blocks in parallel per cycle, depending on which framework is runtime available, 128 or 256 SIMD instructions.</para>
///
/// <description><B>EAX-WBV:</B></description>
/// <para>Wide Block Vectorization is an extension of the standard EAX mode. Instead of processing a single 16 byte block of input, WBV processes 4 or 8 blocks concurrently using SIMD instructions.<br>
/// The underlying block cipher contains the functions Transform64() and Transform128(), which use parallel instructions (SSE3 or AVX dedending on runtime availability), to process multiple input blocks simultaneously.<br>
/// This has two adavantages; the first being that if the longer initialization vector is secure (64 or 128 bytes), there is a corresponding increase in security. The second advantage is performance.<br>
/// Even if a mode is limited by dependency chaining, like the encryption function of the CBC mode, it can still be parallelized using this method, processing input several times faster than the standard 
/// sequential mode configuration.<br>
/// Just as with the standard block size, the decryption function is multi-threaded, maximizing the potential throughput of this extended mode.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>EAX is not a secure mode, and should only be used for testing, timing, or as a base class; i.e. when constructing an authenticated mode.</description></item>
/// <item><description>Encryption and decryption can both be pipelined (SSE3-128 or AVX-256), and multi-threaded.</description></item>
/// <item><description>Parallel processing is enabled by setting IsParallel() to true, and passing an input block of ParallelBlockSize() to the transform.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize() = data.size() - (data.size() % cipher.ParallelMinimumSize());</c></description></item>
/// <item><description>EAX-WBV Transforms require cipher initialization with either a 64 or 128 byte (zeroes) Initialization Vector to trigger WBV.</description></item>
/// <item><description>EAX-WBV uses the Transform64() or Transform128() functions to process input in 64 or 128 byte message blocks in sequential mode.</description></item>
/// <item><description>EAX-WBV Encryption and Decryption must be performed using an identical block length.</description></item>
/// <item><description>EAX-WBV uses ParallelBlockSize() sized input message blocks to process in multi-threaded mode.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The <a href="http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf">EAX Mode</a> of Operation.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class EAX //: public ICipherMode
{
private:

	const size_t MAX_PRLALLOC = 100000000;
	const size_t PRC_DATACACHE = 32000;

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
	size_t m_parallelBlockSize;
	size_t m_parallelMaxDegree;
	size_t m_parallelMinimumSize;
	size_t m_processorCount;
	bool m_wideBlock;

public:

	EAX(const EAX&) = delete;
	EAX& operator=(const EAX&) = delete;
	EAX& operator=(EAX&&) = delete;

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
	/// Get: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() { return CipherModes::EAX; }

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
	/// Get/Set: Enable automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: The cipher mode name
	/// </summary>
	virtual const std::string Name() { return "EAX"; }

	/// <summary>
	/// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// <para>Changes to this property must be made before the <see cref="Initialize(bool, SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return MAX_PRLALLOC; }

	/// <summary>
	/// Get: The smallest valid input block byte length, when using multi-threaded processing; parallel blocks must be a multiple of this size
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return m_parallelMinimumSize; }

	/// <summary>
	/// Get/Set: The maximum number of threads allocated when using multi-threaded processing.
	/// <para>Changes to this value must be made before the <see cref="Initialize(bool, SymmetricKey)"/> function is called.</para>
	/// </summary>
	size_t &ParallelThreadsMax() { return m_parallelMaxDegree; }

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
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a undefined block cipher type name is used</exception>
	explicit EAX(BlockCiphers CipherType)
		:
		m_blockCipher(0),
		m_blockSize(0),
		m_cipherType(CipherType),
		m_destroyEngine(true),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMaxDegree(0),
		m_parallelMinimumSize(0),
		m_processorCount(0),
		m_wideBlock(false)
	{
		if (m_cipherType == BlockCiphers::None)
			throw CryptoCipherModeException("EAX:CTor", "The Cipher can not be null!");

		LoadState();
	}

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized Block Cipher instance; can not be null</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit EAX(IBlockCipher* Cipher)
		:
		m_blockCipher(Cipher),
		m_blockSize(Cipher->BlockSize()),
		m_cipherType(Cipher->Enumeral()),
		m_destroyEngine(false),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMaxDegree(0),
		m_parallelMinimumSize(0),
		m_processorCount(0),
		m_wideBlock(false)
	{
		if (m_blockCipher == 0)
			throw CryptoCipherModeException("EAX:CTor", "The Cipher can not be null!");

		LoadState();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~EAX()
	{
		Destroy();
	}


	//~~~Public Methods~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Decrypt64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 128 bytes in length</exception>
	void Decrypt128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if state could not be destroyed</exception>
	virtual void Destroy();

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt a single block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt a single block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 128 bytes in length</exception>
	void Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 128 bytes in length</exception>
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, False to decrypt</param>
	/// <param name="KeyParam">SymmetricKey containing the encryption Key</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParam);

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Transform a block of bytes. 
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using offset parameters. 
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Transform64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// The Initialization Vector (Nonce) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 64 bytes in length</exception>
	void Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 128 bytes in length</exception>
	void Transform128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (EAX-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (Nonce) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if the block size is not 128 bytes in length</exception>
	void Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void Detect();
	void Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, const size_t BlockCount);
	IBlockCipher* LoadCipher(BlockCiphers CipherType);
	void LoadState();
	void Scope();
	void TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
};

NAMESPACE_MODEEND
#endif