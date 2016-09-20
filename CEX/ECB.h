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
// An implementation of an Electronic CodeBook Mode (ECB).
// Written by John Underhill, September 24, 2014
// Updated September 16, 2016
// Contact: develop@vtdev.com

#ifndef _CEXENGINE_ECB_H
#define _CEXENGINE_ECB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements an Electronic CodeBook Mode: ECB (This is an Insecure Mode; used only for testing purposes)
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// ECB cipher(new AHX());
/// // initialize for encryption
/// cipher.Initialize(true, KeyParams(Key));
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
/// cipher.Initialize(true, KeyParams(Key, IV));
/// // encrypt one parallel sized block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::BlockCiphers"/><BR>
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode"/>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Electronic Code Book cipher processes message input directly through the underlying block cipher. 
/// No Initialization Vector is used, and the output from each block does not effect the output of any other block.<BR>
/// For this reason, ECB is not considered a secure cipher mode, and should never be used in the transformation of real data, but only for debugging and performance testing.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><BR> 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt<BR><BR>
/// <EM>Encryption</EM><BR>
/// For 1 ≤ j ≤ t, Cj ← EK(Pj).<BR>
/// <EM>Decryption</EM><BR>
/// For 1 ≤ j ≤ t, Pj ← E<SUP>−1</SUP>K(Cj).</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the ECB mode be multi-threaded. This is acheived by processing multiple blocks of cipher-text independently across threads.<BR> 
/// The ECB parallel mode also leverages SIMD instructions to 'double parallelize' those segments. A block of cipher-text assigned to a thread
/// uses SIMD instructions to decrypt 4 or 8 blocks in parallel per cycle, depending on which framework is runtime available, 128 or 256 SIMD instructions.</para>
///
/// <description><B>ECB-WBV:</B></description>
/// <para>Wide Block Vectorization is an extension of the standard ECB mode. Instead of processing a single 16 byte block of input, WBV processes 4 or 8 blocks concurrently using SIMD instructions.<BR>
/// The underlying block cipher contains the functions Transform64() and Transform128(), which use parallel instructions (SSE3 or AVX dedending on runtime availability), to process multiple input blocks simultaneously.<BR>
/// This has two adavantages; the first being that if the longer initialization vector is secure (64 or 128 bytes), there is a corresponding increase in security. The second advantage is performance.<BR>
/// Even if a mode is limited by dependency chaining, like the encryption function of the CBC mode, it can still be parallelized using this method, processing input several times faster than the standard 
/// sequential mode configuration.<BR>
/// Just as with the standard block size, the decryption function is multi-threaded, maximizing the potential throughput of this extended mode.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>ECB is not a secure mode, and should only be used for testing, timing, or as a base class; i.e. when constructing an authenticated mode.</description></item>
/// <item><description>Encryption and decryption can both be pipelined (SSE3-128 or AVX-256), and multi-threaded.</description></item>
/// <item><description>Parallel processing is enabled by setting IsParallel() to true, and passing an input block of ParallelBlockSize() to the transform.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on processor cache size but can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize() = (data.size() / cipher.ParallelMinimumSize()) * 40</c></description></item>
/// <item><description>ECB-WBV Transforms require cipher initialization with either a 64 or 128 byte (zeroes) Initialization Vector to trigger WBV.</description></item>
/// <item><description>ECB-WBV uses the Transform64() or Transform128() functions to process input in 64 or 128 byte message blocks in sequential mode.</description></item>
/// <item><description>ECB-WBV Encryption and Decryption must be performed using an identical block length.</description></item>
/// <item><description>ECB-WBV uses ParallelBlockSize() sized input message blocks to process in multi-threaded mode.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class ECB : public ICipherMode
{
private:
	static constexpr size_t MAXALLOC_MB100 = 100000000;
	static constexpr size_t PARALLEL_DEFBLOCK = 64000;

	IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	bool m_destroyEngine;
	std::vector<byte> m_ecbVector;
	bool m_hasAVX;
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

	ECB() = delete;
	ECB(const ECB&) = delete;
	ECB& operator=(const ECB&) = delete;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: Block size of internal cipher in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() { return m_blockCipher; }

	/// <summary>
	/// Get: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() { return CipherModes::ECB; }

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX() { return m_hasAVX; }

	/// <summary>
	/// Get: Returns True if the cipher supports SSE2 SIMD intrinsics
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
	/// Get: The current state of the Initialization Vector
	/// </summary>
	virtual const std::vector<byte> &IV() { return m_ecbVector; }

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual const std::vector<size_t> &LegalKeySizes() { return m_blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: The Cipher Mode name
	/// </summary>
	virtual const char* Name() { return "ECB"; }

	/// <summary>
	/// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>
	/// </summary>
	virtual size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest valid input block byte length, when using multi-threaded processing; parallel blocks must be a multiple of this size
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return m_parallelMinimumSize; }

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
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if a null block cipher type is used</exception>
	explicit ECB(BlockCiphers CipherType)
		:
		m_destroyEngine(true),
		m_ecbVector(0),
		m_hasAVX(false),
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
#if defined(DEBUGASSERT_ENABLED)
		assert((uint)CipherType != 0);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if ((uint)CipherType == 0)
			throw CryptoCipherModeException("ECB:CTor", "The Cipher can not be null!");
#endif

		m_blockCipher = GetCipher(CipherType);
		m_blockSize = m_blockCipher->BlockSize();
		Scope();
	}

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized Block Cipher instance; can not be null</param>
	///
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit ECB(IBlockCipher* Cipher)
		:
		m_blockCipher(Cipher),
		m_blockSize(Cipher->BlockSize()),
		m_destroyEngine(false),
		m_ecbVector(0),
		m_hasAVX(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_processorCount(0),
		m_wideBlock(false)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert(Cipher != 0);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Cipher == 0)
			throw CryptoCipherModeException("ECB:CTor", "The Cipher can not be null!");
#endif

		Scope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~ECB()
	{
		Destroy();
	}


	//~~~Public Methods~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void Decrypt64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void Decrypt128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
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
	virtual void Destroy();

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt a single block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void Encrypt64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt a single block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void Encrypt128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Encrypts one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, False to decrypt</param>
	/// <param name="KeyParam">KeyParams containing the encryption Key</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key is used</exception>
	virtual void Initialize(bool Encryption, const KeyParams &KeyParam);

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Transform a block of bytes. 
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Initialize(bool, KeyParams) must be called before this method can be used.
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using offset parameters. 
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Initialize(bool, KeyParams) must be called before this method can be used.
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Transform64(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// The Initialization Vector (IV) set with Initialize(), must be 64 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	void Transform128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (ECB-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void Detect();
	void Generate(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, const size_t BlockCount);
	IBlockCipher* GetCipher(BlockCiphers CipherType);
	void Scope();
	void TransformParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
};

NAMESPACE_MODEEND
#endif