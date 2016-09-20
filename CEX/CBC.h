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
// An implementation of a Cipher Block Chaining Mode (CBC).
// Written by John Underhill, September 24, 2014
// Updated September 1, 2016
// Contact: develop@vtdev.com

#ifndef _CEXENGINE_CBC_H
#define _CEXENGINE_CBC_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements the Cipher Block Chaining Mode: CBC
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// CBC cipher(new AHX());
/// // initialize for encryption
/// cipher.Initialize(true, KeyParams(Key, IV));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
///
/// <example>
/// <description>Decrypting using multi-threading and CBC-WBV:</description>
/// <code>
/// CBC cipher(new AHX());
/// // enable parallel and set the parallel input block size
/// cipher.IsParallel() = true;
/// // calculated automatically based on cache size, but overridable
/// cipher.ParallelBlockSize() = cipher.ProcessorCount() * 32000;
/// // initialize for decryption
/// cipher.Initialize(false, KeyParams(Key, IV));
/// // decrypt one parallel sized block
/// cipher.Transform128(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::BlockCiphers"/><BR>
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode"/>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Cipher Block Chaining cipher mode wraps a symmetric block cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output.<BR>
/// The mechanism used in CBC mode can be described as XOR chaining of message input blocks; the first block is XOR'd with the initialization vector, then encrypted with the underlying symmetric cipher.
/// The second block is XOR'd with the first encrypted block, then encrypted, and all subsequent blocks follow this pattern.<BR>
/// The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><BR> 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt, <B>^<B/>=XOR<BR><BR>
/// <EM>Encryption</EM><BR>
/// C0 ← IV. For 1 ≤ j ≤ t, Cj ← EK(Cj−1 ^ Pj).<BR>
/// <EM>Decryption</EM><BR>
/// C0 ← IV. For 1 ≤ j ≤ t, Pj ← Cj−1 ^ E<SUP>−1</SUP>K(Cj).</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption function of the CBC mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded.
/// The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores.<BR>
/// This is acheived by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.<BR> 
/// The CBC parallel decryption mode also leverages SIMD instructions to 'double parallelize' those segments. A block of cipher-text assigned to a thread
/// uses SIMD instructions to decrypt 4 or 8 blocks in parallel per cycle, depending on which framework is runtime available, 128 or 256 SIMD instructions.</para>
///
/// <description><B>CBC-WBV:</B></description>
/// <para>Wide Block Vectorization is an extension of the standard CBC mode. Instead of processing a single 16 byte block of input, WBV processes 4 or 8 blocks concurrently using SIMD instructions.<BR>
/// The underlying block cipher contains the functions Transform64() and Transform128(), which use parallel instructions (SSE3 or AVX dedending on runtime availability), to process multiple input blocks simultaneously.<BR>
/// This has two adavantages; the first being that if the longer initialization vector is secure (64 or 128 bytes), there is a corresponding increase in security. The second advantage is performance.<BR>
/// Even if a mode is limited by dependency chaining, like the encryption function of the CBC mode, it can still be parallelized using this method, processing input several times faster than the standard 
/// sequential mode configuration.<BR>
/// Just as with the standard block size, the decryption function is multi-threaded, maximizing the potential throughput of this extended mode.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name.</description></item>
/// <item><description>A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The DecryptBlock, Decrypt64, Decrypt128  EncryptBlock, Encrypt64, Encrypt128 functions can be accessed through the class instance.</description></item>
/// <item><description>The transformation methods can not be called until the the Initialize(bool, KeyParams) function has been called.</description></item>
/// <item><description>In CBC mode, only the decryption function can be processed in parallel.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>Parallel processing is enabled on decryption by setting IsParallel() to true, and passing an input block of ParallelBlockSize() to the transform.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on processor cache size but can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize() = (data.size() / cipher.ParallelMinimumSize()) * 40</c></description></item>
/// <item><description>CBC-WBV Transforms require cipher initialization with either a 64 or 128 byte Initialization Vector.</description></item>
/// <item><description>CBC-WBV uses the Transform64() or Transform128() functions to process input in 64 or 128 byte message blocks in sequential mode.</description></item>
/// <item><description>CBC-WBV output is <B>not equal</B> to the mode run with a smaller block size; Encryption and Decryption must be performed using an identical block length.</description></item>
/// <item><description>CBC-WBV uses ParallelBlockSize() sized input message blocks to process in multi-threaded mode.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class CBC : public ICipherMode
{
private:
	static constexpr size_t MAXALLOC_MB100 = 100000000;
	static constexpr size_t PARALLEL_DEFBLOCK = 64000;

	IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	std::vector<byte> m_cbcVector;
	bool m_destroyEngine;
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

	CBC() = delete;
	CBC(const CBC&) = delete;
	CBC& operator=(const CBC&) = delete;

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
	virtual const CipherModes Enumeral() { return CipherModes::CBC; }

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
	virtual const std::vector<byte> &IV() { return m_cbcVector; }

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual const std::vector<size_t> &LegalKeySizes() { return m_blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: The Cipher Mode name
	/// </summary>
	virtual const char* Name() { return "CBC"; }

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
	explicit CBC(BlockCiphers CipherType)
		:
		m_destroyEngine(true),
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
			throw CryptoCipherModeException("CBC:CTor", "The Cipher type can not be zero!");
#endif

		m_blockCipher = GetCipher(CipherType);
		m_blockSize = m_blockCipher->BlockSize();
		Scope();
	}

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">The uninitialized block cipher instance; can not be null</param>
	///
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit CBC(IBlockCipher* Cipher)
		:
		m_blockCipher(Cipher),
		m_blockSize(Cipher->BlockSize()),
		m_destroyEngine(false),
		m_hasAVX(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMaxDegree(0),
		m_parallelMinimumSize(0),
		m_processorCount(1),
		m_wideBlock(false)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert(Cipher != 0);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Cipher == 0)
			throw CryptoCipherModeException("CBC:CTor", "The Cipher can not be null!");
#endif

		Scope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CBC()
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
	/// <para>Decrypts one block of bytes at the designated offsets.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the Input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the Output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Decrypt a block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Decrypt a single block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Decrypt a single block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// <para>Encrypts one block of bytes at the designated offsets.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt a single block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Encrypt a block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Encrypt a single block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// Encrypt a block of bytes using a Wide Block Vector (CBC-WBV).
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
	/// <param name="KeyParam">KeyParams containing the encryption Key and Initialization Vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
	virtual void Initialize(bool Encryption, const KeyParams &KeyParam);

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
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
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.
	/// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
	/// Initialize(bool, KeyParams) must be called before this function can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using offset parameters.
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (CBC-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// Multi-threading capable in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
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
	/// Transform a block of bytes using a Wide Block Vector (CBC-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 64 bytes (4* 16 byte blocks) in parallel using 128bit SIMD instructions. 
	/// Multi-threading capable in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
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
	/// Transform a block of bytes using a Wide Block Vector (CBC-WBV).
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// Multi-threading capable in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
	/// The Initialization Vector (IV) set with Initialize(), must be 128 bytes in length.
	/// Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	void Transform128(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using a Wide Block Vector (CBC-WBV).
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Wide Block Vector format, processes 128 bytes (8* 16 byte blocks) in parallel using 256bit SIMD instructions.
	/// Multi-threading capable in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
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
	void DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount);
	void Detect();
	IBlockCipher* GetCipher(BlockCiphers CipherType);
	void Scope();
};

NAMESPACE_MODEEND
#endif
