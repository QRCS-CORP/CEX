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
// An implementation of a Cipher FeedBack Mode (CFB).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_CFB_H
#define _CEXENGINE_CFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements a Cipher FeedBack Mode: CFB
/// </summary>
/// 
/// <example>
/// <description>Example using an <c>ICipherMode</c> interface:</description>
/// <code>
/// CFB cipher(new RDX());
/// // initialize for encryption
/// cipher.Initialize(true, KeyParams(Key, IV));
/// // encrypt a block
/// cipher.Transform(Input, Output);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block"/>
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>In CFB mode, only decryption can be processed in parallel.</description></item>
/// <item><description>Parallel processing is enabled on decryption by passing a block size of ParallelBlockSize to the transform.</description></item>
/// <item><description>ParallelBlockSize must be divisible by ParallelMinimumSize.</description></item>
/// <item><description>Parallel block calculation ex. <c>int blocklen = (data.size() / cipher.ParallelMinimumSize()) * 100</c></description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// </list>
/// </remarks>
class CFB : public ICipherMode
{
private:
	static constexpr unsigned int MAXALLOC_MB100 = 100000000;
	static constexpr unsigned int PARALLEL_DEFBLOCK = 64000;

	IBlockCipher* _blockCipher;
	unsigned int _blockSize;
	std::vector<byte> _cfbIv;
	std::vector<byte> _cfbBuffer;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	bool _isParallel;
	unsigned int _parallelBlockSize;
	unsigned int _processorCount;
	std::vector<std::vector<byte>> _threadVectors;

public:
	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher
	/// </summary>
	virtual const unsigned int BlockSize() { return _blockSize; }

	/// <summary>
	/// Get: Underlying Cipher
	/// </summary>
	virtual IBlockCipher* Engine() { return _blockCipher; }

	/// <summary>
	/// Get: The cipher modes type name
	/// </summary>
	virtual const CEX::Enumeration::CipherModes Enumeral() { return CEX::Enumeration::CipherModes::CFB; }

	/// <summary>
	/// Get: Initialized for encryption, false for decryption
	/// </summary>
	virtual const bool IsEncryption() { return _isEncryption; }

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() { return _isParallel; }

	/// <summary>
	/// Get: The current state of the initialization Vector
	/// </summary>
	virtual const std::vector<byte> IV() { return _cfbIv; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<unsigned int> &LegalKeySizes() { return _blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char* Name() { return "CFB"; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// <para>The parallel block size is calculated automatically based on the number of available processors on the system (n * 64kb).</para>
	/// </summary>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
	virtual unsigned int &ParallelBlockSize() { return _parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual const unsigned int ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const unsigned int ParallelMinimumSize() { return _processorCount * _blockSize; }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const unsigned int ProcessorCount() { return _processorCount; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the Cipher
	/// </summary>
	///
	/// <param name="Cipher">Underlying encryption algorithm</param>
	/// <param name="BlockSizeBits">Block size in bits; minimum is 8, or 1 byte. Maximum is Cipher block size in bits</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null Cipher or valid block size is used</exception>
	CFB(IBlockCipher* Cipher, unsigned int BlockSizeBits = 128)
		:
		_blockCipher(Cipher),
		_blockSize(BlockSizeBits / 8),
		_cfbBuffer(Cipher->BlockSize()),
		_cfbIv(Cipher->BlockSize()),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_isParallel(false),
		_processorCount(1),
		_parallelBlockSize(PARALLEL_DEFBLOCK)
	{
		if (Cipher == 0)
			throw CryptoCipherModeException("CFB:CTor", "The Cipher can not be null!");
		if (BlockSizeBits % 8 != 0)
			throw CryptoCipherModeException("CFB:CTor", "Invalid block size! Block must be in bits and a multiple of 8.");
		if (BlockSizeBits / 8 > Cipher->BlockSize())
			throw CryptoCipherModeException("CFB:CTor", "Invalid block size! Block size can not be larger than Cipher block size.");

		SetScope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CFB()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Initialize the Cipher
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
	/// <param name="KeyParam">KeyParams containing key and std::vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
	virtual void Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam);

	/// <summary>
	/// Transform a block of bytes. 
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="Output">Output product of Transform</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes with offset parameters. 
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="Output">Decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Decrypted bytes</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

	/// <summary>
	/// Encrypt a block of bytes.
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="Output">Output product of Transform</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes with offset parameters.
	/// <para>Initialize(bool, KeyParams) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

private:
	void ParallelDecrypt(const std::vector<byte> &Input, std::vector<byte> &Output);
	void ParallelDecrypt(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void ProcessDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset, std::vector<byte> &Iv, const unsigned int BlockCount);
	void SetScope();
};

NAMESPACE_MODEEND
#endif
