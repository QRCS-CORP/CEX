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
// An implementation of a Output FeedBack Mode (OFB).
// Written by John Underhill, January 2, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_OFB_H
#define _CEXENGINE_OFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements a Cipher FeedBack Mode: OFB.
/// <para>OFB as outlined in the NIST document: SP800-38A</para>
/// </summary>
/// 
/// <example>
/// <description>Example using an <c>ICipherMode</c> interface:</description>
/// <code>
/// OFB cipher(new RDX());
/// // initialize for encryption
/// cipher.Initialize(true, KeyParams(Key, IV));
/// // encrypt a block
/// cipher.Transform(Input, Output);
/// </code>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Cipher::Symmetric::Block">CEX::Cipher::Symmetric::Block Namespace</seealso>
/// <seealso cref="CEX::Enumeration::BlockCiphers">CEX::Enumeration BlockCiphers Enumeration</seealso>
/// 
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>OFB is not a parallel capable cipher mode.</description></item>
/// </list>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>NIST: <see href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</see>.</description></item>
/// </list>
/// </remarks>
class OFB : public ICipherMode
{
protected:
	IBlockCipher* _blockCipher;
	unsigned int _blockSize;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	bool _isParallel;
	std::vector<byte> _ofbBuffer;
	std::vector<byte> _ofbIv;
	unsigned int _parallelBlockSize;
	unsigned int _processorCount;

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
	virtual const CEX::Enumeration::CipherModes Enumeral() { return CEX::Enumeration::CipherModes::OFB; }

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
	virtual const std::vector<byte> IV() { return _ofbIv; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<unsigned int> &LegalKeySizes() { return _blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "OFB"; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, or  block size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
	virtual unsigned int &ParallelBlockSize() { return _parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual unsigned int const ParallelMaximumSize() { return 0; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const unsigned int ParallelMinimumSize() { return 0; }

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
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if a null Cipher or valid block size is used</exception>
	OFB(IBlockCipher* Cipher, unsigned int BlockSizeBits = 128)
		:
		_blockCipher(Cipher),
		_blockSize(BlockSizeBits / 8),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_isParallel(false),
		_ofbBuffer(Cipher->BlockSize()),
		_ofbIv(Cipher->BlockSize()),
		_parallelBlockSize(0),
		_processorCount(0)
	{
		if (Cipher == 0)
			throw CryptoCipherModeException("OFB:CTor", "The Cipher can not be null!");
		if (BlockSizeBits % 8 != 0)
			throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block must be in bits and a multiple of 8.");
		if (BlockSizeBits / 8 > Cipher->BlockSize())
			throw CryptoCipherModeException("OFB:CTor", "Invalid block size! Block size can not be larger than Cipher block size.");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~OFB()
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
	/// <param name="Encryption">Cipher is used. for encryption, false to decrypt</param>
	/// <param name="KeyParam">KeyParams containing key and vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key or IV is used</exception>
	virtual void Initialize(bool Encryption, const KeyParams &KeyParam);

	/// <summary>
	/// <para>Transform a block of bytes. 
	/// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="Output">Output product of Transform</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// <para>Transform a block of bytes with offset parameters. 
	/// <see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

protected:
	void ProcessBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void SetScope();
};

NAMESPACE_MODEEND
#endif
