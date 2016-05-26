// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
// Principal Algorithms:
// Cipher implementation based on the Rijndael block cipher designed by Joan Daemen and Vincent Rijmen:
// Rijndael <see href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Specification</see>.
// 
// Implementation Details:
// An extended implementation of the Rijndael encryption algorithm:
// Rijndael Extended (RDX)
// Written by John Underhill, September 10, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_RDX_H
#define _CEXENGINE_RDX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// <h3>RDX: An extended implementation of the Rijndael encryption cipher.</h3>
/// <para>RDX is an implementation of the Rijndael<cite>Rijndael</cite> encryption algorithm, extended to use a 512 bit key</para>
/// </summary> 
/// 
/// <example>
/// <description>Example using an <c>ICipherMode</c> interface:</description>
/// <code>
/// CTR cipher(new RDX());
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
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode">CEX::Cipher::Symmetric::Block::Mode::ICipherMode Interface</seealso>
/// 
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>Valid Key sizes are 128, 192, 256, and 512 bit.</description></item>
/// <item><description>Valid block sizes are 16 and 32 bytes wide.</description></item>
/// </list>
/// 
/// <para>RDX is an implementation of the Rijndael<cite>Rijndael</cite> encryption algorithm, the same one used in the AES<cite>Fips 197</cite> standard. 
/// What has been done is to extend Rijndael so that it now accepts the longer key length (512 bits). 
/// The extended key length provides more security against attacks that attempt to brute force the key, and also adds eight more rounds of diffusion.</para>
/// 
/// <para>The increased number of rounds brings the total from 14 rounds with a 256 bit key, to 22 rounds with the 512 bit key size. 
/// These added passes through the rounds function further disperse the input through row and column transpositions, and XOR’s with a longer expanded key array.</para>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>AES Proposal: <see href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael</see>.</description></item>
/// <item><description>Fips 197: Announcing the <see href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">Advanced Encryption Standard (AES)</see></description></item>
/// </list> 
/// 
/// <description><h4>Code Base Guides:</h4></description>
/// <list type="table">
/// <item><description>Inspired in part by the Mono: <see href="https://github.com/mono/mono/blob/effa4c07ba850bedbe1ff54b2a5df281c058ebcb/mcs/class/corlib/System.Security.Cryptography/RijndaelManagedTransform.cs">RijndaelManagedTransform</see> class.</description></item>
/// </list>
/// </remarks>
class RDX : public IBlockCipher
{
protected:
	static constexpr unsigned int BLOCK16 = 16;
	static constexpr unsigned int BLOCK32 = 32;

	unsigned int _blockSize;
	bool _isDestroyed;
	std::vector<uint> _expKey;
	bool _isEncryption;
	bool _isInitialized;
	std::vector<unsigned int> _legalKeySizes;
	std::vector<unsigned int> _legalRounds;
	unsigned int _NB;
	unsigned int _NK;
	unsigned int _NR;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide. 
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const unsigned int BlockSize() { return _blockSize; }

	/// <summary>
	/// Get: Initialized for encryption, false for decryption.
	/// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
	/// </summary>
	virtual const bool IsEncryption() { return _isEncryption; }

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<unsigned int> &LegalKeySizes() { return _legalKeySizes; }

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<unsigned int> &LegalRounds() { return _legalRounds; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char* Name() { return "RDX"; }

	/// <summary>
	/// Get: The number of diffusion rounds processed by the transform
	/// </summary>
	virtual const unsigned int Rounds() 
	{ 
		if (!_isInitialized)
			throw CryptoSymmetricCipherException("RDX:Rounds", "Cipher must be initialized before rounds can be determined!");

		return _NR; 
	}

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	///
	/// <param name="BlockSize">Cipher input <see cref="BlockSize"/>. The <see cref="LegalBlockSizes"/> property contains available sizes. Default is 16 bytes.</param>
	RDX(unsigned int BlockSize = BLOCK16)
		:
		_blockSize(BlockSize),
		_isEncryption(false),
		_isInitialized(false),
		_legalKeySizes(4, 0),
		_legalRounds(4, 0),
		_NB(4),
		_NK(16),
		_NR(22)
	{
		_legalKeySizes = { 16, 24, 32, 64 };
		_legalRounds = { 10, 12, 14, 22 };
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~RDX()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
	/// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="Output">Decrypted bytes</param>
	virtual void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Decrypted bytes</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void DecryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

	/// <summary>
	/// Clear the buffers and reset
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Encrypt a block of bytes.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Bytes to Encrypt</param>
	/// <param name="Output">Encrypted bytes</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Bytes to Encrypt</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Encrypted bytes</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

	/// <summary>
	/// Initialize the Cipher.
	/// </summary>
	/// 
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="KeyParam">Cipher key container. <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	virtual void Initialize(bool Encryption, const KeyParams &KeyParam);

	/// <summary>
	/// Transform a block of bytes.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Bytes to Encrypt or Decrypt</param>
	/// <param name="Output">Encrypted or Decrypted bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Bytes to Encrypt</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Encrypted bytes</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

protected:
	void Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void Decrypt32(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void Encrypt32(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void ExpandKey(const std::vector<byte> &Key, bool Encryption);
	uint SubByte(uint Rot);
};

NAMESPACE_BLOCKEND
#endif

