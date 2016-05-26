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
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <see href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</see>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation of the Serpent block cipher,
// extended to 512 bit keys and up to 64 rounds.
// Serpent Extended (SPX)
// Written by John Underhill, November 14, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SPX_H
#define _CEXENGINE_SPX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// <h3>SPX: An extended implementation of the Serpent encryption cipher.</h3>
/// <para>SPX is an implementation of the Serpent<cite>Serpent</cite> block cipher, extended to use a 512 bit key.</para>
/// </summary>
/// 
/// <example>
/// <description>Example using an <c>ICipherMode</c> interface:</description>
/// <code>
/// CTR cipher(new SPX());
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
/// <item><description>Valid Key sizes are 128, 192, 256 and 512 bits (16, 24, 32 and 64 bytes).</description></item>
/// <item><description>Block size is 16 bytes wide.</description></item>
/// <item><description>Valid Rounds assignments are 32, 40, 48, 56, and 64, default is 32.</description></item>
/// </list>
/// 
/// <para>The Key Schedule has been written so that it can both accept a larger key size of 512 bits, 
/// and produce the required number of working keys with a variable number of diffusion rounds.</para>
/// 
/// <para>The diffusion rounds, (the portion of the cipher that does the actual mixing of plaintext into ciphertext),
/// is exactly the same with every key length, only it can now process an increased number of rounds, from 32; 
/// the standard, up to 64 rounds. 
/// This increase in the ciphers diffusion cycles makes linear and differential analysis more difficult, 
/// and the larger key size ensures that it can not be brute forced.</para>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>Serpent: <see href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</see>.</description></item>
/// </list>
/// 
/// <description><h4>Code Base Guides:</h4></description>
/// <list type="table">
/// <item><description>Inspired in part by the Bouncy Castle Java <see href="http://bouncycastle.org/latest_releases.html">Release 1.51</see>.</description></item>
/// </list> 
/// </remarks>
class SPX : public IBlockCipher
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 16;
	static constexpr unsigned int MAX_ROUNDS = 64;
	static constexpr unsigned int MIN_ROUNDS = 32;
	static constexpr uint  PHI = 0x9E3779B9;
	static constexpr unsigned int ROUNDS32 = 32;

	unsigned int _dfnRounds;
	std::vector<uint> _expKey;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	std::vector<unsigned int> _legalKeySizes;
	std::vector<unsigned int> _legalRounds;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide.
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const unsigned int BlockSize() { return BLOCK_SIZE; }

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
	virtual const char* Name() { return "SPX"; }

	/// <summary>
	/// Get: The number of diffusion rounds processed by the transform
	/// </summary>
	virtual const unsigned int Rounds() { return _dfnRounds; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	///
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes.  Default is 32 rounds.</param>
	///
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	SPX(unsigned int Rounds = ROUNDS32)
		:
		_dfnRounds(Rounds),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_legalKeySizes(4, 0),
		_legalRounds(8, 0)
	{
		if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64 && Rounds != 80 && Rounds != 96 && Rounds != 128)
			throw CryptoSymmetricCipherException("SPX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64, 80, 96 and 128.");

		_legalRounds = { 32, 40, 48, 56, 64, 80, 96, 128 };
		_legalKeySizes = { 16, 24, 32, 64 };
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SPX()
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
	/// <exception cref="CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
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
	void CopyVector(const std::vector<uint> &Input, unsigned int InOffset, std::vector<uint> &Output, unsigned int OutOffset, unsigned int Length);
	void ExpandKey(const std::vector<byte> &Key);
	void Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void LinearTransform(uint &R0, uint &R1, uint &R2, uint &R3);
	void InverseTransform(uint &R0, uint &R1, uint &R2, uint &R3);
};

NAMESPACE_BLOCKEND
#endif

