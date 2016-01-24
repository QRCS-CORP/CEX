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
// Principal Algorithms:
// Portions of this cipher partially based on the Twofish block cipher designed by Bruce Schneier, John Kelsey, 
// Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
// Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</see>.
// 
// Implementation Details:
// An implementation based on the Twofish block cipher,
// using HKDF with a selectable Message Digest for expanded key generation.
// TwoFish HKDF Extended (THX)
// Written by John Underhill, December 11, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_THX_H
#define _CEXENGINE_THX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// THX: An extended implementation of the Twofish encryption cipher.
/// <para>THX is an implementation of the Twofish block cipher, extended to use a 512 bit key.</para>
/// </summary>
///
/// <example>
/// <description>Example using an <c>ICipherMode</c> interface:</description>
/// <code>
/// CTR cipher(new THX());
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
/// <remarks>
/// <description><h4>Implementation Notes:</h4></description>
/// <list type="bullet">
/// <item><description>Valid Key sizes are 128, 192, 256 and 512 bits (16, 24, 32 and 64 bytes).</description></item>
/// <item><description>Block size is 16 bytes wide.</description></item>
/// <item><description>Valid Rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16.</description></item>
/// </list>
/// 
/// <para>THX extends the original design allowing it to accept the longer key length (512 bits).</para>
/// 
/// <para>The number of diffusion rounds processed in the ciphers transformation method has also been extended, and is user configurable; 
/// from the original 16 rounds, to a full 32 rounds of transformation. 
/// This increase in key size eliminates brute force attacks, and the increase in the number of diffusion rounds makes cryptanalysis far more difficult.</para>
/// 
/// <description><h4>Guiding Publications:</h4></description>
/// <list type="number">
/// <item><description>Twofish: <see href="https://www.schneier.com/paper-twofish-paper.pdf">A 128-Bit Block Cipher</see>.</description></item>
/// </list>
/// </remarks>
class THX : public IBlockCipher
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 16;
	static constexpr unsigned int DEFAULT_SUBKEYS = 40;
	static constexpr unsigned int GF256_FDBK = 0x169; // primitive polynomial for GF(256)
	static constexpr unsigned int GF256_FDBK_2 = GF256_FDBK / 2;
	static constexpr unsigned int GF256_FDBK_4 = GF256_FDBK / 4;
	static constexpr unsigned int KEY_BITS = 256;
	static constexpr unsigned int LEGAL_KEYS = 14;
	static constexpr unsigned int MAX_STDKEY = 64;
	static constexpr unsigned int ROUNDS16 = 16;
	static constexpr unsigned int RS_GF_FDBK = 0x14D; // field generator
	static constexpr unsigned int SK_BUMP = 0x01010101;
	static constexpr unsigned int SK_ROTL = 9;
	static constexpr unsigned int SK_STEP = 0x02020202;
	static constexpr unsigned int SBOX_SIZE = 1024;

	bool _destroyEngine;
	unsigned int _dfnRounds;
	std::vector<uint> _expKey;
	std::vector<byte> _hkdfInfo;
	unsigned int _ikmSize;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	IDigest* _kdfEngine;
	Digests _kdfEngineType;
	std::vector<unsigned int> _legalKeySizes;
	std::vector<unsigned int> _legalRounds;
	std::vector<uint> _sprBox;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide.
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const unsigned int BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get/Set: Sets the Info value in the HKDF initialization parameters.
	/// <para>Must be set before <see cref="Initialize(bool, KeyParams)"/> is called.
	/// Changing this code will create a unique distribution of the cipher.
	/// Code can be either a zero byte array, or a multiple of the HKDF digest engines return size.</para>
	/// </summary>
	///
	/// <exception cref="CryptoSymmetricCipherException">Thrown if an invalid distribution code is used</exception>
	const std::vector<byte> &DistributionCode() { return _hkdfInfo; }

	/// <summary>
	/// Get: The block ciphers type name
	/// </summary>
	virtual const BlockCiphers Enumeral() { return BlockCiphers::THX; }

	/// <summary>
	/// Get/Set: Specify the size of the HMAC key; extracted from the cipher key.
	/// <para>This property can only be changed before the Initialize function is called.</para>
	/// <para>Default is the digest return size; can only be a multiple of that length.
	/// Maximum size is the digests underlying block size; if the key
	/// is longer than this, the size will default to the block size.</para>
	/// </summary>
	unsigned int &IkmSize() { return _ikmSize; }

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
	virtual const char* Name() { return "THX"; }

	/// <summary>
	/// Get: The number of diffusion rounds processed by the transform
	/// </summary>
	virtual const unsigned int Rounds() { return _dfnRounds; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class with a Digest instance
	/// </summary>
	/// 
	/// <param name="KdfEngine">The Key Schedule KDF digest engine; can be any one of the <see cref="Digests">Digest</see> implementations.</param>
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 16 rounds.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(IDigest *KdfEngine, unsigned int Rounds = ROUNDS16)
		:
		_destroyEngine(false),
		_dfnRounds(Rounds),
		_hkdfInfo(0, 0),
		_ikmSize(0),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_kdfEngine(KdfEngine),
		_legalKeySizes(LEGAL_KEYS, 0),
		_legalRounds(9, 0),
		_sprBox(SBOX_SIZE, 0)
	{
		if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
			throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

		std::string info = "THX version 1 information string";
		_hkdfInfo.reserve(info.size());
		for (unsigned int i = 0; i < info.size(); ++i)
			_hkdfInfo.push_back(info[i]);

		_legalRounds = { 16, 18, 20, 22, 24, 26, 28, 30, 32 };
		_kdfEngineType = KdfEngine->Enumeral();
		// set the hmac key size
		_ikmSize = _ikmSize == 0 ? _kdfEngine->DigestSize() : _ikmSize;
		// add standard key lengths
		_legalKeySizes[0] = 16;
		_legalKeySizes[1] = 24;
		_legalKeySizes[2] = 32;
		_legalKeySizes[3] = 64;

		for (unsigned int i = 4; i < _legalKeySizes.size(); i++)
			_legalKeySizes[i] = (_kdfEngine->BlockSize() * (i - 3)) + _ikmSize;
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 16 rounds.</param>
	/// <param name="KdfEngineType">The Key Schedule KDF digest engine; can be any one of the <see cref="Digests">Digest</see> implementations. The default engine is SHA512.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(unsigned int Rounds = ROUNDS16, Digests KdfEngineType = Digests::SHA512)
		:
		_destroyEngine(true),
		_dfnRounds(Rounds),
		_hkdfInfo(0, 0),
		_ikmSize(0),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_kdfEngineType(KdfEngineType),
		_legalKeySizes(LEGAL_KEYS, 0),
		_legalRounds(9, 0),
		_sprBox(SBOX_SIZE, 0)
	{
		if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
			throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

		std::string info = "THX version 1 information string";
		_hkdfInfo.reserve(info.size());
		for (unsigned int i = 0; i < info.size(); ++i)
			_hkdfInfo.push_back(info[i]);

		_legalRounds = { 16, 18, 20, 22, 24, 26, 28, 30, 32 };
		// set the hmac key size
		_ikmSize = _ikmSize == 0 ? GetIkmSize(KdfEngineType) : _ikmSize;
		// add standard key lengths
		_legalKeySizes[0] = 16;
		_legalKeySizes[1] = 24;
		_legalKeySizes[2] = 32;
		_legalKeySizes[3] = 64;

		int dgtblock = GetSaltSize(KdfEngineType);

		// hkdf extended key sizes
		for (unsigned int i = 4; i < _legalKeySizes.size(); ++i)
			_legalKeySizes[i] = (dgtblock * (i - 3)) + _ikmSize;
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~THX()
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
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="Output">Output product of Transform</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
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
	/// <param name="Input">Input bytes to Transform or Decrypt</param>
	/// <param name="Output">Output product of Transform</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);

protected:
	void ExpandKey(const std::vector<byte> &Key);
	void Decrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const unsigned int InOffset, std::vector<byte> &Output, const unsigned int OutOffset);
	IDigest* GetDigest(Digests DigestType);
	int GetIkmSize(Digests DigestType);
	int GetSaltSize(Digests DigestType);
	uint MDSEncode(uint K0, uint K1);
	uint THX::Mix32(const uint X, const std::vector<uint> &Key, const unsigned int Count);
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);

	inline uint Fe0(uint X)
	{
		return _sprBox[2 * (byte)X] ^
			_sprBox[2 * (byte)(X >> 8) + 0x001] ^
			_sprBox[2 * (byte)(X >> 16) + 0x200] ^
			_sprBox[2 * (byte)(X >> 24) + 0x201];
	}

	inline uint Fe3(uint X)
	{
		return _sprBox[2 * (byte)(X >> 24)] ^
			_sprBox[2 * (byte)X + 0x001] ^
			_sprBox[2 * (byte)(X >> 8) + 0x200] ^
			_sprBox[2 * (byte)(X >> 16) + 0x201];
	}

	inline uint LFSR1(uint X)
	{
		return (X >> 1) ^ (((X & 0x01) != 0) ? GF256_FDBK_2 : 0);
	}

	inline uint LFSR2(uint X)
	{
		return (X >> 2) ^ (((X & 0x02) != 0) ? GF256_FDBK_2 : 0) ^
			(((X & 0x01) != 0) ? GF256_FDBK_4 : 0);
	}

	inline uint MX(uint X)
	{
		return X ^ LFSR2(X);
	}

	inline uint MXY(uint X)
	{
		return X ^ LFSR1(X) ^ LFSR2(X);
	}

};

NAMESPACE_BLOCKEND
#endif

