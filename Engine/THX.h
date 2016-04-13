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
// Twofish: <a href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</a>.
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
/// THX: A Twofish Cipher extended with an (optional) HKDF powered Key Schedule.
/// <para>THX is a Twofish implementation that can use a standard configuration on key sizes up to 256 bits, 
/// an extended key size of 512 bits, or unlimited key sizes greater than 64 bytes. 
/// On <see cref="LegalKeySizes"/> larger than 64 bytes, an HKDF bytes generator is used to expand the <c>working key</c> integer array.
/// In extended mode, the number of <c>transformation rounds</c> can be user assigned (through the constructor) to between 16 and 32 rounds.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(new THX());
/// // initialize for encryption
/// cipher.Initialize(true, KeyParams(Key, IV));
/// // encrypt a block
/// cipher.Transform(Input, Output);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::BlockCiphers"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// <seealso cref="CEX::Digest::IDigest"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>HKDF Digest engine is definable through the <see cref="THX(uint, Digests)">Constructor</see> parameter: KeyEngine.</description></item>
/// <item><description>Key Schedule is (optionally) powered by a Hash based Key Derivation Function using a definable Digest.</description></item>
/// <item><description>Minimum HKDF key size is the Digests Hash output size, recommended is 2* the minimum or increments of (N * Digest Hash Size) in bytes.</description></item>
/// <item><description>Valid block size is 16 bytes wide.</description></item>
/// <item><description>Valid Rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16 (128-256 bit key), with a 512 bit key assigned 20 rounds.</description></item>
/// </list>
/// 
/// <description>HKDF Bytes Generator:</description>
/// <para>HKDF: is a key derivation function that uses a Digest HMAC (Hash based Message Authentication Code) as its random engine. 
/// This is one of the strongest methods available for generating pseudo-random keying material, and far superior in entropy dispersion to Rijndael, or even Serpents key schedule. 
/// HKDF uses up to three inputs; a nonce value called an information string, an Ikm (Input keying material), and a Salt value. 
/// The HMAC RFC 2104, recommends a key size equal to the digest output, in the case of SHA512, 64 bytes, anything larger gets passed through the hash function to get the required 512 bit key size. 
/// The Salt size is a minimum of the hash functions block size, with SHA-2 512 that is 128 bytes.</para>
/// 
/// <para>When using SHA-2 256, a minimum key size for SHX is 32 bytes, further blocks of can be added to the key so long as they align; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum.</para> 
/// 
/// <para>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake, Keccak, SHA-2 or Skein.
/// Correct key sizes can be determined at run time using the <see cref="LegalKeySizes"/> property.
/// When using the extended mode, the legal key sizes are determined based on the selected digests hash size, 
/// ex. SHA256 the minimum legal key size is 256 bits, the recommended size is 2* the hash size.</para>
/// 
/// <para>The number of diffusion rounds processed within the ciphers rounds function can be defined in HKDF extended mode; 
/// adding rounds creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. 
/// THX is capable of processing up to 32 rounds, that is twice the number of rounds used in a standard implementation of Twofish. 
/// Valid rounds assignments can be found in the <see cref="LegalRounds"/> static property.</para>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</a>.</description></item>
/// <item><description>HKDF <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>.</description></item>
/// <item><description>SHA3 <a href="https://131002.net/blake/blake.pdf">The Blake digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
/// </list>
/// </remarks>
class THX : public IBlockCipher
{
private:
	static constexpr size_t BLOCK_SIZE = 16;
	static constexpr uint DEFAULT_SUBKEYS = 40;
	static constexpr uint GF256_FDBK = 0x169; // primitive polynomial for GF(256)
	static constexpr uint GF256_FDBK_2 = GF256_FDBK / 2;
	static constexpr uint GF256_FDBK_4 = GF256_FDBK / 4;
	static constexpr uint KEY_BITS = 256;
	static constexpr size_t LEGAL_KEYS = 10;
	static constexpr uint ROUNDS16 = 16;
	static constexpr uint ROUNDS20 = 20;
	static constexpr uint RS_GF_FDBK = 0x14D; // field generator
	static constexpr uint SK_BUMP = 0x01010101;
	static constexpr uint SK_ROTL = 9;
	static constexpr uint SK_STEP = 0x02020202;
	static constexpr size_t SBOX_SIZE = 1024;

	bool _destroyEngine;
	size_t _dfnRounds;
	std::vector<uint> _expKey;
	std::vector<byte> _hkdfInfo;
	size_t _ikmSize;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	CEX::Digest::IDigest* _kdfEngine;
	CEX::Enumeration::Digests _kdfEngineType;
	std::vector<size_t> _legalKeySizes;
	std::vector<size_t> _legalRounds;
	std::vector<uint> _sprBox;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide.
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const size_t BlockSize() { return BLOCK_SIZE; }

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
	virtual const CEX::Enumeration::BlockCiphers Enumeral() { return CEX::Enumeration::BlockCiphers::THX; }

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
	virtual const std::vector<size_t> &LegalKeySizes() { return _legalKeySizes; }

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<size_t> &LegalRounds() { return _legalRounds; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char* Name() { return "THX"; }

	/// <summary>
	/// Get: The number of diffusion rounds processed by the transform
	/// </summary>
	virtual const size_t Rounds() { return _dfnRounds; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class with a Digest instance
	/// </summary>
	/// 
	/// <param name="KdfEngine">The Key Schedule HKDF digest engine instance; can be any one of the Digest implementations.</param>
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes; default is 20 rounds.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(CEX::Digest::IDigest *KdfEngine, size_t Rounds = ROUNDS20)
		:
		_destroyEngine(false),
		_dfnRounds(Rounds),
		_hkdfInfo(0),
		_ikmSize(0),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_kdfEngine(KdfEngine),
		_legalKeySizes(LEGAL_KEYS, 0),
		_legalRounds(9, 0),
		_sprBox(SBOX_SIZE, 0)
	{
		if (KdfEngine == 0)
			throw CryptoSymmetricCipherException("THX:CTor", "Invalid null parameter! The digest instance can not be null.");
		if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
			throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

		std::string info = "THX version 1 information string";
		_hkdfInfo.reserve(info.size());
		for (size_t i = 0; i < info.size(); ++i)
			_hkdfInfo.push_back(info[i]);

		_legalRounds = { 16, 18, 20, 22, 24, 26, 28, 30, 32 };
		_kdfEngineType = KdfEngine->Enumeral();
		// set the hmac key size
		_ikmSize = _kdfEngine->DigestSize();

		// add standard key lengths
		_legalKeySizes[0] = 16;
		_legalKeySizes[1] = 24;
		_legalKeySizes[2] = 32;
		_legalKeySizes[3] = 64;

		for (size_t i = 4; i < _legalKeySizes.size(); i++)
			_legalKeySizes[i] = (_legalKeySizes[3] + _ikmSize * (i - 3));
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. 
	/// Default is 16 rounds, defining rounds requires HKDF extended mode.</param>
	/// <param name="KdfEngineType">The Key Schedule KDF digest engine; can be any one of the Digest implementations. 
	/// The default engine is None, which invokes the standard key schedule mechanism.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(uint Rounds = ROUNDS16, CEX::Enumeration::Digests KdfEngineType = CEX::Enumeration::Digests::None)
		:
		_destroyEngine(true),
		_dfnRounds(Rounds),
		_hkdfInfo(0),
		_ikmSize(0),
		_isDestroyed(false),
		_isEncryption(false),
		_isInitialized(false),
		_kdfEngine(0),
		_kdfEngineType(KdfEngineType),
		_legalKeySizes(LEGAL_KEYS, 0),
		_legalRounds(0, 0),
		_sprBox(SBOX_SIZE, 0)
	{
		// add standard key lengths
		_legalKeySizes[0] = 16;
		_legalKeySizes[1] = 24;
		_legalKeySizes[2] = 32;
		_legalKeySizes[3] = 64;

		if (KdfEngineType != CEX::Enumeration::Digests::None)
		{
			if (Rounds != 16 && Rounds != 18 && Rounds != 20 && Rounds != 22 && Rounds != 24 && Rounds != 26 && Rounds != 28 && Rounds != 30 && Rounds != 32)
				throw CryptoSymmetricCipherException("THX:CTor", "Invalid rounds size! Sizes supported are 16, 18, 20, 22, 24, 26, 28, 30 and 32.");

			std::string info = "THX version 1 information string";
			_hkdfInfo.reserve(info.size());
			for (size_t i = 0; i < info.size(); ++i)
				_hkdfInfo.push_back(info[i]);

			_legalRounds.resize(9);
			_legalRounds = { 16, 18, 20, 22, 24, 26, 28, 30, 32 };
			// set the hmac key size
			_ikmSize = GetIkmSize(KdfEngineType);

			// hkdf extended key sizes
			for (size_t i = 4; i < _legalKeySizes.size(); ++i)
				_legalKeySizes[i] = (_legalKeySizes[3] + _ikmSize * (i - 3));
		}
		else
		{
			_legalKeySizes.resize(4);
			_legalRounds.resize(2);
			_legalRounds = { 16, 20 };
		}
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
	virtual void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

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
	virtual void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the Cipher.
	/// </summary>
	///
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="KeyParam">Cipher key container. <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
	///
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	virtual void Initialize(bool Encryption, const CEX::Common::KeyParams &KeyParam);

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
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void ExpandKey(const std::vector<byte> &Key);
	void Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	CEX::Digest::IDigest* GetDigest(CEX::Enumeration::Digests DigestType);
	int GetIkmSize(CEX::Enumeration::Digests DigestType);
	uint MDSEncode(uint K0, uint K1);
	uint THX::Mix32(const uint X, const std::vector<uint> &Key, const size_t Count);
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);

	inline uint Fe0(uint X)
	{
		return _sprBox[2 * (byte)X] ^ _sprBox[2 * (byte)(X >> 8) + 0x001] ^ _sprBox[2 * (byte)(X >> 16) + 0x200] ^ _sprBox[2 * (byte)(X >> 24) + 0x201];
	}

	inline uint Fe3(uint X)
	{
		return _sprBox[2 * (byte)(X >> 24)] ^ _sprBox[2 * (byte)X + 0x001] ^ _sprBox[2 * (byte)(X >> 8) + 0x200] ^ _sprBox[2 * (byte)(X >> 16) + 0x201];
	}

	inline uint LFSR1(uint X)
	{
		return (X >> 1) ^ (((X & 0x01) != 0) ? GF256_FDBK_2 : 0);
	}

	inline uint LFSR2(uint X)
	{
		return (X >> 2) ^ (((X & 0x02) != 0) ? GF256_FDBK_2 : 0) ^ (((X & 0x01) != 0) ? GF256_FDBK_4 : 0);
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

