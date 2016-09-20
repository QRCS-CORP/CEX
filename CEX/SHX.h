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
// Portions of this cipher based on Serpent written by Ross Anderson, Eli Biham and Lars Knudsen:
// Serpent <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.
// 
// The sboxes are based on the work of Brian Gladman and Sam Simpson.
// <a href="http://fp.gladman.plus.com/cryptography_technology/serpent/">Specification</a>.
// Copyright: Dr B. R Gladman (gladman@seven77.demon.co.uk) and 
// Sam Simpson (s.simpson@mia.co.uk), 17th December 1998.
// 
// Implementation Details:
// An implementation based on the Serpent block cipher,
// using HKDF with a selectable Message Digest for expanded key generation.
// Serpent HKDF Extended (SHX)
// Written by John Underhill, November 15, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SHX_H
#define _CEXENGINE_SHX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// SHX: A Serpent cipher extended with an (optional) HKDF powered Key Schedule.
/// <para>SHX is a Serpent implementation that can use a standard configuration on key sizes up to 256 bits, 
/// an extended key size of 512 bits, or unlimited key sizes in extended operation (HKDF) mode. 
/// In extended mode, the number of transformation rounds can be user assigned (through the constructor) to between 32 and 128 rounds.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(new SHX());
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
/// <item><description>HKDF Digest engine is definable through the SHX(uint, Digests) Constructor parameter: KDFEngine.</description></item>
/// <item><description>The extended Key Schedule is (optionally) powered by a Hash based Key Derivation Function using a user definable Digest engine.</description></item>
/// <item><description>Minimum HKDF key size is the Digests Hash output size, recommended is 2* the minimum or increments of (N * Digest Hash Size) in bytes.</description></item>
/// <item><description>Valid block size is 16 bytes wide.</description></item>
/// <item><description>Valid Rounds assignments are set at 32 in standard mode, and 32, 40, 48, 56, 64.. 128, in extended mode.</description></item>
/// </list>
/// 
/// <para>When using SHA-2 256, a minimum key size for SHX is 32 bytes, further blocks of can be added to the key so long as they align; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum.</para> 
/// 
/// <para>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake, Keccak, SHA-2 or Skein.
/// Correct key sizes can be determined at run time using the <see cref="LegalKeySizes"/> property.
/// When using the extended mode, the legal key sizes are determined based on the selected digests hash size, 
/// ex. SHA256 the minimum legal key size is 256 bits, the recommended size is 2* the hash size.</para>
/// 
/// <para>In extended mode, the number of diffusion rounds processed within the ciphers rounds function can be defined; adding rounds creates a more diffused cipher output, 
/// making the resulting cipher-text more difficult to cryptanalyze. 
/// SHX is capable of processing up to 128 rounds, that is four times the number of rounds used in a standard implementation of Serpent. 
/// Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</para>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Serpent: <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.</description></item>
/// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</a>.</description></item>
/// <item><description>HKDF <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>.</description></item>
/// <item><description>SHA3 <a href="https://131002.net/blake/blake.pdf">The Blake digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
/// </list>
/// </remarks>
class SHX : public IBlockCipher
{
private:
	static constexpr size_t BLOCK_SIZE = 16;
	static constexpr size_t LEGAL_KEYS = 10;
	static constexpr size_t MAX_ROUNDS = 64;
	static constexpr size_t MIN_ROUNDS = 32;
	static constexpr uint PHI = 0x9E3779B9;
	static constexpr size_t ROUNDS32 = 32;
	static constexpr size_t ROUNDS40 = 40;

	bool m_destroyEngine;
	size_t m_dfnRounds;
	std::vector<uint> m_expKey;
	std::vector<byte> m_hkdfInfo;
	size_t m_ikmSize;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	IDigest* m_kdfEngine;
	Digests m_kdfEngineType;
	std::vector<size_t> m_legalKeySizes;
	std::vector<size_t> m_legalRounds;

	SHX(const SHX&) = delete;
	SHX& operator=(const SHX&) = delete;

public:

	//~~~Properties~~~//

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
	const std::vector<byte> &DistributionCode() { return m_hkdfInfo; }

	/// <summary>
	/// Get: The block ciphers type name
	/// </summary>
	virtual const BlockCiphers Enumeral() { return BlockCiphers::SHX; }

	/// <summary>
	/// Get: Initialized for encryption, false for decryption.
	/// <para>Value set in <see cref="Initialize(bool, KeyParams)"/>.</para>
	/// </summary>
	virtual const bool IsEncryption() { return m_isEncryption; }

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<size_t> &LegalKeySizes() { return m_legalKeySizes; }

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<size_t> &LegalRounds() { return m_legalRounds; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char* Name() { return "SHX"; }

	/// <summary>
	/// Get: The number of diffusion rounds processed by the transform
	/// </summary>
	virtual const size_t Rounds() { return m_dfnRounds; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class with a Digest instance
	/// </summary>
	///
	/// <param name="KdfEngine">The Key Schedule HKDF digest engine instance; can be any one of the message Digest implementations.</param>
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 40 rounds.</param>
	///
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	SHX(IDigest *KdfEngine, size_t Rounds = ROUNDS40)
		:
		m_destroyEngine(false),
		m_isDestroyed(false),
		m_dfnRounds(Rounds),
		m_hkdfInfo(0, 0),
		m_ikmSize(0),
		m_isEncryption(false),
		m_isInitialized(false),
		m_kdfEngine(KdfEngine),
		m_legalKeySizes(LEGAL_KEYS, 0),
		m_legalRounds(5, 0)
	{
#if defined(DEBUGASSERT_ENABLED)
		assert(KdfEngine != 0);
		assert(Rounds % 8 == 0 && Rounds >= 32 && Rounds <= 64);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (KdfEngine == 0)
			throw CryptoSymmetricCipherException("SHX:CTor", "Invalid null parameter! The digest instance can not be null.");
		if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64)
			throw CryptoSymmetricCipherException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, 64.");
#endif

		std::string info = "SHX version 1 information string";
		m_hkdfInfo.reserve(info.size());
		for (size_t i = 0; i < info.size(); ++i)
			m_hkdfInfo.push_back(info[i]);

		m_legalRounds = { 32, 40, 48, 56, 64 };
		m_kdfEngineType = KdfEngine->Enumeral();
		// set the hmac key size
		m_ikmSize = m_kdfEngine->DigestSize();

		// add standard key lengths
		m_legalKeySizes[0] = 16;
		m_legalKeySizes[1] = 24;
		m_legalKeySizes[2] = 32;
		m_legalKeySizes[3] = 64;

		for (size_t i = 4; i < m_legalKeySizes.size(); i++)
			m_legalKeySizes[i] = (m_legalKeySizes[3] + m_ikmSize * (i - 3));
	}

	/// <summary>
	/// Initialize the class
	/// </summary>
	///
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. 
	/// Default is 32 rounds with a 128-256 bit key, 40 rounds with a 512 bit key.</param>
	/// <param name="KdfEngineType">The Key Schedule KDF digest engine; can be any one of the Digest implementations. 
	/// The default engine is None, which invokes the standard key schedule mechanism.</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	SHX(size_t Rounds = ROUNDS32, Digests KdfEngineType = Digests::None)
		:
		m_isDestroyed(false),
		m_destroyEngine(true),
		m_dfnRounds(Rounds),
		m_hkdfInfo(0, 0),
		m_ikmSize(0),
		m_isEncryption(false),
		m_isInitialized(false),
		m_kdfEngine(0),
		m_kdfEngineType(KdfEngineType),
		m_legalKeySizes(LEGAL_KEYS, 0),
		m_legalRounds(0, 0)
	{
		// add standard key lengths
		m_legalKeySizes[0] = 16;
		m_legalKeySizes[1] = 24;
		m_legalKeySizes[2] = 32;
		m_legalKeySizes[3] = 64;

		if (KdfEngineType != CEX::Enumeration::Digests::None)
		{
#if defined(DEBUGASSERT_ENABLED)
			assert(Rounds % 8 == 0 && Rounds >= 32 && Rounds <= 64);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
			if (Rounds != 32 && Rounds != 40 && Rounds != 48 && Rounds != 56 && Rounds != 64)
				throw CryptoSymmetricCipherException("SHX:CTor", "Invalid rounds size! Sizes supported are 32, 40, 48, 56, and 64.");
#endif

			std::string info = "SHX version 1 information string";
			m_hkdfInfo.reserve(info.size());
			for (size_t i = 0; i < info.size(); ++i)
				m_hkdfInfo.push_back(info[i]);

			m_legalRounds.resize(5);
			m_legalRounds = { 32, 40, 48, 56, 64 };
			// set the hmac key size
			m_ikmSize = GetIkmSize(KdfEngineType);

			// hkdf extended key sizes
			for (size_t i = 4; i < m_legalKeySizes.size(); ++i)
				m_legalKeySizes[i] = (m_legalKeySizes[3] + m_ikmSize * (i - 3));
		}
		else
		{
			m_legalKeySizes.resize(4);
			m_legalRounds.resize(2);
			m_legalRounds = { 32, 40 };
		}
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SHX()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

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
	/// <param name="KeyParam">Cipher key container.<para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
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
	/// <param name="Input">Input message to Transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Starting offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform 4 blocks of bytes.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least 4 * <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input message to Transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Starting offset in the Output array</param>
	virtual void Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Transform 8 blocks of bytes.
	/// <para><see cref="Initialize(bool, KeyParams)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least 8 * <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input message to Transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Starting offset in the Output array</param>
	virtual void Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void ExpandKey(const std::vector<byte> &Key);
	void Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	uint GetIkmSize(Digests DigestType);
	IDigest* GetDigest(Digests DigestType);
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);
};

NAMESPACE_BLOCKEND
#endif
