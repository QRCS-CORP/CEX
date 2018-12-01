// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Principal Algorithms:
// Cipher implementation based on the Rijndael block cipher designed by Joan Daemen and Vincent Rijmen:
// Rijndael <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Specification</a>.
// AES specification <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">Fips 197</a>.
// 
// Implementation Details:
// An AES-NI implementation based on the Rijndael block cipher, 
// using HKDF with a selectable Message Digest for expanded key generation.
// AES-NI HKDF Extended (AHX)
// Written by John Underhill, May 21, 2016
// Updated October 20, 2016
// Updated April 16, 2017
// Updated November 30, 2018
// Contact: develop@vtdev.com

#ifndef CEX_AHX_H
#define CEX_AHX_H

#include "IBlockCipher.h"
#if defined(__AVX__)
#	include <wmmintrin.h>
#endif

NAMESPACE_BLOCK

#if defined(__AVX__)

/// <summary>
/// A Rijndael cipher using either standard modes, or extended modes of operation with HKDF(SHA2) or cSHAKE powered key schedule and increased transformation rounds.
/// </summary> 
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(Enumeration::BlockCiphers::AHX);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt a block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Description:</description>
/// <para>AHX is a Rijndael implementation that can use either a standard configuration with key sizes of 16, 24, and 32 bytes (128, 192, and 256-bits), 
/// or an extended mode using key sizes of 32, 64, and 128 bytes, (256, 512, and 1024 bits). \n
/// In extended mode, the number of transformation rounds are set to 22, 30 and 38, corresponding to the 256, 512, and 1024 input cipher key sizes. \n
/// Increasing the number of transformation rounds processed by the ciphers transformation function creates a more diffused output, making the resulting cipher-text more difficult to cryptanalyze. \n
/// AHX is capable of processing up to 38 rounds, that is 24 rounds more than a standard implementation of AES-256. 
/// </para>
///
/// <description>Implementation Notes:</description>
/// <para>The key schedule in AHX, and the number of transformation rounds processed are the difference between the extended mode operations, and a standard version of AES.
/// The standard Rijndael Key Schedule processes 128, 192, and 256 bit keys, and a fixed set of transformation rounds of 10, 12, and 14, the extended version of the cipher uses 256, 512, and 1024-bit keys processing 22, 30, and 38 rounds. \n
/// AHX extended mode can use an HMAC based Key Derivation Function; HKDF(HMAC(SHA2)) or the Keccak XOF function cSHAKE, to expand the input cipher key to create the internal round-key integer array. \n
/// This provides better security, and allows for an implemetation to safely use an increased number of transformation rounds further strengthening the cipher. \n
/// The DistributionCode array is a user-definable a cipher-tweak, and can be used to create a unique cipher-text output. \n
/// This tweak array is set as either the information string for HKDF, or as the cSHAKE customization string.</para>
/// <para>When using the extended mode of the cipher, the minimum key size is 32 bytes (256 bits), and valid key sizes are 256, 512, and 1024 bits long. \n
/// AHX is capable of processing up to 38 transformation rounds in extended mode; a 256-bit key uses 22 rounds, a 512-bit key 30 rounds, and a 1024-bit key is set to 38 rounds.</para>
/// 
/// <list type="bullet">
/// <item><description>This cipher should only be used in conjunction with an AEAD or standard cipher mode, or as an component in another construction, ex. CMAC.</item>
/// <item><description>Valid key sizes can be determined at using the <see cref="LegalKeySizes"/> property.</description> collection.</item>
/// <item><description>The internal block-size is fixed at 16 bytes (128 bits) wide.</description></item>
/// <item><description>The cipher can process 128, 192, and 256-bit keys in standard mode, and 256, 512, and 1024-bit keys in extended mode.</description></item>
/// <item><description>Transformation rounds assignments are 10, 12, and 14 in standard modes, and 22, 30, and 38 rounds with 256, 512, and 1024-bit length keys.</description></item>
/// <item><description>The DistributionCode array is a user-definable cipher tweak, this can be used to create a unique cipher-text output with a secondary secret.</description></item>
/// <item><description>Extended mode is set through the constructors BlockCipherExtensions parameter to either None for standard mode, or HKDF(SHA2-256), HKDF(SHA2-512), cSHAKE256, cSHAKE512, or cSHAKE1024 for extended mode operation.</description></item>
/// <item><description>It is recommended that in extended mode, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or HKDF(SHA2-512) for a 512-bit key.</description></item>
/// </list>
///
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</a>.</description></item>
/// <item><description>HKDF <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class AHX final : public IBlockCipher
{
private:

	static const size_t AES256_ROUNDS = 14;
	static const size_t AES512_ROUNDS = 22;
	static const size_t BLOCK_SIZE = 16;
	static const std::string CIPHER_NAME;
	static const std::string CLASS_NAME;
	static const std::string DEF_DSTINFO;
	static const size_t MAX_ROUNDS = 38;
	static const size_t MIN_ROUNDS = 10;
	// size of state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	BlockCipherExtensions m_cprExtension;
	bool m_destroyEngine;
	std::vector<byte> m_distCode;
	size_t m_distCodeMax;
	std::vector<__m128i> m_expKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::unique_ptr<IKdf> m_kdfGenerator;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_rndCount;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	AHX(const AHX&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	AHX& operator=(const AHX&) = delete;

	/// <summary>
	/// Instantiate the class with an optional block-cipher extension type.
	/// <para>It is recommended that in extended mode operation, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or, HKDF(SHA2-512) for a 512-bit key.</para>
	/// </summary>
	/// 
	/// <param name="CipherExtensionType">Sets the optional Key Schedule key-expansion engine; valid options are cSHAKE, HKDF, or None for standard mode. 
	/// <para>The default engine is None, which invokes the standard key schedule mechanism.</para></param>
	AHX(BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None);

	/// <summary>
	/// Instantiate the class with a Key Derivation Function instance.
	/// <para>It is recommended that in extended mode operation, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or, HKDF(SHA2-512) for a 512-bit key.</para>
	/// </summary>
	///
	/// <param name="Kdf">The Key Schedule KDF engine instance; can not be null.</param>
	AHX(Kdf::IKdf* Kdf);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~AHX() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide.
	/// Value set in class constructor.</para>
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The extended key-schedule KDF generator type
	/// </summary>
	const BlockCipherExtensions CipherExtension() override;

	/// <summary>
	/// Read/Write: Reads or Sets the Info (personalization string) value in the HKDF initialization parameters.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// Code can be sized as either a zero byte array, or any length up to the DistributionCodeMax size.
	/// For best security, the distribution code should be random, secret, and equal in length to the DistributionCodeMax size.
	/// Note: If the Info parameter of an ISymmetricKey is non-zero, it will overwrite the distribution code.</para>
	/// </summary>
	std::vector<byte> &DistributionCode() override;

	/// <summary>
	/// Read Only: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary source of entropy (secret) in the HKDF key expansion phase.
	/// For best security, the distribution code should be random, secret, and equal in size to this value.</para>
	/// </summary>
	const size_t DistributionCodeMax() override;

	/// <summary>
	/// Read Only: The block ciphers type name
	/// </summary>
	const BlockCiphers Enumeral() override;

	/// <summary>
	/// Read Only: Initialized for encryption, false for decryption.
	/// <para>Value set in <see cref="Initialize(bool, ISymmetricKey)"/>.</para>
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Read Only: Cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Available Encryption Key Sizes in bytes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The block ciphers class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The number of transformation rounds processed by the transform
	/// </summary>
	const size_t Rounds() override;

	/// <summary>
	/// Read Only: The sum size in bytes (plus some allowance for externals) of the classes persistant state.
	/// <para>Used in the parallel block size calculations, to reduce the occurence of L1 cache eviction of hot tables and class variables. 
	/// This is a timing and performance optimization, see the ParallelOptions class for more details.</para>
	/// </summary>
	const size_t StateCacheSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
	/// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="Output">Decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">Decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Encrypt a block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Encrypt a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	///
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="KeyParams">Cipher key container. 
	/// <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
	///
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Transform a block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform or Decrypt</param>
	/// <param name="Output">The output array of transformed bytes</param>
	void Transform(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Transform a block of bytes with offset parameters.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output arrays with Offsets must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset in the output array</param>
	void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Transform 4 blocks of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least 4 * <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset in the output array</param>
	void Transform512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Transform 8 blocks of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least 8 * <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset in the output array</param>
	void Transform1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Transform 16 blocks of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least 16 * <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset in the Input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset in the output array</param>
	void Transform2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

private:

	void Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt512(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt1024(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt2048(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void ExpandKey(bool Encryption, const std::vector<byte> &Key);
	void ExpandRotBlock(std::vector<__m128i> &Key, __m128i* K1, __m128i* K2, __m128i KR, size_t Offset);
	void ExpandRotBlock(std::vector<__m128i> &Key, const size_t Index, const size_t Offset);
	void ExpandSubBlock(std::vector<__m128i> &Key, const size_t Index, const size_t Offset);
	void LoadState();
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);
};

#endif
NAMESPACE_BLOCKEND
#endif
