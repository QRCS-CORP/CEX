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
// An implementation based on the Rijndael block cipher, 
// using HKDF with a selectable Message Digest for expanded key generation.
// Rijndael HKDF Extended (RHX)
// Written by John Underhill, November 11, 2014
// Updated October 20, 2016
// Updated April 16, 2017
// Contact: develop@vtdev.com

#ifndef CEX_RHX_H
#define CEX_RHX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// A Rijndael Cipher extended with an (optional) HKDF powered Key Schedule
/// </summary> 
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(Enumeration::BlockCiphers::RHX);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt a block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>The key schedule in RHX is the defining difference between this and a standard version of Rijndael.
/// The standard Rijndael Key Schedule (128-256 bits), has been extended to accommodate a 512 bit key size. \n
/// RHX can (optionally) use an HMAC based Key Derivation Function (HKDF) to expand the cipher key to create the internal round key integer array.
/// This provides better security, and allows for a user assignable number of transformation rounds. \n
/// When using the HKDF extended mode, the number of transformation rounds can be set by the user (through the class constructor).
/// RHX can run between 10 and 38 rounds.</para>
///
/// <description>Changes to RHX Version 1.2:</description>
/// <para>Version 1.2 of the cipher has changes to the HKDF powered key schedule, which may make it incompatable with previous versions of the cipher. \n
/// Previous versions split the key into salt and key arrays, and processed these arrays with the HKDF Extract step, which compresses the key material into a pseudo random key used to initialize the HMAC. \n
/// The previous versions also added the Info parameter through the HKDF Initialize(key, salt, info) function. \n
/// The Info parameter is now set through a property added to the HKDF implementation, so using the Initialize function to load the Info string is no longer required. \n
/// This allows for loading the key into HKDF with the Initialize(key) function, which bypasses the extract step, but can still use the Info parameter to provide additional entropy. \n
/// The key is used by HKDF to initialize the HMAC. The HMAC key can use up to the hash functions internal block size before a compression cycle is called, reducing the key size to the hash functions output size. \n
/// The best size for maximum security is to set the HMAC key to the hash functions block size, this initializes the HMAC with a full block of keying material. \n
/// HKDF cycles it's internal state, a one byte counter, and the Info parameter through the HMAC to generate the expanded key. \n
/// For best security, it is desirable to have the HMAC process input equal to the hash functions block size, i.e. no zero byte padding is processed by the compression function. \n
/// The Info parameter can now be used as an additional source of keying material, if sized to the DistributionCodeMax() property, blocks of state+counter+info are equal to the hash functions block size,
/// this is the best possible security configuration.</para>
///
/// <para>When using SHA-2 256, a minimum key size for RHX is 32 bytes, larger lengths of input key can be used so long as it aligns; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum. \n
/// The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake2, Keccak, SHA-2 or Skein. \n
/// Valid key sizes can be determined at runtime using the <see cref="LegalKeySizes"/> property, based on the digest selected.
/// When using the extended mode, the legal key sizes are determined based on the selected digests hash output size, 
/// ex. SHA256 the minimum legal key size is 256 bits (32 bytes), the recommended size is 2* the hash size, or 512 bits (64 bytes). \n
/// The number of transformation rounds processed within the ciphers rounds function can also be defined; adding rounds creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. \n
/// RHX is capable of processing up to 38 rounds, that is twenty-four rounds more than the fourteen rounds used in an implementation of AES-256. \n
/// Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</para>
/// 
/// <list type="bullet">
/// <item><description>An input key of up to 64 bytes in length will use a standard key schedule for internal key expansion; greater than 64 bytes implements the HKDF key schedule.</description></item>
/// <item><description>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake2, Keccak, SHA-2 or Skein.</description></item>
/// <item><description>The HKDF Digest engine is definable through the <see cref="RHX(uint, Digests)">Constructor</see> type enumeration parameter: Digest.</description></item>
/// <item><description>Minimum HKDF key size is the Digests Hash output size, recommended is 2* the minimum, or increments of (n * hash-size) in bytes.</description></item>
/// <item><description>The recommended size for maximum security is 2* the digests block size; this calls HKDF Extract using full blocks of key and salt.</description></item>
/// <item><description>Valid key sizes can be determined at run time using the <see cref="LegalKeySizes"/> property.</description></item>
/// <item><description>The internal block size is 16 bytes wide.</description></item>
/// <item><description>Diffusion rounds assignments are 10 to 38, the default is 22 (128-256 bit key), a 512 bit key is automatically assigned 22 rounds.</description></item>
/// <item><description>Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</description></item>
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
/// <item><description>SHA3 <a href="https://131002.net/blake/blake.pdf">The Blake digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>SHA3 <a href="http://www.skein-hash.info/sites/default/files/skein1.1.pdf">The Skein digest</a>.</description></item>
/// </list>
/// </remarks>
class RHX final : public IBlockCipher
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
	// size of state buffer and lookup tables subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 5120;

	BlockCipherExtensions m_cprExtension;
	bool m_destroyEngine;
	std::vector<byte> m_distCode;
	size_t m_distCodeMax;
	std::vector<uint> m_expKey;
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
	RHX(const RHX&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RHX& operator=(const RHX&) = delete;

	/// <summary>
	/// Instantiate the class with an optional block-cipher extension type
	/// </summary>
	/// 
	/// <param name="CipherExtensionType">Sets the optional Key Schedule key-expansion engine; valid options are cSHAKE, HKDF, or None for standard mode. 
	/// <para>The default engine is None, which invokes the standard key schedule mechanism.</para></param>
	RHX(BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None);

	/// <summary>
	/// Instantiate the class with a Key Derivation Function instance
	/// </summary>
	///
	/// <param name="Kdf">The Key Schedule KDF engine instance; can not be null.</param>
	RHX(Kdf::IKdf* Kdf);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~RHX() override;

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
	void ExpandRotBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset, size_t RconIndex);
	void ExpandSubBlock(std::vector<uint> &Key, size_t KeyIndex, size_t KeyOffset);
	void LoadState();
	void Prefetch();
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);
	uint SubByte(uint Rot);
};

NAMESPACE_BLOCKEND
#endif

