// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
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
// Updated October 20, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_THX_H
#define _CEX_THX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// A Twofish Cipher extended with an (optional) HKDF powered Key Schedule
/// </summary>
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(Enumeration::BlockCiphers::THX);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt a block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Description:</description>
/// <para>THX is a Twofish implementation that can use a standard configuration on key sizes up to 32 bytes (256 bits), 
/// an extended key size of 64 bytes (512 bits), or unlimited key sizes greater than 64 bytes. \n
/// On <see cref="LegalKeySizes"/> larger than 64 bytes, an HKDF random bytes generator is used to expand the <c>working key</c> integer array. \n
/// In HKDF extended mode, the number of <c>transformation rounds</c> can be user assigned (through the constructor) to between 16 and 32 rounds.
/// Increasing the number of transformation rounds processed within the ciphers rounds function creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. \n
/// THX is capable of processing up to 32 rounds, that is twice the number of rounds used in a standard implementation of Twofish. 
/// When using e.g. SHA-2 256, a minimum key size for is 32 bytes, further blocks of can be added to the key so long as they align; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum.
/// </para>
///
/// <description>Changes to THX Version 1.2:</description>
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
/// <para>When using SHA-2 256, a minimum key size for THX is 32 bytes, larger lengths of input key can be used so long as it aligns; (n * hash size), ex. 64, 128, 192 bytes.. there is no upper maximum. \n
/// The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake2, Keccak, SHA-2 or Skein. \n
/// Valid key sizes can be determined at runtime using the <see cref="LegalKeySizes"/> property, based on the digest selected.
/// When using the extended mode, the legal key sizes are determined based on the selected digests hash output size, 
/// ex. SHA256 the minimum legal key size is 256 bits (32 bytes), the recommended size is 2* the hash size, or 512 bits (64 bytes). \n
/// The number of transformation rounds processed within the ciphers rounds function can also be defined; adding rounds creates a more diffused cipher output, making the resulting cipher-text more difficult to cryptanalyze. \n
/// THX is capable of processing up to thirty-two rounds, that is sixteen rounds more than sixteen rounds used in a standard implementation of Twofish. \n
/// Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</para>
/// 
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>An input key of up to 64 bytes in length will use a standard key schedule for internal key expansion; greater than 64 bytes implements the HKDF key schedule.</description></item>
/// <item><description>The Digest that powers HKDF, can be any one of the Hash Digests implemented in the CEX library; Blake2, Keccak, SHA-2 or Skein.</description></item>
/// <item><description>The HKDF Digest engine is definable through the <see cref="THX(uint, Digests)">Constructor</see> type enumeration parameter: KdfEngine.</description></item>
/// <item><description>Minimum HKDF key size is the Digests Hash output size, recommended is 2* the minimum, or increments of (n * hash-size) in bytes.</description></item>
/// <item><description>The recommended size for maximum security is 2* the digests block size; this calls HKDF Extract using full blocks of key and salt.</description></item>
/// <item><description>Valid key sizes can be determined at run time using the <see cref="LegalKeySizes"/> property.</description></item>
/// <item><description>The internal block size is 16 bytes wide.</description></item>
/// <item><description>Diffusion rounds assignments are 16, 18, 20, 22, 24, 26, 28, 30 and 32, default is 16 (128-256 bit key), a 512 bit key is automatically assigned 20 rounds.</description></item>
/// <item><description>Valid rounds assignments can be found in the <see cref="LegalRounds"/> property.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Twofish: <a href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</a>.</description></item>
/// <item><description>HMAC <a href="http://tools.ietf.org/html/rfc2104">RFC 2104</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">Fips 198.1</a>.</description></item>
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

	static const std::string DEF_INFO;
	const size_t BLOCK_SIZE = 16;
	const uint DEF_ROUNDS = 16;
	const uint GF256_FDBK = 0x169;
	const uint GF256_FDBK_2 = GF256_FDBK / 2;
	const uint GF256_FDBK_4 = GF256_FDBK / 4;
	const uint KEY_BITS = 256;
	const uint RS_GF_FDBK = 0x14D;
	const uint SK_BUMP = 0x01010101;
	const uint SK_ROTL = 9;
	const uint SK_STEP = 0x02020202;
	const size_t SBOX_SIZE = 1024;
	// size of state buffer and sbox subtracted parallel size calculations
	const size_t STATE_PRECACHED = 2048 + 4096;

	bool m_destroyEngine;
	std::vector<uint> m_expKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	IDigest* m_kdfEngine;
	Digests m_kdfEngineType;
	std::vector<byte> m_kdfInfo;
	size_t m_kdfInfoMax;
	size_t m_kdfKeySize;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::vector<size_t> m_legalRounds;
	size_t m_rndCount;
	std::vector<uint> m_sBox;

public:

	THX(const THX&) = delete;
	THX& operator=(const THX&) = delete;
	THX& operator=(THX&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide.
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get/Set: Reads or Sets the Info (personalization string) value in the HKDF initialization parameters.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// Code can be sized as either a zero byte array, or any length up to the DistributionCodeMax size.
	/// For best security, the distribution code should be random, secret, and equal in length to the DistributionCodeMax() size.
	/// If the Info parameter of an ISymmetricKey is non-zero, it will overwrite the distribution code.</para>
	/// </summary>
	virtual std::vector<byte> &DistributionCode() { return m_kdfInfo; }

	/// <summary>
	/// Get: The maximum size of the distribution code in bytes.
	/// <para>The distribution code can be used as a secondary source of entropy (secret) in the HKDF key expansion phase.
	/// For best security, the distribution code should be random, secret, and equal in size to this value.</para>
	/// </summary>
	virtual const size_t DistributionCodeMax() { return m_kdfInfoMax; }

	/// <summary>
	/// Get: The block ciphers type name
	/// </summary>
	virtual const BlockCiphers Enumeral() { return m_kdfEngineType == Digests::None ? BlockCiphers::Twofish : BlockCiphers::THX; }

	/// <summary>
	/// Get: Initialized for encryption, false for decryption.
	/// <para>Value set in <see cref="Initialize(bool, ISymmetricKey)"/>.</para>
	/// </summary>
	virtual const bool IsEncryption() { return m_isEncryption; }

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: The extended ciphers HKDF digest type
	/// </summary>
	virtual const Digests KdfEngine() { return m_kdfEngineType; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_legalKeySizes; }

	/// <summary>
	/// Get: Available transformation round assignments
	/// </summary>
	virtual const std::vector<size_t> LegalRounds() { return m_legalRounds; }

	/// <summary>
	/// Get: The block ciphers class name
	/// </summary>
	virtual const std::string Name() { return "THX"; }

	/// <summary>
	/// Get: The number of transformation rounds processed by the transform
	/// </summary>
	virtual const size_t Rounds() { return m_rndCount; }

	/// <summary>
	/// Get: The sum size in bytes (plus some allowance for externals) of the classes persistant state.
	/// <para>This value is subtracted from the parallel block-size calculations, to reduce the occurence of L1 cache eviction of hot tables and class variables. 
	/// This is a timing and performance optimization, see the ParallelOptions class for more details.</para>
	/// </summary>
	virtual const size_t StateCacheSize() { return STATE_PRECACHED; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate the class with optional transformation rounds, and KDF engine type settings
	/// </summary>
	/// 
	/// <param name="KdfEngineType">The Key Schedule KDF digest engine; can be any one of the Digest implementations. 
	/// The default engine is None, which invokes the standard key schedule mechanism.</param>
	/// <param name="Rounds">Number of transformation rounds. The <see cref="LegalRounds"/> property contains available sizes. 
	/// Default is 16 rounds, defining rounds requires HKDF extended mode.</param>
	/// 
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(Digests KdfEngineType = Digests::None, uint Rounds = 16);

	/// <summary>
	/// Instantiate the class with a Digest instance (HKDF extended mode), and with optional transformation rounds count
	/// </summary>
	/// 
	/// <param name="KdfEngine">The Key Schedule HKDF digest engine instance; can be any one of the Digest implementations.</param>
	/// <param name="Rounds">Number of transformation rounds; the <see cref="LegalRounds"/> property contains available sizes, default is 20 rounds.</param>
	/// 
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	THX(IDigest *KdfEngine, size_t Rounds = 20);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~THX();

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>false</c> before this method can be used.
	/// Input and Output arrays must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">Encrypted bytes</param>
	/// <param name="Output">Decrypted bytes</param>
	virtual void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

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
	virtual void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Clear the buffers and reset
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Encrypt a block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called with the Encryption flag set to <c>true</c> before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

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
	virtual void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	///
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="KeyParams">Cipher key container. <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
	///
	/// <exception cref="Exception::CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParams);

	/// <summary>
	/// Transform a block of bytes.
	/// <para><see cref="Initialize(bool, ISymmetricKey)"/> must be called before this method can be used.
	/// Input and Output array lengths must be at least <see cref="BlockSize"/> in length.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform or Decrypt</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

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
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

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
	virtual void Transform64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

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
	virtual void Transform128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void Decrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt16(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt64(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void ExpandKey(const std::vector<byte> &Key);
	void LoadState(Digests KdfEngineType);
	uint MdsEncode(uint K0, uint K1);
	uint Mix4(const uint X, const std::vector<uint> &Key, const size_t Count);
	void Mix16(const uint X, const std::vector<byte> &Key, const size_t Count, std::vector<uint> &Output);
	void SecureExpand(const std::vector<byte> &Key);
	void StandardExpand(const std::vector<byte> &Key);
};

NAMESPACE_BLOCKEND
#endif

