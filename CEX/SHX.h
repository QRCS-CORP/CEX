// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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
// Written by John G. Underhill, November 15, 2014
// Updated October 20, 2016
// Updated April 16, 2017
// Updated November 30, 2018
// Contact: develop@vtdev.com

#ifndef CEX_SHX_H
#define CEX_SHX_H

#include "IBlockCipher.h"

NAMESPACE_BLOCK

/// <summary>
/// A Serpent cipher using either standard modes, or extended modes of operation using a HKDF(SHA2) or cSHAKE key schedule, and increased transformation rounds.
/// <para>This cipher should not be used directly but through a cipher mode, or as part of a larger construction.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of encrypting a block:</description>
/// <code>
/// CTR cipher(Enumeration::BlockCiphers::SHX);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt a block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Description:</description>
/// <para>SHX is a Serpent implementation that can use either a standard configuration with key sizes of up to 32 bytes (256 bits), 
/// or an extended mode using key sizes of 32, 64, and 128 bytes, (256, 512, and 1024 bits). \n
/// In extended mode, the number of transformation rounds are set to 40, 48 and 64 rounds corresponding to the 256, 512, and 1024 input cipher key sizes. \n
/// Increasing the number of transformation rounds processed by the ciphers rounds function creates a more diffused output, making the resulting cipher-text more resistant to some forms of cryptanalysis. \n
/// SHX is capable of processing up to 64 rounds, that is twice the number of rounds used in a standard implementation of Serpent. 
/// </para>
///
/// <description>Implementation Notes:</description>
/// <para>The key schedule in SHX, and the number of transformation rounds processed are the difference between the extended mode operations, and a standard version of Serpent.
/// The standard Serpent Key Schedule processes 128, 192, and 256 bit keys, and is fixed at 32 transformation rounds, the extended version of the cipher processes 256, 512, and 1024-bit keys and up to 64 rounds. \n
/// SHX extended mode can use an HMAC based Key Derivation Function; HKDF(HMAC(SHA2)) or the Keccak XOF function cSHAKE, to expand the cipher key to create the internal round-key integer array. \n
/// This provides better security, and allows for an implemetation to safely use an increased number of transformation rounds. \n
/// The cipher can also use a user-definable cipher tweak through the Info parameter of the symmetric key container, this can be used to create a unique cipher-text output. \n
/// This tweak array is set as either the information string for HKDF, or as the cSHAKE name string.</para>
///
/// <para>When using the extended mode of the cipher, the minimum key size is 32 bytes (256 bits), and valid key sizes are 256, 512, and 1024 bits long. \n
/// SHX is capable of processing up to 64 rounds, that is twice the number of mixing rounds set in a standard implementation of Serpent; in extended mode a 256-bit key uses 40 rounds, a 512-bit key 48 rounds, and a 1024-bit key is set to 64 rounds.</para>
/// 
/// <list type="bullet">
/// <item><description>This cipher should only be used in conjunction with an AEAD or standard cipher mode, or as an component in another construction, ex. CMAC.</item>
/// <item><description>Valid key sizes can be determined at run-time using the <see cref="LegalKeySizes"/> property.</description> collection.</item>
/// <item><description>The internal block-size is fixed at 16 bytes (128 bits) wide.</description></item>
/// <item><description>The cipher can process 128, 192, and 256-bit keys in standard mode, and 256, 512, and 1024-bit keys in extended mode.</description></item>
/// <item><description>Transformation rounds assignments are 32 in standard modes, and 40, 48, and 64 rounds (256, 512, and 1024-bit keys).</description></item>
/// <item><description>The Info parameter in a symmetric key container is a user-definable cipher tweak, this can be used to create a unique cipher-text output with a secondary secret.</description></item>
/// <item><description>Extended mode is set through the constructors BlockCipherExtensions parameter to either None for standard mode, or HKDF(SHA2-256), HKDF(SHA2-512), cSHAKE256, cSHAKE512, or cSHAKE1024 for extended mode operation.</description></item>
/// <item><description>It is recommended that in extended mode, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or HKDF(SHA2-512) for a 512-bit key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Serpent: <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.</description></item>
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
class SHX final : public IBlockCipher
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t MAX_ROUNDS = 64;
	static const size_t MIN_ROUNDS = 32;
	static const uint PHI = 0x9E3779B9UL;
	// size of state buffer subtracted parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	class ShxState;
	std::unique_ptr<ShxState> m_shxState;
	std::unique_ptr<IKdf> m_kdfGenerator;
	std::vector<SymmetricKeySize> m_legalKeySizes;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SHX(const SHX&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SHX& operator=(const SHX&) = delete;

	/// <summary>
	/// Instantiate the class with an optional block-cipher extension type.
	/// <para>It is recommended that in extended mode operation, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or, HKDF(SHA2-512) for a 512-bit key.</para>
	/// </summary>
	/// 
	/// <param name="CipherExtensionType">Sets the optional Key Schedule key-expansion function; valid options are cSHAKE, HKDF, or None for standard mode. 
	/// <para>The default engine is None, which invokes the standard key schedule mechanism.</para></param>
	SHX(BlockCipherExtensions CipherExtensionType = BlockCipherExtensions::None);

	/// <summary>
	/// Instantiate the class with a Key Derivation Function instance.
	/// <para>It is recommended that in extended mode operation, the key expansion functions security match the key size used; ex. with a 256-bit key use SHAKE-256, or, HKDF(SHA2-512) for a 512-bit key.</para>
	/// </summary>
	///
	/// <param name="Kdf">The Key Schedule KDF engine instance; can be null.</param>
	SHX(IKdf* Kdf);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SHX() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Unit block size of internal cipher in bytes.
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The block ciphers enumeration type name
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
	/// Read Only: A list of SymmetricKeySize structures containing valid key-sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The block ciphers formal class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The number of transformation rounds processed by the rounds function
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
	void DecryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

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
	void EncryptBlock(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the cipher with a populated SymmetricKey or SymmetricSecureKey container
	/// </summary>
	/// 
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="Parameters">Cipher key container.
	/// <para>The <see cref="LegalKeySizes"/> property contains valid sizes.</para></param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

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
	void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

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
	void Transform512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

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
	void Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

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
	virtual void Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) override;

private:

	static std::vector<SymmetricKeySize> CalculateKeySizes(BlockCipherExtensions Extension);
	static void SecureExpand(const SecureVector<byte> &Key, std::unique_ptr<ShxState> &State, std::unique_ptr<IKdf> &Generator);
	static void StandardExpand(const SecureVector<byte> &Key, std::unique_ptr<ShxState> &State);

	void Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Decrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Decrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Decrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Encrypt512(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Encrypt1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Encrypt2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

};

NAMESPACE_BLOCKEND
#endif
