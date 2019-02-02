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
// Implementation Details:
// An implementation of an Authenticated Counter Mode (ACS).
// Written by John Underhill, December 9, 2018
// Updated December 20, 2018
// Updated December 26, 2018
// Contact: develop@vtdev.com

#ifndef CEX_ACS_H
#define CEX_ACS_H

#include "IStreamCipher.h"
#include "BlockCiphers.h"
#include "BlockCipherExtensions.h"
#include "CTR.h"
#include "IBlockCipher.h"
#include "IMac.h"
#include "ShakeModes.h"
#include "StreamAuthenticators.h"
#include "SecureVector.h"

NAMESPACE_STREAM

using Enumeration::BlockCiphers;
using Enumeration::BlockCipherExtensions;
using Cipher::Block::Mode::CTR;
using Cipher::Block::Mode::IBlockCipher;
using Mac::IMac;
using Enumeration::ShakeModes;
using Enumeration::StreamAuthenticators;

/// <summary>
/// An Encrypt and Authenticate AEAD stream cipher implementation (Authenticated Cipher Stream).
/// <para>Uses an optional authentication mode; HMAC(SHA2) or KMAC set through the constructor to authenticate the stream.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// ACS cipher(BlockCiphers::AES, BlockCipherExtensions::SHAKE256, StreamAuthenticators::KMAC256);
/// // mac code is appended to the cipher-text stream in authentication mode
/// cipher.Initialize(true, kp);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Encrypt and authenticate an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// ACS cipher(StreamAuthenticators::HMACSHA256);
/// // initialize for encryption
/// cipher.Initialize(true, kp);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Decrypt and authenticate an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// ACS cipher(StreamAuthenticators::HMACSHA256);
/// // initialize for decryption
/// cipher.Initialize(false, kp);
/// // decrypt the ciphertext
/// try
/// {
///		cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// }
/// catch (CryptoAuthenticationFailure)
/// {
///		// do something...
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>
/// The ACS Cipher Mode is an Authenticate Encrypt and Additional Data (AEAD) authenticated stream cipher. \n
/// ACS is an online mode, meaning it can stream data of any size, without needing to know the data size in advance. \n
/// It also has provable security, dependant on the block cipher used by the mode. \n
/// ACS first encrypts the plaintext using a counter mode (CTR), then processes that cipher-text using a MAC function used for data authentication. \n
/// When each transform call encryption is completed, the MAC code is generated and appended to the output stream automatically. \n
/// Decryption performs these steps in reverse, processing the cipher-text bytes through the MAC function, then decrypting the data to plain-text. \n
/// During decryption, if the MAC codes do not match, a CryptoAuthenticationFailure exception error is thrown.</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the ACS mode can be multi-threaded. This is achieved by processing multiple blocks of message input independently across threads. \n
/// The ACS stream cipher also leverages SIMD instructions to 'double parallelize' those segments. An input block assigned to a thread
/// uses SIMD instructions to decrypt/encrypt blocks in parallel, depending on which framework is runtime available, 256 or 512-bit SIMD instructions. \n
/// Input blocks equal to, or divisble by the ParallelBlockSize() are processed in parallel on supported systems.
/// The cipher transform is parallelizable, however the authentication pass, is processed sequentially.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Supported key sizes are 32, 64, and 128 bytes (256, 512, and 1024 bits).</description></item>
/// <item><description>The mandatory Nonce size is 16 bytes (128 bits).</description></item>
/// <item><description>The ISymmetricKey info value can be used as a cipher tweak to create a unique ciphertext and MAC output.</description></item>
/// <item><description>The ciphers Initialize function can use either a SymmetricKey container, or an encrypted SymmetricSecureKey.</description></item>
/// <item><description>Block size is 16 bytes wide (128 bits).</description></item>
/// <item><description>This cipher is capable of authentication by setting the constructors StreamAuthenticators enumeration to one of the HMAC or KMAC options.</description></item>
/// <item><description>In authentication mode, during encryption the MAC code is automatically appended to the output cipher-text, during decryption, this MAC code is checked and authentication failure will generate a CryptoAuthenticationFailure exception.</description></item>
/// <item><description>If authentication is enabled, the cipher-key and MAC seed are generated using cSHAKE, this will change the cipher-text output.</description></item>
/// <item><description>In authenticated mode, the cipher-key generated by cSHAKE will be constant even with differing MAC generators; only two cipher-text outputs are possible, authenticated or non-authenticated.</description></item>
/// <item><description>The Info string is optional, but can be used to create a tweakable cipher; must be 16 bytes in length.</description></item>
/// <item><description>Permutation rounds are fixed 22, 30, and 38, for 256, 512, and 1024-bit keys.</description></item>
/// <item><description>Authentication using HMAC or KMAC, can be invoked by setting the StreamAuthenticators parameter in the constructor.</description></item>
/// <item><description>The class functions are virtual, and can be accessed from an IStreamCipher instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(ISymmetricKey) function has been called.</description></item>
/// <item><description>Encryption can both be pipelined (AVX, AVX2, or AVX512), and multi-threaded with any even number of threads, the configuration can be modified using the ParallelProfile() accessor function.</description></item>
/// <item><description>If the system supports Parallel processing, and ParallelProfile().IsParallel() is set to true; passing an input block of ParallelProfile().ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>The ParallelProfile().ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelProfile().ParallelBlockSize() is calculated automatically based on processor(s) cache size but can be user defined, but must be evenly divisible by ParallelProfile().ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize() can be changed through the ParallelProfile() property</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize = N - (N % .ParallelMinimumSize);</c></description></item>
/// </list>
///
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The <a href="http://web.cs.ucdavis.edu/~rogaway/papers/acs.pdf">ACS Mode</a> of Operation.</description></item>
/// <item><description>RFC 5116: <a href="https://tools.ietf.org/html/rfc5116">An Interface and Algorithms for Authenticated Encryption</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// <item><description>Fips-202: The <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard</a></description>.</item>
/// <item><description>SP800-185: <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SHA-3 Derived Functions</a></description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198-1</a>: The Keyed-Hash Message Authentication Code (HMAC).</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">180-4</a>: Secure Hash Standard (SHS).</description></item>
/// </list>
/// </remarks>
class ACS final : public IStreamCipher
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const std::string CLASS_NAME;
	static const size_t INFO_SIZE = 16;
	static const size_t MAX_PRLALLOC = 100000000;
	static const size_t MIN_TAGSIZE = 16;
	static const std::vector<byte> OMEGA_INFO;
	static const byte UPDATE_PREFIX = 0x80;

	StreamAuthenticators m_authenticatorType;
	std::unique_ptr<CTR> m_cipherMode;
	BlockCiphers m_cipherType;
	std::vector<byte> m_cShakeCustom;
	ShakeModes m_expansionMode;
	bool m_isAuthenticated;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::unique_ptr<IMac> m_macAuthenticator;
	ulong m_macCounter;
	SecureVector<byte> m_macKey;
	std::vector<byte> m_macTag;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ACS(const ACS&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ACS& operator=(const ACS&) = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name.
	/// <para>The cipher instance is created and destroyed automatically.</para>
	/// </summary>
	///
	/// <param name="CipherType">The enumeration name of the underlying block cipher; the default is RHX</param>
	/// <param name="AuthenticatorType">The authentication engine, the default is KMAC256</param>
	///
	/// <exception cref="CryptoSymmetricCipherException">Thrown if an invalid block cipher type is used</exception>
	ACS(BlockCiphers CipherType = BlockCiphers::AES, StreamAuthenticators AuthenticatorType = StreamAuthenticators::KMAC256);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ACS() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Internal block size of internal cipher in bytes.
	/// <para>Block size is 16 bytes wide.</para>
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The maximum size of the distribution code in bytes.
	/// <para>The distribution code is set with the ISymmetricKey Info parameter; and can be used as a secondary domain key.</para>
	/// </summary>
	const size_t DistributionCodeMax() override;

	/// <summary>
	/// Read Only: The stream ciphers type name
	/// </summary>
	const StreamCiphers Enumeral() override;

	/// <summary>
	/// Read Only: Cipher has authentication enabled
	/// </summary>
	const bool IsAuthenticator() override;

	/// <summary>
	/// Read Only: Cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this cipher.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: Array of SymmetricKeySize containers, containing legal cipher input key sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The stream ciphers implementation name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and recommended sizes.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the Initialize(bool, ISymmetricKey) function is called.</para>
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	/// <summary>
	/// Read Only: The current MAC tag value
	/// </summary>
	const std::vector<byte> &Tag() override;

	/// <summary>
	/// Read Only: The legal tag length in bytes
	/// </summary>
	const size_t TagSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// The stream ciphers authentication MAC generator type.
	/// <para>Change the MAC generator (HMAC, KMAK -N), type used to authenticate the stream.</para>
	/// </summary>
	/// 
	/// <param name="AuthenticatorType">The MAC generator type used to calculate the authentication code</param>
	void Authenticator(StreamAuthenticators AuthenticatorType) override;

	/// <summary>
	/// Initialize the cipher with an ISymmetricKey key container.
	/// <para>If authentication is enabled, setting the Encryption parameter to false will decrypt and authenticate a ciphertext stream.
	/// Authentication on a decrypted stream is performed automatically; failure will throw a CryptoAuthenticationFailure exception.
	/// If encryption and authentication are set to true, the MAC code is appended to the ciphertext array.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="KeyParams">Cipher key structure, containing cipher key, nonce, and optional info array</param>
	///
	/// <exception cref="CryptoSymmetricCipherException">Thrown if a null or invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor [virtual] cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Add additional data to the authentication generator.  
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and can be called before or after a stream segment has been processed.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to process</param>
	/// <param name="Offset">Starting offset within the input array</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoSymmetricCipherException">Thrown if the cipher is not initialized</exception>
	void SetAssociatedData(const std::vector<byte> &Input, const size_t Offset, const size_t Length) override;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset and length parameters.
	/// <para>Initialize(bool, ISymmetricKey) must be called before this method can be used.
	///	In authenticated encryption mode, the MAC code is automatically appended to the output stream at the end of the cipher-text, the output array must be long enough to accommodate this code.
	/// In decryption mode, this code is checked before the stream is decrypted, if the authentication fails a CryptoAuthenticationFailure exception is thrown.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// <param name="Length">Number of bytes to process</param>
	///
	/// <exception cref="CryptoAuthenticationFailure">Thrown during decryption if the the ciphertext fails authentication</exception>
	void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

private:

	void Finalize(std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
	void Reset();
};

NAMESPACE_STREAMEND
#endif
