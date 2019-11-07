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
// An implementation of an Rijndael-256 Counter Mode (ACS).
// Written by John G. Underhill, March 8, 2019
// Contact: develop@vtdev.com

#ifndef CEX_ACS_H
#define CEX_ACS_H

#include "IStreamCipher.h"
#include "IMac.h"
#include "Intrinsics.h"
#include "StreamAuthenticators.h"

NAMESPACE_STREAM

using Mac::IMac;
using Enumeration::StreamAuthenticators;

/// <summary>
/// An AES-NI implementation of the Rijndael symmetric 256-bit block-cipher, operating in a Little-Endian counter-mode, as an Authenticate, Encrypt, and Additional Data (AEAD) stream cipher implementation  (AESNI-256 Cipher Stream).
/// <para>This cipher uses an optional authentication mode; Poly1305, HMAC(SHA2), or KMAC set through the constructor to authenticate the stream.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting an array of bytes:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// // initialize the Rijndael cipher with the SHAKE-256 key-schedule extension
/// ACS cipher(StreamAuthenticators::KMAC256);
/// // mac code is appended to the cipher-text stream in authentication mode
/// cipher.Initialize(true, kp);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Decrypt and verify an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// ACS cipher(StreamAuthenticators::KMAC256);
/// // initialize for decryption
/// cipher.Initialize(false, kp);
///
/// // decrypt the ciphertext and catch authentication failures
/// try
/// {
///		cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// }
/// catch (CryptoAuthenticationFailure)
/// {
///		// authentication has failed, do something...
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>
/// The ACS symmetric cipher is a 256-bit wide-block Rijndael based, Authenticate, Encrypt, and Additional Data (AEAD) authenticated stream-cipher. \n
/// ACS is an online cipher, meaning it can stream data of any size, without needing to know the data size in advance. \n
/// It also has provable security, based on the Rijndael-256 permutation function used by this cipher. \n
/// ACS first encrypts the plain-text using a Little-Endian counter mode, then processes that cipher-text using a MAC function used for data authentication. \n\n
/// When each transform encryption call is completed, the MAC code is generated and appended to the output vector automatically. \n
/// Decryption performs these steps in reverse, processing the cipher-text bytes through the MAC function, and if authentication succeeds, then decrypting the data to plain-text. \n
/// During decryption, if the MAC codes do not match, a CryptoAuthenticationFailure exception error is thrown.</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the ACS mode can be multi-threaded. This is achieved by processing multiple blocks of message input independently across threads. \n
/// The ACS stream cipher also leverages SIMD instructions to 'double parallelize' those segments. An input block assigned to a thread
/// uses SIMD instructions to decrypt/encrypt blocks in parallel, depending on which framework is runtime available, AVX, AVX2, or AVX512 SIMD instructions. \n
/// Input blocks equal to, or divisble by the ParallelBlockSize() are processed in parallel on supported systems.
/// The cipher transform is parallelizable, however the authentication pass, is processed sequentially.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Supported key sizes are 32, 64, and 128 bytes (256, 512, and 1024 bits).</description></item>
/// <item><description>The required Nonce size is 16 bytes (128 bits).</description></item>
/// <item><description>The ISymmetricKey info value can be used as a cipher tweak to create a unique ciphertext and MAC output.</description></item>
/// <item><description>The ciphers Initialize function can use either a SymmetricKey, or an encrypted SymmetricSecureKey key container.</description></item>
/// <item><description>The internal block input-size is fixed at 32 bytes wide (256 bits).<</description></item>
/// <item><description>This cipher is capable of authentication by setting the constructors StreamAuthenticators enumeration to Poly1305, or one of the HMAC or KMAC options.</description></item>
/// <item><description>In authentication mode, during encryption the MAC code is automatically appended to the output cipher-text, during decryption, this MAC code is checked and authentication failure will generate a CryptoAuthenticationFailure exception.</description></item>
/// <item><description>If authentication is enabled, the cipher and MAC keys are generated by passing the input cipher-key through an instance of cSHAKE, this will yield a different cipher-text output from non-authenticated modes.</description></item>
/// <item><description>In authenticated mode, the internal keys generated by cSHAKE will be unique with each MAC generator, each authentication option should be considered a seperate and distinct variant of the cipher, for example, RCS256-SHAKE512 or RCS256-HMAC512</description></item>
/// <item><description>The Info string is optional, but can be used to create a tweakable cipher, this can be used for adding additional key material, or using a second key to restrict decryption to a domain based system.</description></item>
/// <item><description>Permutation rounds are fixed 22, 30, and 38, for 256, 512, and 1024-bit keys.</description></item>
/// <item><description>Authentication using Poly1305, HMAC, or KMAC, can be invoked by setting the StreamAuthenticators parameter in the constructor, when set to None, authentication is disabled.</description></item>
/// <item><description>The class functions are virtual, and can be accessed from an IStreamCipher instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(ISymmetricKey) function has been called.</description></item>
/// <item><description>Encryption can both be pipelined (AVX, AVX2, or AVX512), and multi-threaded with any even number of threads, the configuration can be modified using the ParallelProfile() accessor function.</description></item>
/// <item><description>If the system supports Parallel processing, and ParallelProfile().IsParallel() is set to true; passing an input block of ParallelProfile().ParallelBlockSize() to the transform will be auto-parallelized.</description></item>
/// <item><description>The ParallelProfile().ParallelThreadsMax() property is used as the thread count in the parallel loop; it defaults to the maximum number of available virtual cores, but is user-assignable, and must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelProfile().ParallelBlockSize() is calculated automatically based on processor(s) cache size but can be user defined, but must be evenly divisible by ParallelProfile().ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property, but this has been auto-calculated based on the systems hardware, modifications are not recommended</description></item>
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
class ACS final : public IStreamCipher
{
private:

	static const size_t BLOCK_SIZE = 32;
	static const size_t INFO_SIZE = 16;
	static const size_t MAX_PRLALLOC = 100000000;
	static const std::vector<byte> OMEGA_INFO;
	static const size_t STATE_PRECACHED = 2048;
	static const size_t STATE_THRESHOLD = 838;
	static const byte UPDATE_PREFIX = 0x80;
	static const __m128i BLEND_MASK;
	static const __m128i SHIFT_MASK;

	class AcsState;
	std::unique_ptr<AcsState> m_acsState;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::unique_ptr<IMac> m_macAuthenticator;
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
	/// <param name="AuthenticatorType">The authentication engine, the default is KMAC256</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid block cipher type is used</exception>
	ACS(StreamAuthenticators AuthenticatorType = StreamAuthenticators::KMAC256);

	/// <summary>
	/// Initialize the stream cipher using a secure-vector serialized state.
	/// <para>The Serialize function stores the internal state of the cipher, so that it can be reinitialized,
	/// without the need to call the Initialize function and key-schedule. 
	/// If this constructor is used, the cipher is fully initialized to the values it had when the Serialize function was called.</para>
	/// </summary>
	///
	/// <param name="State">The serialized state, created by the Serialize() function</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid block cipher type is used</exception>
	ACS(SecureVector<byte> &State);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ACS() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The stream ciphers type name
	/// </summary>
	const StreamCiphers Enumeral() override;

	/// <summary>
	/// Read Only: Cipher has authentication enabled
	/// </summary>
	const bool IsAuthenticator() override;

	/// <summary>
	/// Read Only: The cipher has been initialized for encryption
	/// </summary>
	const bool IsEncryption() override;

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
	/// Read Only: Vector of SymmetricKeySize containers, containing legal cipher input key sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The stream ciphers formal implementation name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The current value of the nonce counter array.
	/// </summary>
	const std::vector<byte> Nonce() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class, but must be a multiple of the ParallelMinimumSize().</para>
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
	/// Read Only: The current standard-vector MAC tag value
	/// </summary>
	const std::vector<byte> Tag() override;

	/// <summary>
	/// Copies the internal MAC tag to a secure-vector
	/// </summary>
	/// 
	/// <param name="Output">The secure-vector receiving the MAC code</param>
	const void Tag(SecureVector<byte> &Output) override;

	/// <summary>
	/// Read Only: The legal MAC tag length in bytes
	/// </summary>
	const size_t TagSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the cipher with an ISymmetricKey key container.
	/// <para>If authentication is enabled, setting the Encryption parameter to false will decrypt and authenticate a ciphertext stream.
	/// Authentication on a decrypted stream is performed automatically; failure will throw a CryptoAuthenticationFailure exception.
	/// If encryption and authentication are set to true, the MAC code is appended to the cipher-text array.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="Parameters">Cipher key structure, containing cipher key, nonce, and optional info vectors</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor virtual cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Saves the internal state of the cipher to a secure vector.
	/// <para>The Serialize function can store the internal state of the cipher at the time it is invoked.
	/// The cipher instance can be reinitialized through a constructor option, without the need to re-call the Initialize function and associated key-schedule functions.
	/// This is useful in situations where the cipher is required intermitantly, and the entire state can be stored rather than just the key and nonce.</para>
	/// </summary>
	///
	/// <returns>The serialized cipher state</returns>
	SecureVector<byte> Serialize();

	/// <summary>
	/// Add additional data to the message authentication code generator.  
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and can then be called before or after a stream segment has been processed.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if the cipher is not initialized</exception>
	void SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Encrypt/Decrypt a vector of bytes with offset and length parameters.
	/// <para>Initialize(bool, ISymmetricKey) must be called before this method can be used. 
	///	In authenticated encryption mode, the MAC code is automatically appended to the output stream at the end of the cipher-text, the output array must be long enough to accommodate this TagSize() code.
	/// In decryption mode, this code is checked before the stream is decrypted, if the authentication fails a CryptoAuthenticationFailure exception is thrown.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">Number of bytes to process</param>
	///
	/// <exception cref="CryptoAuthenticationFailure">Thrown during decryption if the the ciphertext fails authentication</exception>
	void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

private:

	static void Finalize(std::unique_ptr<AcsState> &State, std::unique_ptr<IMac> &Authenticator);
	void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Counter);
	void Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void ProcessParallel(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void ProcessSequential(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Reset();
	void Transform256(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Transform1024(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Transform2048(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Transform4096(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
};

NAMESPACE_STREAMEND
#endif
