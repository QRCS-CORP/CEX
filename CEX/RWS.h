// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
// An implementation of an Rijndael-512 authenticated Counter Mode (RWS).
// Version 1.0b
// Written by John G. Underhill, March 8, 2019
// Updated January 09, 2020
// Updated July 31, 2020
// Updated August 17, 2020
// Contact: develop@qscs.ca

#ifndef CEX_RWS_H
#define CEX_RWS_H

#include "IStreamCipher.h"
#include "IMac.h"
#include "KmacModes.h"

NAMESPACE_STREAM

using Mac::IMac;
using Enumeration::KmacModes;

/// <summary>
/// The Rijndael-512 wide-block based authenticated stream cipher.
/// <para>An implementation of the Rijndael-based 512-bit wide block-cipher RWS, operating in a Little-Endian counter-mode, as an Authenticate, Encrypt,
/// and Additional Data (AEAD) stream cipher implementation (Rijndael-512 Cipher Stream).</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting an array of bytes:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// // initialize the Rijndael cipher with the authentication option
/// RWS cipher(true);
/// // mac code is appended to the cipher-text stream in authentication mode
/// cipher.Initialize(true, kp);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Decrypt and verify an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// RWS cipher(true);
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
/// The RWS symmetric cipher is a 512-bit wide-block Rijndael based, Authenticate, Encrypt, and Additional Data (AEAD) authenticated stream-cipher. \n
/// RWS first encrypts the plain-text using a Little-Endian CTR mode, then processes that cipher-text using a MAC function used for data authentication. \n
/// When each transform encryption call is completed, the MAC code is generated and appended to the output vector automatically. \n
/// Decryption performs these steps in reverse, processing the cipher-text bytes through the MAC function, and if authentication succeeds, then decrypting the data to plain-text. \n
/// During decryption, if the MAC codes do not match, a CryptoAuthenticationFailure exception error is thrown.</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the RWS mode can be multi-threaded. This is achieved by processing multiple blocks of message input independently across threads. \n
/// The RWS stream cipher also leverages SIMD instructions to 'double parallelize' those segments. An input block assigned to a thread
/// uses SIMD instructions to decrypt/encrypt blocks in parallel, depending on which framework is runtime available, AVX, AVX2, or AVX512 SIMD instructions. \n
/// Input blocks equal to, or divisble by the ParallelBlockSize() are processed in parallel on supported systems.
/// The cipher transform is parallelizable, however the authentication pass, is processed sequentially.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Supported key sizes are 32, 64, and 128 bytes (256, 512, and 1024 bits).</description></item>
/// <item><description>The required Nonce size is 64 bytes (512 bits).</description></item>
/// <item><description>The ISymmetricKey Info value can be used as a cipher tweak to create a unique ciphertext and MAC output.</description></item>
/// <item><description>The ciphers Initialize function can use either a SymmetricKey, or an encrypted SymmetricSecureKey key container.</description></item>
/// <item><description>The internal block input-size is fixed at 64 bytes wide (512 bits).</description></item>
/// <item><description>This cipher is capable of authentication by setting the constructors Authenticate parameter to true, the size of the input key determines the KMAC mode; 256, 512, or 1024 bit.</description></item>
/// <item><description>In authentication mode, during encryption the MAC code is automatically appended to the output cipher-text, during decryption, this MAC code is checked and authentication failure will generate a CryptoAuthenticationFailure exception.</description></item>
/// <item><description>If authentication is enabled, the cipher and MAC keys are generated by passing the input cipher-key through an instance of cSHAKE, this will yield a different cipher-text output from non-authenticated modes.</description></item>
/// <item><description>Authentication using KMAC, can be invoked by setting the Authenticate parameter in the constructor to true, when set to false, authentication is disabled.</description></item>
/// <item><description>The Info string is optional, but can be used to create a tweakable cipher, this can be used for adding additional key material, or using a second key to restrict decryption to a domain based system.</description></item>
/// <item><description>Transformation rounds are fixed 40, 80, and 120, for 256, 512, and 1024-bit keys.</description></item>
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
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198.1</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// </remarks>
class RWS final : public IStreamCipher
{
private:

	static const size_t BLOCK_SIZE = 64;
	static const size_t IK128_SIZE = 16;
	static const size_t IK256_SIZE = 32;
	static const size_t IK512_SIZE = 64;
	static const size_t IK1024_SIZE = 128;
	static const size_t INFO_SIZE = 16;
	static const size_t MAX_PRLALLOC = 100000000;
	// Transformation round counts per input key size:
	// modifying these values will increase the rounds processed by the cipher.
	// These are the minimum sizes, changes will cause test failures,
	// and incompatibility with standard the version.
	static const size_t RK128_COUNT = 20;
	static const size_t RK256_COUNT = 40;
	static const size_t RK512_COUNT = 80;
	static const size_t STATE_PRECACHED = 2048;
	static const size_t STATE_THRESHOLD = 838;
	static const uint8_t UPDATE_PREFIX = 0x80;

	class RwsState;
	std::unique_ptr<RwsState> m_rwsState;
	std::unique_ptr<IMac> m_macAuthenticator;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	RWS(const RWS&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	RWS& operator=(const RWS&) = delete;

	/// <summary>
	/// Initialize the stream cipher using a stream authentication generator type-name
	/// </summary>
	///
	/// <param name="Authenticate">Activate the authentication option</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid authentication type is chosen</exception>
	explicit RWS(bool Authenticate);

	/// <summary>
	/// Initialize the stream cipher using a secure-vector serialized state.
	/// <para>The Serialize function stores the internal state of the cipher, so that it can be reinitialized,
	/// without the need to call the Initialize function and key-schedule. 
	/// If this constructor is used, the cipher is fully initialized to the values it had when the Serialize function was called.</para>
	/// </summary>
	///
	/// <param name="State">The serialized state, created by the Serialize() function</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid state array is used</exception>
	explicit RWS(SecureVector<uint8_t> &State);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~RWS() override;

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
	const std::vector<uint8_t> Nonce() override;

	/// <summary>
	/// Read Only: Parallel block size; the uint8_t-size of the input/output data arrays passed to a transform that trigger parallel processing.
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
	const std::vector<uint8_t> Tag() override;

	/// <summary>
	/// Copies the internal MAC tag to a secure-vector
	/// </summary>
	/// 
	/// <param name="Output">The secure-vector receiving the MAC code</param>
	const void Tag(SecureVector<uint8_t> &Output) override;

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
	SecureVector<uint8_t> Serialize();

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
	void SetAssociatedData(const std::vector<uint8_t> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Encrypt/Decrypt a vector of bytes with offset and length parameters.
	/// <para>Initialize(bool, ISymmetricKey) must be called before this method can be used. 
	///	In authenticated encryption mode, the MAC code is automatically appended to the output stream at the end of the cipher-text, the output array must be int64_t enough to accommodate this TagSize() code.
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
	void Transform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length) override;

private:

	static void Finalize(std::unique_ptr<RwsState> &State, std::unique_ptr<IMac> &Authenticator);
	static void PrefetchSbox();
	void Generate(std::vector<uint8_t> &Output, size_t OutOffset, size_t Length, std::vector<uint8_t> &Counter);
	void Process(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length);
	void ProcessParallel(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length);
	void ProcessSequential(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset, size_t Length);
	void Reset();
	void Transform512(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void Transform2048(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void Transform4096(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void Transform8192(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
};

NAMESPACE_STREAMEND
#endif
