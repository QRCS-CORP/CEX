
// The GPL version 3 License (GPLv3)
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// TSX1024: An implementation if the Threefish-1024 implemented as a stream cipher
// Written by John G. Underhill, September 11, 2018
// Updated December 20, 2018
// Updated December 26, 2018
// Updated July 31, 2020
// Contact: develop@vtdev.com

#ifndef CEX_TSX1024_H
#define CEX_TSX1024_H

#include "IStreamCipher.h"
#include "ShakeModes.h"

NAMESPACE_STREAM

using Enumeration::ShakeModes;

/// <summary>
/// A vectorized and optionally parallelized Threefish-1024 120-round stream cipher [TSX1024] implementation.
/// <para>This cipher uses an optional authentication mode; KMAC enabled through the constructor to authenticate the stream.</para>
/// </summary>
/// 
/// <example>
/// <description>Encrypt and add a MAC code to an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// TSX1024 cipher(true);
/// // initialize for encryption
/// cipher.Initialize(true, kp);
/// cipher.Transform(Input, InOffset, Output, OutOffset, Length);
/// </code>
///
/// <description>Decrypt and authenticate an array:</description>
/// <code>
/// SymmetricKey kp(Key, Nonce);
/// TSX1024 cipher(true);
/// // initialize for decryption
/// cipher.Initialize(false, kp);
///
/// // decrypt the ciphertext, if the authentication fails an exception is thrown
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
/// <para>This cipher is a vectorized and optionally parallelized implementation of the Threefish-1024 cipher, used by the Skein family of hash functions. \n
/// It is capable of processing data using AVX2 or AVX512 SIMD instructions, and can also optionally employ multi-threaded parallelism. \n
/// An optional authentication component has also been added, and the cipher output can be authenticated using the Keccak based KMAC authentication code generator. \n
/// The number of rounds in the permutation function has been increased in this implementation from the standard 80 to 120 rounds to increase the potential security of the cipher.</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The transformation function used by Threefish is not limited by a dependency chain; this mode can be both SIMD pipelined and multi-threaded. \n
/// This is achieved by pre-calculating the counters positional offset over multiple 'chunks' of key-stream, which are then generated independently across threads. \n 
/// The key stream generated by encrypting the counter array(s), is used as a source of random, and XOR'd with the message input to produce the cipher text.</para>
///
/// <description><B>Authentication:</B></description>
/// <para>When operating in authenticated mode; in an encryption cycle the MAC code is automatically appended to the output cipher-text. \n
/// During a decryption cycle, the code is checked against the new code generated by the MAC generator, and a failure will throw a CryptoAuthenticationFailure exception. \n
/// It is recommended that the decryption function is wrapped in a try/catch block, so that the CryptoAuthenticationFailure exception can be handled by the calling function.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The key size is fixed at 128 bytes (1024 bits).</description></item>
/// <item><description>The nonce size is fixed at 16 bytes (128 bits), and should be a random vector.</description></item>
/// <item><description>The Info string is optional, but can be used to create a tweakable cipher; it must be 16 bytes in length.</description></item>
/// <item><description>The internal block size is 128 bytes wide.</description></item>
/// <item><description>Permutation rounds have been increased from the standard Threefish-1024 implementation of 80, and are fixed at 120.</description></item>
/// <item><description>Authentication using KMAC-1024, can be invoked by setting the Authenticate parameter in the constructor.</description></item>
/// <item><description>This cipher is capable of authentication by setting the constructors StreamAuthenticators enumeration to Poly1305, or one of the HMAC or KMAC options.</description></item>
/// <item><description>In authentication mode, during encryption the MAC code is automatically appended to the output cipher-text of each transform call, during decryption, this MAC code is checked and authentication failure will generate a CryptoAuthenticationFailure exception.</description></item>
/// <item><description>Encryption can both be pipelined (AVX2 or AVX512), and multi-threaded with any even number of threads no greater than the processors maximum virtual thread count.</description></item>
/// <item><description>The class functions are virtual, and can be accessed from an IStreamCipher instance.</description></item>
/// <item><description>The transformation functions can not be called until the Initialize(ISymmetricKey) function has been called.</description></item>
/// <item><description>If the system supports Parallel processing, and ParallelProfile().IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>The ParallelProfile().ParallelThreadsMax() property is used as the thread count in the parallel loop; it defaults to the maximum number of available virtual cores, but is user-assignable, and must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelProfile().ParallelBlockSize() is calculated automatically based on processor(s) cache size but can be user defined, but must be evenly divisible by ParallelProfile().ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The Skein Hash Function Family <a href="https://www.schneier.com/academic/paperfiles/skein1.3.pdf">Skein V1.1</a>.</description></item>
/// <item><description>NIST Round 3 <a href="https://www.schneier.com/academic/paperfiles/skein-1.3-modifications.pdf">Tweak Description</a>.</description></item>
/// <item><description>Skein <a href="https://www.schneier.com/academic/paperfiles/skein-proofs.pdf">Provable Security</a> Support for the Skein Hash Family.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3 Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition>.</description></item>
/// <item><description>FIPS 202: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Permutation Based Hash</a> and Extendable Output Functions</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">SP800-185</a> SHA-3 Derived Functions.</description></item>
/// <item><description>Team Keccak <a href="https://keccak.team/index.html">Homepage</a>.</description></item>
/// </list>
/// 
/// </remarks>
class TSX1024 final : public IStreamCipher
{
private:

	static const size_t BLOCK_SIZE = 128;
	static const std::string CLASS_NAME;
	static const size_t INFO_SIZE = 16;
	static const size_t KEY_SIZE = 128;
	static const size_t NONCE_SIZE = 2;
	static const std::vector<byte> OMEGA_INFO;
	static const size_t ROUND_COUNT = 120;
	static const size_t STATE_PRECACHED = 2048;
	static const size_t STATE_SIZE = 128;
	static const size_t TAG_SIZE = 128;

	class TSX1024State;
	std::unique_ptr<TSX1024State> m_tsx1024State;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::unique_ptr<IMac> m_macAuthenticator;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	TSX1024(const TSX1024&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	TSX1024& operator=(const TSX1024&) = delete;

	/// <summary>
	/// Initialize the TSX1024 cipher.
	/// <para>Setting the optional AuthenticatorType parameter to any value other than None, enables authentication for this cipher.
	/// In encryption mode the MAC tag will be appended to the output cipher-text automatically.
	/// In decryption mode, the code is checked before decrypting the cipher-text, and the transform function will throw a CryptoAuthenticationFailure exception on authentication failure.
	/// The default authenticator parameter in TSX1024 is KMAC1024; valid options are, None, HMACSHA2256, HMACSHA2512, KMAC256, KMAC512, and KMAC1024.</para>
	/// </summary>
	/// 
	/// <param name="Authenticate">Activate the authentication option</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid authentication type is chosen</exception>
	explicit TSX1024(bool Authenticate);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~TSX1024() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The stream ciphers enumeration type name
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
	/// Read Only: The cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this cipher.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallel processing.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: A vector of SymmetricKeySize containers, containing legal cipher input-key sizes
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
	/// Read Only: The current MAC tag value
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
	/// If encryption and authentication are set to true, the MAC code is appended to the cipher-text array after each transform call.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	/// <param name="Parameters">Cipher key structure, containing cipher key, nonce, and optional info array</param>
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

	static void Finalize(std::unique_ptr<TSX1024State> &State, std::unique_ptr<IMac> &Authenticator);
	static void Generate(std::unique_ptr<TSX1024State> &State, std::array<ulong, 2> &Counter, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Process(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length);
	void Reset();
};

NAMESPACE_STREAMEND
#endif

