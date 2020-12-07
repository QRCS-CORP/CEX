// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
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
// Version 1.1a
// An implementation of an Encrypt and Authenticate AEAD cipher mode, block cipher counter-mode with Hash based Authentication (HBA).
// Written by John G. Underhill, November 24, 2019
// Updated December 4, 2020
// Contact: develop@vtdev.com

#ifndef CEX_CHA_H
#define CEX_CHA_H

#include "ICM.h"
#include "IAeadMode.h"
#include "IMac.h"
#include "StreamAuthenticators.h"

NAMESPACE_MODE

using Exception::CryptoAuthenticationFailure;
using Mac::IMac;
using Enumeration::StreamAuthenticators;


/// <summary>
/// A block cipher CTR mode with Hash Based Authentication, an AEAD cipher mode (HBA).
/// An Encrypt and Authenticate AEAD block cipher mode.
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a 1kb vector of bytes:</description>
/// <code>
/// // create an instance using the RHX cipher and the Keccak based KMAC-256
/// HBA cipher(BlockCiphers::RHXS256, StreamAuthenticators::KMAC256);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce, [Info]));
/// // encrypt 1024 bytes, and finalize the mac, the code is appended to the end of the output vector
/// cipher.Transform(Input, 0, Output, 0, 1024);
/// </code>
/// </example>
///
/// <example>
/// <description>Decrypting a 1kb vector of bytes:</description>
/// <code>
/// // create an instance using the RHX cipher and the Keccak based KMAC-256
/// HBA cipher(BlockCiphers::RHXS256, StreamAuthenticators::KMAC256);
/// // initialize for decryption
/// cipher.Initialize(false, SymmetricKey(Key, Nonce, [Info]));
/// 
/// // decrypt 1024 bytes, if the authentication fails a CryptoAuthenticationFailure exception is thrown
/// try
/// {
///		cipher.Transform(Input, 0, Output, 0, 1024);
/// }
/// catch (CryptoAuthenticationFailure const &ex)
/// {
///		// authentication has failed, do something..
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The HBA Cipher Mode is an Authenticate Encrypt and Additional Data (AEAD) authenticated block-cipher mode. \n
/// HBA has provable security, the security-level dependant on the block cipher and MAC functions used by the mode. \n
/// HBA first encrypts the plaintext using a block-cipher counter mode (CTR), then processes that cipher-text using either an HMAC(SHA2) or KMAC, MAC authentication code generator. \n
/// When encryption is completed, the MAC code is generated and appended to the output stream after each call to Transform(Input, InOffset, OLutput, OutOffset, Length) function. \n
/// Decryption performs these steps in reverse, processing the cipher-text bytes through the MAC function, then decrypting the data to plain-text. \n
/// If during the authentication stage of decryption the MAC code check fails, a CryptoAuthenticationFailure exception is generated, and the cipher-text is not decrypted.</para>
///
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>k</B>=key, <B>E</B>=encrypt, <B>D</B>=decrypt, <B>Mk</B>=keyed mac, <B>T</B>=mac code \n
/// <EM>Encryption</EM> \n
/// For i ...n (Ci = Ek(Pi), T = Mk(Ci)). CT = C||T. \n
/// <EM>Decryption</EM> \n
/// For i ...n (T = Mk(Ci), Pi = D(Ci)). PT = P||T.</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption and decryption functions of the HBA mode can be multi-threaded. This is achieved by processing multiple blocks of message input independently across threads. \n
/// The HBA parallel mode also leverages SIMD instructions to 'double parallelize' those segments. \n
/// An input block assigned to a thread uses SIMD instructions to decrypt/encrypt 4, 8, or 16 blocks in parallel per cycle, depending on which framework is runtime available, AVX, AVX2, or AVX512 instructions. \n
/// Input blocks equal to, or divisble by the ParallelBlockSize() are processed in parallel on supported systems, this can be disabled through the ParallelProfile accessor function. \n
/// The cipher transform is parallelizable, however the authentication pass, (HMAC/KMAC), is processed sequentially. (though this implementation does support the Intel SHA2-256 SIMD instructions).</para>
///
///
/// <description><B>API and Usage:</B></description>
/// <para>
/// The constructor HBA(BlockCiphers, StreamAuthenticators), has enumeration options for the base block-cipher type, and the MAC generator type.
/// The advanced constructer HBA(IBlockCipher*, StreamAuthenticators), takes a pointer to an uninitalized block-cipher instance.
/// Instances of the cipher and generator are created and assigned to internal unique pointers. \n
/// The initialization function Initialize(bool, ISymmetricKey), sets the cipher mode to encryption or decryption mode, 
/// and initializes the state with the user supplied key parameters. \n
/// The SetAssociatedData(Input, Offset, Length) function updates the MAC generator with associatiated data. \n
/// The Transform(Input, InOffset, Output, OutOffset, Length) function process a data array, and returns the transformed data.
/// in Encryption mode, the input is encrypted and that cipher-text is added to the MAC generator, a MAC code is generated and appended to the cipher-text. \n
/// In Decryption mode, the cipher-text is first processed by the MAC generator and the resulting MAC code is compared to the code appended to the cipher-text.
/// If the codes do not match, the cipher-text has failed authentication, a CryptoAuthenticationFailure exception is raised, and the cipher-text is not decrypted.
/// HBA is not an 'online' cipher mode, one in which multiple calls to transform are be made, 
/// where the cipher-text is decrypted and the MAC updated in tandem, and the cipher-text is authenticated only after a finalization call is made.
/// This implementation, does not use the online mode format, but instead adds or authenticates a MAC each time the Transform function is called.
/// If during decryption, the MAC authentication check fails, an exception is raised and no decryption of the cipher-text takes place, 
/// thus making this implementation immune to chosen ciphertext attacks that target the underlying block-cipher.
/// </para>
/// 
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>HBA is an AEAD authenticated mode, additional data such as packet header information can be added to the authentication process.</description></item>
/// <item><description>Additional data can be added using the SetAssociatedData(Input, Offset, Length) call, and during Initialize, using the Info parameter of the SymmetricKey.</description></item>
/// <item><description>Each time the Transform function is called, this mode either adds a MAC code to the end of the output stream [encryption], or checks the MAC code appended to the cipher-text [decryption].</description></item>
/// <item><description>The Transform(Input, InOffset, Output, OutOffset, Length) function adds a MAC code to the end of the output stream in Encryption mode; the output vector must be sized to allow for the full length of the cipher-text and the MAC tag (TagSize() property).</description></item>
/// <item><description>In Decryption mode, the Transform function MACs the input cipher-text and compares the output to the MAC code appended to the input stream; if the MAC check fails, a CryptoAuthenticationFailure exception is raised.</description></item>
/// <item><description>Encryption and decryption can both be pipelined (AVX/AVX2/AVX512), and multi-threaded with any even number of threads up to the processors total [virtual] processing cores.</description></item>
/// <item><description>If the system supports Parallel processing, and IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>The recommended parallel input block-size ParallelBlockSize(), is calculated automatically based on the processor(s) L1/L2 cache sizes, the algorithms code-cache requirements, and available memory.</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property, this value can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Standard</a>.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198-1</a>: The Keyed-Hash Message Authentication Code (HMAC).</description></item>
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">Fips202</a>.</description></item>
/// <item><description>NIST <a href = "http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd">SP800-185</a>.</description></item>
/// <item><description>RFC 5116: <a href="https://tools.ietf.org/html/rfc5116">An Interface and Algorithms for Authenticated Encryption</a>.</description></item>
/// </list>
/// </remarks>
class HBA final : public IAeadMode
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t MAX_PRLALLOC = 100000000;
	static const size_t MIN_TAGSIZE = 32;

	class HbaState;
	std::unique_ptr<HbaState> m_hbaState;
	std::unique_ptr<ICM> m_cipherMode;
	std::unique_ptr<IMac> m_macAuthenticator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	HBA(const HBA&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	HBA& operator=(const HBA&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	HBA() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name.
	/// <para>The cipher instance is created and destroyed automatically.</para>
	/// </summary>
	///
	/// <param name="CipherType">The enumeration name of the block cipher</param>
	/// <param name="AuthenticatorType">The enumeration name of the MAC generator</param>,
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid block cipher type is used</exception>
	explicit HBA(BlockCiphers CipherType, StreamAuthenticators AuthenticatorType);

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance, and specify the authentication generator type.
	/// <para>The cipher instance is created and destroyed automatically.</para>
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized Block Cipher instance; can not be null</param>
	/// <param name="AuthenticatorType">The enumeration name of the MAC generator</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit HBA(IBlockCipher* Cipher, StreamAuthenticators AuthenticatorType);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~HBA() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Cipher Modes enumeration type name
	/// </summary>
	const AeadModes Enumeral() override;

	/// <summary>
	/// Read Only: True if initialized for encryption, false for decryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Read Only: The Block Cipher is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: Array of allowed cipher input key byte-sizes
	/// </summary>
	const  std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The mode and cipher name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
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
	const void Tag(SecureVector<byte> &Output);

	/// <summary>
	/// Read Only: The MAC code length in bytes
	/// </summary>
	const size_t TagSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the Cipher instance.
	/// <para>The legal symmetric key and nonce sizes are contained in the LegalKeySizes() property.
	/// The Info parameter of the SymmetricKey can be used as the initial associated data.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">Set to true if cipher is used for encryption, false for decryption mode</param>
	/// <param name="Parameters">SymmetricKey containing the encryption Key and Nonce</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null or invalid Key/Nonce is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Add additional data to the message authentication code generator.  
	/// <para>Must be set before the transformation call. 
	/// This function can only be called once per each initialization/finalization cycle.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input standard-vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if state has been processed</exception>
	void SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Add additional data to the message authentication code generator using a memory-locked vector.  
	/// <para>Must be set before the transformation call.
	/// This function can only be called once per each initialization/finalization cycle.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input secure-vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if state has been processed</exception>
	void SetAssociatedData(const SecureVector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Transform a length of bytes with offset and length parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// In encryption mode, the message data is encrypted, and the cipher-text is used by the MAC generator to calculate the MAC code, 
	/// which is appended to the output array.
	/// In decryption mode, the input cipher-text is added to the MAC generator, and an internal code is generated.
	/// This code is compared to the MAC code contained in the cipher-text; if the codes do not match a CryptoAuthenticationFailure exception is thrown.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The number of bytes to transform</param>
	void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	//~~~Private Functions~~~//

private:

	void Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length);
	bool Verify(const std::vector<byte> &Input, size_t InOffset, size_t Length);
};

NAMESPACE_MODEEND
#endif
