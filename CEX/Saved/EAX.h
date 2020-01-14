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
// An implementation of an Encrypt and Authenticate mode (EAX).
// Written by John G. Underhill, January 9, 2017
// Updated April 18, 2017
// Contact: develop@vtdev.com

#ifndef CEX_EAX_H
#define CEX_EAX_H

#include "IAeadMode.h"
#include "CMAC.h"
#include "CTR.h"

NAMESPACE_MODE

/// <summary>
/// EAX: An Encrypt and Authenticate AEAD block cipher mode
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a 1kb block of bytes:</description>
/// <code>
/// EAX cipher(BlockCiphers::AES);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce, [Info]));
/// // encrypt 1kb
/// cipher.Transform(Input, 0, Output, 0, 1024);
/// // finalize the mac, and append the code to the end of the output vector
/// cipher.Finalize(Output, 1024);
/// </code>
/// </example>
///
/// <example>
/// <description>Decrypting a 1kb block of bytes:</description>
/// <code>
/// EAX cipher(BlockCiphers::AES);
/// // initialize for decryption
/// cipher.Initialize(false, SymmetricKey(Key, Nonce, [Info]));
/// // decrypt 1kb
/// cipher.Transform(Input, 0, Output, 0, 1024);
///
/// // The verify call finalizes the mac and compares the internal code 
/// // to the one appended to the cipher-text input vector.
/// // If the call returns false, authentication has failed.
/// // This can also be done manually, by calling the Finalize function to generate the MAC tag,
/// // and comparing it to the tag attached to the cipher-text
/// if (!cipher.Verify(Input, decLen))
/// {
///		throw;
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The EAX Cipher Mode is an Authenticate Encrypt and Additional Data (AEAD) authenticated block-cipher mode. \n
/// EAX is an online mode, meaning it can stream data of any length, without needing to know the data size in advance. \n
/// It also has provable security, the security-level dependant on the block cipher used by the mode. \n
/// EAX first encrypts the plaintext using a block-cipher counter mode (CTR), then processes that cipher-text using a CBC-based MAC function (CMAC) used for data authentication. \n
/// When encryption is completed, the MAC code is generated and appended to the output stream using the Finalize(Output, Offset) call. \n
/// Decryption performs these steps in reverse, processing the cipher-text bytes through the MAC function, then decrypting the data to plain-text. \n
/// The Verify(Input, Offset) function can be used to compare the MAC code embedded in the cipher-text with the code generated during the decryption process.</para>
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
/// <para>The encryption and decryption functions of the EAX mode can be multi-threaded. This is achieved by processing multiple blocks of message input independently across threads. \n
/// The EAX parallel mode also leverages SIMD instructions to 'double parallelize' those segments. \n
/// An input block assigned to a thread uses SIMD instructions to decrypt/encrypt 4, 8, or 16 blocks in parallel per cycle, depending on which framework is runtime available, AVX, AVX2, or AVX512 instructions. \n
/// Input blocks equal to, or divisble by the ParallelBlockSize() are processed in parallel on supported systems, this can be disabled through the ParallelProfile accessor function. \n
/// The cipher transform is parallelizable, however the authentication pass, (CMAC), is processed sequentially.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>EAX is an AEAD authenticated mode, additional data such as packet header information can be added to the authentication process.</description></item>
/// <item><description>Additional data can be added using the SetAssociatedData(Input, Offset, Length) call, and during Initialize, using the Info parameter of the SymmetricKey.</description></item>
/// <item><description>Calling the Finalize(Output, Offset, Length) function writes the MAC code to the output vector in either encryption or decryption operation mode.</description></item>
/// <item><description>The Verify(Input, Offset, Length) function can be used to compare the MAC code embedded with the cipher-text to the internal MAC code generated after a Decryption cycle.</description></item>
/// <item><description>Encryption and decryption can both be pipelined (AVX/AVX2/AVX512), and multi-threaded with any even number of threads up to the processors total [virtual] processing cores.</description></item>
/// <item><description>If the system supports Parallel processing, and IsParallel() is set to true; passing an input block of ParallelBlockSize() to the transform will be auto parallelized.</description></item>
/// <item><description>The recommended parallel input block-size ParallelBlockSize(), is calculated automatically based on the processor(s) L1/L2 cache sizes, the algorithms code-cache requirements, and available memory.</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property, this value can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The <a href="http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf">EAX Mode</a> of Operation.</description></item>
/// <item><description>RFC 5116: <a href="https://tools.ietf.org/html/rfc5116">An Interface and Algorithms for Authenticated Encryption</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class EAX final : public IAeadMode
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t MAX_PRLALLOC = 100000000;
	static const size_t MIN_TAGSIZE = 12;

	class EaxState;
	std::unique_ptr<EaxState> m_eaxState;
	std::unique_ptr<CTR> m_cipherMode;
	std::unique_ptr<Mac::CMAC> m_macGenerator;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	EAX(const EAX&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	EAX& operator=(const EAX&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	EAX() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name.
	/// <para>The cipher instance is created and destroyed automatically.</para>
	/// </summary>
	///
	/// <param name="CipherType">The enumeration name of the block cipher</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid block cipher type is used</exception>
	explicit EAX(BlockCiphers CipherType);

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized Block Cipher instance; can not be null</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block cipher is used</exception>
	explicit EAX(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~EAX() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Enable auto-incrementing of the input nonce, each time the Finalize method is called.
	/// <para>Treats the Nonce value loaded during Initialize as a monotonic counter; 
	/// incrementing the value by 1 and re-calculating the working set each time the cipher is finalized. 
	/// If set to false, requires a re-key after each finalization cycle.</para>
	/// </summary>
	bool &AutoIncrement() override;

	/// <summary>
	/// Read Only: The Cipher Modes enumeration type name
	/// </summary>
	const AeadModes Enumeral() override;

	/// <summary>
	/// Read Only: True if initialized for encryption, False for decryption
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
	/// Read Only: The maximum legal tag length in bytes
	/// </summary>
	const size_t MaxTagSize() override;

	/// <summary>
	/// Read Only: The minimum legal tag length in bytes
	/// </summary>
	const size_t MinTagSize() override;

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
	/// Read/Write: Persist a one-time associated data for the entire session.
	/// <para>Allows the use of a single SetAssociatedData() call to apply the MAC data to all segments.
	/// Finalize and Verify can be called multiple times, applying the initial associated data to each finalize cycle.</para>
	/// </summary>
	bool &PreserveAD() override;

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

	//~~~Public Functions~~~//

	/// <summary>
	/// Calculate the MAC code (Tag) and copy it to the Output standard-vector.     
	/// <para>The output vector must be of sufficient length to receive the MAC code.
	/// This function finalizes the Encryption/Decryption cycle, all data must be processed before this function is called.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used, unless AutoIncrement is enabled.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector that receives the authentication code</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The number of MAC code bytes to write to the output vector.
	/// <para>Must be no greater than the MAC functions output size, and no less than the minimum Tag size.</para></param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized, or output vector is too small</exception>
	void Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Calculate the MAC code (Tag) and copy it to the Output secure-vector.     
	/// <para>The output vector must be of sufficient length to receive the MAC code.
	/// This function finalizes the Encryption/Decryption cycle, all data must be processed before this function is called.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector that receives the authentication code</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The number of MAC code bytes to write to the output vector.
	/// <para>Must be no greater than the MAC functions output size, and no less than the minimum Tag size.</para></param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized, or output vector is too small</exception>
	void Finalize(SecureVector<byte> &Output, size_t OutOffset, size_t Length) override;

	/// <summary>
	/// Initialize the Cipher instance.
	/// <para>The legal symmetric key and nonce sizes are contained in the LegalKeySizes() property.
	/// The Info parameter of the SymmetricKey can be used as the initial associated data.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">Set to true if cipher is used for encryption, false for decryption operation mode</param>
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
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and before any processing of plaintext or ciphertext input. 
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
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and before any processing of plaintext or ciphertext input. 
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

	/// <summary>
	/// Generate the internal MAC code and compare it with the tag contained in the Input standard-vector.   
	/// <para>This function finalizes the Decryption cycle and generates the MAC tag.
	/// The cipher must be set for Decryption and the cipher-text bytes fully processed before calling this function.
	/// Verify can be called in place of a Finalize(Output, Offset, Length) call, or after finalization.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input standard-vector containing the expected authentication code</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to compare.
	/// <para>Must be no greater than the MAC functions output size, and no less than the MinTagSize() size.</para></param>
	/// 
	/// <returns>Returns true if the authentication codes match</returns>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized for decryption</exception>
	bool Verify(const std::vector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Generate the internal MAC code and compare it with the tag contained in the Input secure-vector.   
	/// <para>This function finalizes the Decryption cycle and generates the MAC tag.
	/// The cipher must be set for Decryption and the cipher-text bytes fully processed before calling this function.
	/// Verify can be called in place of a Finalize(Output, Offset, Length) call, or after finalization.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input secure-vector containing the expected authentication code</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to compare.
	/// <para>Must be no greater than the MAC functions output size, and no less than the MinTagSize() size.</para></param>
	/// 
	/// <returns>Returns true if the authentication codes match</returns>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized for decryption</exception>
	bool Verify(const SecureVector<byte> &Input, size_t Offset, size_t Length) override;

private:

	void Compute();
	void Decrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void Encrypt128(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void UpdateTag(byte Tag);
};

NAMESPACE_MODEEND
#endif
