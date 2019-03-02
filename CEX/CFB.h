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
// An implementation of a Cipher FeedBack Mode (CFB).
// Written by John Underhill, September 24, 2014
// Updated September 16, 2016
// Updated April 18, 2017
// Updated October 14, 2017
// Updated March 1, 2019
// Contact: develop@vtdev.com

#ifndef CEX_CFB_H
#define CEX_CFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// An implementation of a Cipher FeedBack Mode
/// </summary>
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// CFB cipher(new AES(), [RegisterSize]);
/// // initialize for encryption
/// cipher.Initialize(true, SymmetricKey(Key, Nonce));
/// // encrypt one block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
///
/// <example>
/// <description>Decrypting using multi-threading:</description>
/// <code>
/// CFB cipher(BlockCiphers::AES, [RegisterSize]);
/// // enable parallel and set the parallel input block size
/// cipher.IsParallel() = true;
/// // calculated automatically based on cache size, but overridable
/// cipher.ParallelBlockSize() = cipher.ProcessorCount() * 1600;
/// // initialize for decryption
/// cipher.Initialize(false, SymmetricKey(Key, Nonce));
/// // decrypt one parallel sized block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The Cipher FeedBack mode wraps a symmetric block-cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output. \n
/// Similar to CBC encryption, the chaining mechanism requires that a ciphertext block depends on preceding plaintext blocks. \n
/// On the first block the IV is encrypted, then XOR'd with the plaintext, using the specified feedback-register number of bytes. \n
/// The block is left-shifted by rehister-size bytes, and the ciphertext is used to fill the end of the vector. \n
/// The second block is encrypted and XOR'd with the first encrypted block using the same register shift, and all subsequent blocks follow this pattern. \n
/// The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>D</B>=decrypt, <B>^</B>=XOR \n
/// <EM>Encryption</EM> \n
/// I1 ← IV . (Ij is the input value in a shift register) For 1 ≤ j ≤ u: \n
/// (a) Oj ← EK(Ij). (Compute the block-cipher output) \n
/// (b) tj ← the r leftmost bits of Oj. (Assume the leftmost is identified as bit 1) \n
/// (c) Cj ← Pj ^ tj. (Transmit the r-bit ciphertext block cj) \n
/// (d) Ij+1 ← 2r · Ij + Cj mod 2n. (Shift Cj into right end of shift register) \n
/// <EM>Decryption</EM> \n
/// Pj ← Cj ^ tj. where tj, Oj and Ij</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption function of the CFB mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded.
/// The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores. \n
/// This is achieved by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>A cipher mode constructor can either be initialized with a block-cipher instance, or using the block ciphers enumeration type name.</description></item>
/// <item><description>A block-cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The class functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(bool, ISymmetricKey) function has been called.</description></item>
/// <item><description>In CFB mode, only the decryption function can be processed in parallel.</description></item>
/// <item><description>Parallel processing is enabled on decryption by passing an input block of at least ParallelBlockSize() to the transform; this can be disabled by setting IsParallel() to false in the ParallelProfile() accessor.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, but must be evenly divisible by ParallelMinimumSize().</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class CFB final : public ICipherMode
{
private:

	static const size_t BLOCK_SIZE = 16;

	class CfbState;
	std::unique_ptr<CfbState> m_cfbState;
	std::unique_ptr<IBlockCipher> m_blockCipher;
	ParallelOptions m_parallelProfile;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CFB(const CFB&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CFB& operator=(const CFB&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CFB() = delete;

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher enumeration type name
	/// </summary>
	///
	/// <param name="CipherType">The enumeration name of a block-cipher</param>
	/// <param name="RegisterSize">The feedback register size in bytes; minimum is 1 byte, the default is the block-ciphers internal block size</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an undefined block-cipher type name is used</exception>
	explicit CFB(BlockCiphers CipherType, size_t RegisterSize = 16);

	/// <summary>
	/// Initialize the Cipher Mode using a block-cipher instance
	/// </summary>
	///
	/// <param name="Cipher">The uninitialized block-cipher instance; can not be null</param>
	/// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the block-ciphers internal block size; default value is 16 bytes</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if a null block-cipher is used, or the specified block size is invalid</exception>
	explicit CFB(IBlockCipher* Cipher, size_t RegisterSize = 16);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CFB() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The ciphers internal block-size in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The block ciphers enumeration type name
	/// </summary>
	const BlockCiphers CipherType() override;

	/// <summary>
	/// Read Only: A pointer to the underlying block-cipher instance
	/// </summary>
	IBlockCipher* Engine() override;

	/// <summary>
	/// Read Only: The cipher modes enumeration type name
	/// </summary>
	const CipherModes Enumeral() override;

	/// <summary>
	/// Read Only: The operation mode, returns true if initialized for encryption, false for decryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Read Only: The block-cipher mode has been keyed and is ready to transform data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel() override;

	/// <summary>
	/// Read Only: A vector of allowed cipher-mode input key byte-sizes
	/// </summary>
	const std::vector<SymmetricKeySize> &LegalKeySizes() override;

	/// <summary>
	/// Read Only: The cipher-modes formal class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize() override;

	/// <summary>
	/// Read/Write: Contains parallel and SIMD capability flags and sizes
	/// </summary>
	ParallelOptions &ParallelProfile() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of cipher-text bytes</param>
	/// <param name="Output">The output vector of plain-text bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of cipher-text bytes</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of plain-text bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of plain-text bytes</param>
	/// <param name="Output">The output vector of cipher-text bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes at the designated offsets.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of plain-text bytes</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of cipher-text bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) override;

	/// <summary>
	/// Initialize the cipher-mode instance
	/// </summary>
	/// 
	/// <param name="Encryption">Operation mode, true if cipher is used for encryption, false to decrypt</param>
	/// <param name="Parameters">SymmetricKey containing the encryption Key and Initialization Vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid key or nonce is used</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters) override;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	void ParallelMaxDegree(size_t Degree) override;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// Parallel processing is limited to the Decryption function only, the Encryption function will process ParallelBlockSize() blocks in sequential mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	/// <param name="Length">The number of bytes to transform</param>
	void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) override;

private:

	void Decrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount);
	void Encrypt128(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void Process(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
};

NAMESPACE_MODEEND
#endif
