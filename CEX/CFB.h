// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
// Implementation Details:
// An implementation of a Cipher FeedBack Mode (CFB).
// Written by John Underhill, September 24, 2014
// Updated September 16, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_CFB_H
#define _CEX_CFB_H

#include "ICipherMode.h"

NAMESPACE_MODE

/// <summary>
/// Implements a Cipher FeedBack Mode (CFB)
/// </summary>
/// 
/// <example>
/// <description>Encrypting a single block of bytes:</description>
/// <code>
/// CFB cipher(new AHX());
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
/// CFB cipher(BlockCiphers::AHX);
/// // enable parallel and set the parallel input block size
/// cipher.IsParallel() = true;
/// // calculated automatically based on cache size, but overridable
/// cipher.ParallelBlockSize() = cipher.ProcessorCount() * 32000;
/// // initialize for decryption
/// cipher.Initialize(false, SymmetricKey(Key, Nonce));
/// // decrypt one parallel sized block
/// cipher.Transform(Input, 0, Output, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>//encrypt the register, xor the ciphertext with the plaintext by block-size bytes   left shift the register  copy cipher text to the register
/// <para>The Cipher FeedBack mode wraps a symmetric block cipher, enabling the processing of multiple contiguous input blocks to produce a unique cipher-text output.<br>
/// Similar to CBC encryption, the chaining mechanism requires that a ciphertext block depends on preceding plaintext blocks.<br>
/// On the first block the Nonce (register) is first encrypted, then XOR'd with the plaintext, using the specified BlockSize number of bytes.<br>
/// The block is left-shifted by block-size bytes, and the ciphertext is used to fill the end of the vector.<br>
/// The second block is encrypted and XOR'd with the first encrypted block using the same register shift, and all subsequent blocks follow this pattern.<br>
/// The decryption function follows the reverse pattern; the block is decrypted with the symmetric cipher, and then XOR'd with the ciphertext from the previous block to produce the plain-text.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM><br> 
/// <B>C</B>=ciphertext, <B>P</B>=plaintext, <B>K</B>=key, <B>E</B>=encrypt, <B>E<SUP>-1</SUP></B>=decrypt, <B>^</B>=XOR<br>
/// <EM>Encryption</EM><br>
/// I1 ← IV . (Ij is the input value in a shift register) For 1 ≤ j ≤ u:<br>
/// (a) Oj ← EK(Ij). (Compute the block cipher output)<br>
/// (b) tj ← the r leftmost bits of Oj. (Assume the leftmost is identified as bit 1)<br>
/// (c) Cj ← Pj ^ tj. (Transmit the r-bit ciphertext block cj)<br>
/// (d) Ij+1 ← 2r · Ij + Cj mod 2n. (Shift Cj into right end of shift register)<br>
/// <EM>Decryption</EM><br>
/// Pj ← Cj ^ tj. where tj, Oj and Ij</para>
///
/// <description><B>Multi-Threading:</B></description>
/// <para>The encryption function of the CFB mode is limited by its dependency chain; that is, each block relies on information from the previous block, and so can not be multi-threaded.
/// The decryption function however, is not limited by this dependency chain and can be parallelized via the use of simultaneous processing by multiple processor cores.<br>
/// This is acheived by storing the starting vector, (the encrypted bytes), from offsets within the ciphertext stream, and then processing multiple blocks of cipher-text independently across threads.<br> 
/// The CFB parallel decryption mode also leverages SIMD instructions to 'double parallelize' those segments. A block of cipher-text assigned to a thread
/// uses SIMD instructions to decrypt 4 or 8 blocks in parallel per cycle, depending on which framework is runtime available, 128 or 256 SIMD instructions.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>A cipher mode constructor can either be initialized with a block cipher instance, or using the block ciphers enumeration name.</description></item>
/// <item><description>A block cipher instance created using the enumeration constructor, is automatically deleted when the class is destroyed.</description></item>
/// <item><description>The Transform functions are virtual, and can be accessed from an ICipherMode instance.</description></item>
/// <item><description>The DecryptBlock and EncryptBlock functions can only be accessed through the class instance.</description></item>
/// <item><description>The transformation methods can not be called until the Initialize(bool, SymmetricKey) function has been called.</description></item>
/// <item><description>In CFB mode, only the decryption function can be processed in parallel.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>Parallel processing is enabled on decryption by setting IsParallel() to true, and passing an input block of ParallelBlockSize() to the transform.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize() = data.size() - (data.size() % cipher.ParallelMinimumSize());</c></description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf">SP800-38A</a>.</description></item>
/// <item><description>Handbook of Applied Cryptography <a href="http://cacr.uwaterloo.ca/hac/about/chap7.pdf">Chapter 7: Block Ciphers</a>.</description></item>
/// </list>
/// </remarks>
class CFB : public ICipherMode
{
private:

	const size_t MAX_PRLALLOC = 100000000;
	const size_t PRC_DATACACHE = 32000;

	IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	std::vector<byte> m_cfbVector;
	BlockCiphers m_cipherType;
	bool m_destroyEngine;
	bool m_hasAVX2;
	bool m_hasSSE;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isParallel;
	size_t m_parallelBlockSize;
	size_t m_parallelMaxDegree;
	size_t m_parallelMinimumSize;
	size_t m_processorCount;

public:

	CFB(const CFB&) = delete;
	CFB& operator=(const CFB&) = delete;
	CFB& operator=(CFB&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: Block size of internal cipher in bytes
	/// </summary>
	virtual const size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: The block ciphers formal type name
	/// </summary>
	virtual BlockCiphers CipherType() { return m_cipherType; }

	/// <summary>
	/// Get: The underlying Block Cipher instance
	/// </summary>
	virtual IBlockCipher* Engine() { return m_blockCipher; }

	/// <summary>
	/// Get: The Cipher Modes enumeration type name
	/// </summary>
	virtual const CipherModes Enumeral() { return CipherModes::CFB; }

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX2() { return m_hasAVX2; }

	/// <summary>
	/// Get: Returns True if the cipher supports SSE SIMD intrinsics
	/// </summary>
	virtual const bool HasSSE() { return m_hasSSE; }

	/// <summary>
	/// Get: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() { return m_isEncryption; }

	/// <summary>
	/// Get: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get/Set: Enable automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: Array of valid encryption key byte lengths
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const { return m_blockCipher->LegalKeySizes(); }

	/// <summary>
	/// Get: The cipher mode name
	/// </summary>
	virtual const std::string Name() { return "CFB"; }

	/// <summary>
	/// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// <para>Changes to this value must be made before the <see cref="Initialize(bool, SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return MAX_PRLALLOC; }

	/// <summary>
	/// Get: The smallest valid input block byte length, when using multi-threaded processing; parallel blocks must be a multiple of this size
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return m_parallelMinimumSize; }

	/// <summary>
	/// Get/Set: The maximum number of threads allocated when using multi-threaded processing.
	/// <para>Changes to this value must be made before the <see cref="Initialize(bool, SymmetricKey)"/> function is called.</para>
	/// </summary>
	size_t &ParallelThreadsMax() { return m_parallelMaxDegree; }

	/// <summary>
	/// Get: Available system processor core count
	/// </summary>
	virtual const size_t ProcessorCount() { return m_processorCount; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher type name
	/// </summary>
	///
	/// <param name="CipherType">The formal enumeration name of a block cipher</param>
	/// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an undefined block cipher type name is used</exception>
	explicit CFB(BlockCiphers CipherType, size_t RegisterSize = 16)
		:
		m_blockCipher(0),
		m_blockSize(RegisterSize),
		m_cfbVector(0),
		m_cipherType(CipherType),
		m_destroyEngine(true),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_parallelMaxDegree(0),
		m_processorCount(0)
	{
		if (m_cipherType == BlockCiphers::None)
			throw CryptoCipherModeException("CFB:CTor", "The Cipher type can not be zero!");
		if (m_blockSize == 0)
			throw CryptoCipherModeException("CFB:CTor", "The register size can not be zero!");

		LoadState();

		if (m_blockSize > m_blockCipher->BlockSize())
			throw CryptoCipherModeException("CFB:CTor", "The register size is invalid!");
	}

	/// <summary>
	/// Initialize the Cipher Mode using a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized block cipher instance; can not be null</param>
	/// <param name="RegisterSize">Register size in bytes; minimum is 1 byte, maximum is the Block Ciphers internal block size; default value is 16 bytes</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if a null Block Cipher is used, or the specified block size is invalid</exception>
	explicit CFB(IBlockCipher* Cipher, size_t RegisterSize = 16)
		:
		m_blockCipher(Cipher),
		m_blockSize(RegisterSize),
		m_cfbVector(Cipher->BlockSize()),
		m_cipherType(Cipher->Enumeral()),
		m_destroyEngine(false),
		m_hasAVX2(false),
		m_hasSSE(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(0),
		m_parallelMaxDegree(0),
		m_parallelMinimumSize(0),
		m_processorCount(0)
	{
		if (m_blockCipher == 0)
			throw CryptoCipherModeException("CFB:CTor", "The Cipher can not be null!");
		if (m_blockSize < 1)
			throw CryptoCipherModeException("CFB:CTor", "The register size can not be zero!");
		if (m_blockSize > m_blockCipher->BlockSize())
			throw CryptoCipherModeException("CFB:CTor", "The register size is invalid! Register size can not be larger than Block Ciphers internal block size.");

		LoadState();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~CFB()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Decrypt a single block of bytes.
	/// <para>Decrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	void DecryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Decrypt a block of bytes with offset parameters.
	/// <para>Decrypts one block of bytes using the designated offsets.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of encrypted bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of decrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void DecryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if state could not be destroyed</exception>
	virtual void Destroy();

	/// <summary>
	/// Encrypt a single block of bytes. 
	/// <para>Encrypts one block of bytes beginning at a zero index.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	void EncryptBlock(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt a block of bytes using offset parameters. 
	/// <para>Encrypts one block of bytes at the designated offsets.
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of plain text bytes</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of encrypted bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	void EncryptBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	/// 
	/// <param name="Encryption">True if cipher is used for encryption, False to decrypt</param>
	/// <param name="KeyParam">SymmetricKey containing the encryption Key and Initialization Vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if a null Key or Nonce is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &KeyParam);

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Transform a block of bytes.
	/// <para>Transforms one block of bytes beginning at a zero index.
	/// Encryption or Decryption is performed based on the Encryption flag set in the Initialize() function.
	/// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
	/// Initialize(bool, SymmetricKey) must be called before this function can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Transform a block of bytes using offset parameters.
	/// <para>Transforms one block of bytes using the designated offsets.
	/// Multi-threading capable function in Decryption mode; set IsParallel() to true to enable, and process blocks of ParallelBlockSize().
	/// Initialize(bool, SymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	///
	/// <param name="Input">The input array to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

private:
	void DecryptParallel(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);
	void DecryptSegment(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, std::vector<byte> &Iv, const size_t BlockCount);
	void Detect();
	IBlockCipher* LoadCipher(BlockCiphers CipherType);
	void LoadState();
	void Scope();
};

NAMESPACE_MODEEND
#endif
