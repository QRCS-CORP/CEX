// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// Portions of this cipher based on the Salsa20 stream cipher designed by Daniel J. Bernstein:
// Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</a>.
// 
// Implementation Details:
// Salsa20+
// An implementation based on the Salsa20 stream cipher,
// using an higher variable rounds assignment.
// Valid Key sizes are 128, and 256 (16 and 32 bytes).
// Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.
// Written by John Underhill, October 17, 2014
// contact: develop@vtdev.com</para>

#ifndef _CEXENGINE_SALSA20_H
#define _CEXENGINE_SALSA20_H

#include "IStreamCipher.h"

NAMESPACE_STREAM

/// <summary>
/// Salsa20+: A parallelized Salsa20 stream cipher implementation
/// </summary>
/// 
/// <example>
/// <description>Encrypt an array with Salsa20:</description>
/// <code>
/// KeyParams kp(key, iv);
/// Salsa20 cipher(20);
/// // linear encrypt
/// cipher.Initialize(kp);
/// cipher.IsParallel() = false;
/// cipher.Transform(Input, Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Valid Key sizes are 128, 256 (16 and 32 bytes).</description></item>
/// <item><description>Block size is 64 bytes wide.</description></item>
/// <item><description>Valid rounds are 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28 and 30.</description></item>
/// <item><description>Parallel block size is 64,000 bytes by default; but is configurable.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Salsa20 <a href="http://www.ecrypt.eu.org/stream/salsa20pf.html">Specification</a>.</description></item>
/// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/design.pdf">Design</a>.</description></item>
/// <item><description>Salsa20 <a href="http://cr.yp.to/snuffle/security.pdf">Security</a>.</description></item>
/// </list>
/// 
/// </remarks>
class Salsa20 : public IStreamCipher
{
private:
	static constexpr size_t BLOCK_SIZE = 64;
	static constexpr size_t MAXALLOC_MB100 = 100000000;
	static constexpr size_t MAX_ROUNDS = 30;
	static constexpr size_t MIN_ROUNDS = 8;
	static constexpr size_t PARALLEL_CHUNK = 1024;
	static constexpr size_t PARALLEL_DEFBLOCK = 64000;
	static constexpr size_t ROUNDS20 = 20;
	static constexpr const char *SIGMA = "expand 32-byte k";
	static constexpr size_t STATE_SIZE = 16;
	static constexpr const char *TAU = "expand 16-byte k";
	static constexpr size_t VECTOR_SIZE = 8;

	std::vector<uint> m_ctrVector;
	std::vector<byte> m_dstCode;
	bool m_hasAVX;
	bool m_hasIntrinsics;
	bool m_isDestroyed;
	bool m_isInitialized;
	bool m_isParallel;
	std::vector<size_t> m_legalKeySizes;
	std::vector<size_t> m_legalRounds;
	size_t m_parallelBlockSize;
	size_t m_processorCount;
	size_t m_rndCount;
	std::vector<std::vector<uint>> m_threadVectors;
	std::vector<uint> m_wrkState;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size is 64 bytes wide.</para>
	/// </summary>
	virtual const size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get the current counter value
	/// </summary>
	ulong Counter() { return ((ulong)m_ctrVector[1] << 32) | (m_ctrVector[0] & 0xffffffffL); }

	/// <summary>
	/// Get/Set: Sets the Nonce value in the initialization parameters (Tau-Sigma).
	/// <para>Must be set before <see cref="Initialize(KeyParams)"/> is called.
	/// Changing this code will create a unique distribution of the cipher.
	/// Code must be 16 bytes in length and sufficiently asymmetric (no more than 2 repeating characters, at a distance of 2 intervals).</para>
	/// </summary>
	std::vector<byte> &DistributionCode() { return m_dstCode; }

	/// <summary>
	/// Get: The stream ciphers type name
	/// </summary>
	virtual const CEX::Enumeration::StreamCiphers Enumeral() { return CEX::Enumeration::StreamCiphers::Salsa; }

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX() { return m_hasAVX; }

	/// <summary>
	/// Get: Returns True if the cipher supports SIMD intrinsics
	/// </summary>
	virtual const bool HasIntrinsics() { return m_hasIntrinsics; }

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: Available Encryption Key Sizes in bytes
	/// </summary>
	virtual const std::vector<size_t>&LegalKeySizes() { return m_legalKeySizes; }

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<size_t> &LegalRounds() { return m_legalRounds; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "Salsa20"; }

	/// <summary>
	/// Get/Set: Parallel block size; must align (threads * n) with ParallelMinimumSize()
	/// </summary>
	virtual size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const size_t ParallelMinimumSize() { return m_processorCount * (STATE_SIZE * 4); }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const size_t ProcessorCount() { return GetProcessorCount(); }

	/// <summary>
	/// Get: Number of rounds
	/// </summary>
	virtual const size_t Rounds() { return m_rndCount; }

	/// <summary>
	/// Get: Initialization vector size
	/// </summary>
	virtual const size_t VectorSize() { return VECTOR_SIZE; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	///
	/// <param name="Rounds">Number of diffusion rounds. The <see cref="LegalRounds"/> property contains available sizes. Default is 20 rounds.</param>
	///
	/// <exception cref="CEX::Exception::CryptoSymmetricCipherException">Thrown if an invalid rounds count is chosen</exception>
	explicit Salsa20(size_t Rounds = ROUNDS20)
		:
		m_ctrVector(2, 0),
		m_hasAVX(false),
		m_hasIntrinsics(false),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_isParallel(false),
		m_parallelBlockSize(PARALLEL_DEFBLOCK),
		m_rndCount(Rounds),
		m_wrkState(14, 0)
	{
#if defined(ENABLE_CPPEXCEPTIONS)
		if (Rounds == 0 || (Rounds & 1) != 0)
			throw CryptoSymmetricCipherException("Salsa20:Ctor", "Rounds must be a positive even number!");
		if (Rounds < MIN_ROUNDS || Rounds > MAX_ROUNDS)
			throw CryptoSymmetricCipherException("Salsa20:Ctor", "Rounds must be between 8 and 30!");
#endif

		m_legalKeySizes = { 16, 32 };
		m_legalRounds = { 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30 };

		DetectCpu();
		SetScope();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Salsa20()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Destroy of this class
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Initialize the Cipher
	/// </summary>
	/// 
	/// <param name="KeyParam">Cipher key container. 
	/// <para>Uses the Key and IV fields of KeyParam. 
	/// The <see cref="LegalKeySizes"/> property contains valid Key sizes. 
	/// IV must be 8 bytes in size.</para>
	/// </param>
	virtual void Initialize(const CEX::Common::KeyParams &KeyParam);

	/// <summary>
	/// Reset the primary internal counter
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Encrypt/Decrypt an array of bytes.
	/// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
	/// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset parameters.
	/// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset and length parameters.
	/// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	/// <param name="Length">Number of bytes to process</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);

private:
	void DetectCpu();
	void Increase(const std::vector<uint> &Input, std::vector<uint> &Output, const size_t Length);
	void Increment(std::vector<uint> &Counter);
	void Generate(std::vector<byte> &Output, const size_t OutOffset, std::vector<uint> &Counter, const size_t Length);
	uint GetProcessorCount();
	void ProcessBlock(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length);
	void SetKey(const std::vector<byte> &Key, const std::vector<byte> &Iv);
	void SetScope();
	void Transform64(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter);
	void Transform256(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter);
	void Transform512(std::vector<byte> &Output, size_t OutOffset, std::vector<uint> &Counter);
};

NAMESPACE_STREAMEND
#endif

