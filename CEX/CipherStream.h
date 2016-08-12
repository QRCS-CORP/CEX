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
// Written by John Underhill, January 21, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_CIPHERSTREAM_H
#define _CEXENGINE_CIPHERSTREAM_H

#include "Common.h"
#include "CryptoProcessingException.h"
#include "CipherDescription.h"
#include "Event.h"
#include "IByteStream.h"
#include "ICipherMode.h"
#include "IPadding.h"
#include "IStreamCipher.h"

NAMESPACE_PROCESSING

/// <summary>
/// CipherStream: used to wrap a streams cryptographic transformation.
/// <para>Wraps encryption stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of encrypting a Stream using a CipherDescription preset:</description>
/// <code>
/// KeyParams kp(key, iv);
/// MemoryStream mIn(plaintext);
/// MemoryStream mOut;
/// CipherDescription cd = CipherDescription::AES256CTR();
///
/// CipherStream cs(cd);
/// cs.Initialize(true, kp);
/// cs.Write(&mIn, &mOut);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Common::CipherDescription"/>
/// <seealso cref="CEX::Cipher::Symmetric::Stream"/>
/// <seealso cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode"/>
/// <seealso cref="CEX::Cipher::Symmetric::Block"/>
/// <seealso cref="CEX::Enumeration::SymmetricEngines"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Cipher Mode wrapped Block Ciphers, or any of the implemented Stream Ciphers.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per any of the Write() calls.</description></item>
/// <item><description>Changes to the Cipher or CipherStream ParallelBlockSize must be set after initialization.</description></item>
/// </list>
/// </remarks>
class CipherStream
{
public:

	/// <summary>
	/// ParallelBlockProfile enumeration
	/// </summary>
	enum BlockProfiles : int
	{
		/// <summary>
		/// Set parallel block size as a division of 100 segments
		/// </summary>
		ProgressProfile = 1,
		/// <summary>
		/// Set parallel block size for maximum possible speed
		/// </summary>
		SpeedProfile = 2,
		/// <summary>
		/// The block size is specified by the user
		/// </summary>
		UserDefined = 4
	};

private:
	static constexpr size_t BLOCK_SIZE = 1024;
	static constexpr size_t MAXALLOC_MB100 = 100000000;
	static constexpr size_t PARALLEL_DEFBLOCK = 64000;

	CEX::Cipher::Symmetric::Block::IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	CEX::Cipher::Symmetric::Block::Mode::ICipherMode* m_cipherEngine;
	CEX::Cipher::Symmetric::Block::Padding::IPadding* m_cipherPadding;
	bool m_destroyEngine;
	bool m_isBufferedIO;
	bool m_isCounterMode;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isParallel;
	bool m_isStreamCipher;
	size_t m_parallelBlockSize;
	size_t m_processorCount;
	BlockProfiles m_parallelBlockProfile;
	CEX::Cipher::Symmetric::Stream::IStreamCipher* m_streamCipher;

	CipherStream() {}

public:
	/// <summary>
	/// The Progress Percent event
	/// </summary>
	CEX::Event::Event<int> ProgressPercent;

	// *** Properties *** //

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get/Set: Determines how the size of a parallel block is calculated; using the <see cref="BlockProfiles">Block Profiles</see>
	/// </summary>
	BlockProfiles &ParallelBlockProfile() { return m_parallelBlockProfile; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	const size_t ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	const size_t ParallelMinimumSize() { return m_processorCount * m_blockSize; }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	const size_t ProcessorCount() { return m_processorCount; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class with a CipherDescription Structure; containing the cipher implementation details, and a KeyParams class containing the Key material.
	/// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
	/// Cipher modes, padding, and engines are destroyed automatically through this classes Destroy() method.</para>
	/// </summary>
	/// 
	/// <param name="EngineType">The encryption engine type</param>
	/// <param name="RoundCount">The number of transformation rounds</param>
	/// <param name="CipherType">The cipher mode</param>
	/// <param name="PaddingType">The padding type</param>
	/// <param name="BlockSize">The cipher blocksize</param>
	/// <param name="KdfEngine">The HX ciphers key schedule engine</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if an invalid CipherDescription or KeyParams is used</exception>
	CipherStream(CEX::Enumeration::SymmetricEngines EngineType, int RoundCount = 22, CEX::Enumeration::CipherModes CipherType = CEX::Enumeration::CipherModes::CTR, CEX::Enumeration::PaddingModes PaddingType = CEX::Enumeration::PaddingModes::PKCS7, int BlockSize = 16, CEX::Enumeration::Digests KdfEngine = CEX::Enumeration::Digests::SHA512)
		:
		m_blockCipher(0),
		m_destroyEngine(true),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
		SetScope();

		if (EngineType == CEX::Enumeration::SymmetricEngines::ChaCha || EngineType == CEX::Enumeration::SymmetricEngines::Salsa)
		{
			try
			{
				m_streamCipher = GetStreamEngine((CEX::Enumeration::StreamCiphers)EngineType, RoundCount);
			}
			catch (...)
			{
#if defined(CPPEXCEPTIONS_ENABLED)
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!");
#endif
			}

			m_isStreamCipher = true;
			ParametersCheck();
		}
		else
		{
			try
			{
				m_cipherEngine = GetCipherMode(CipherType, (CEX::Enumeration::BlockCiphers)EngineType, BlockSize, RoundCount, KdfEngine);
			}
			catch (...)
			{
#if defined(CPPEXCEPTIONS_ENABLED)
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!");
#endif
			}

			m_isStreamCipher = false;
			ParametersCheck();

			if (!m_isCounterMode)
				m_cipherPadding = GetPaddingMode(PaddingType);
		}
	}

	/// <summary>
	/// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
	/// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
	/// Cipher modes, padding, and engines are destroyed automatically through this classes Destruct() method.</para>
	/// </summary>
	/// 
	/// <param name="Header">A CipherDescription containing the cipher description</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if an invalid CipherDescription is used</exception>
	explicit CipherStream(CEX::Common::CipherDescription* Header)
		:
		m_blockCipher(0),
		m_destroyEngine(true),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Header == 0)
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");
#endif

		SetScope();

		if (Header->EngineType() == CEX::Enumeration::SymmetricEngines::ChaCha || Header->EngineType() == CEX::Enumeration::SymmetricEngines::Salsa)
		{
			try
			{
				m_streamCipher = GetStreamEngine((CEX::Enumeration::StreamCiphers)Header->EngineType(), (int)Header->RoundCount());
			}
			catch (...)
			{
#if defined(CPPEXCEPTIONS_ENABLED)
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!");
#endif
			}

			m_isStreamCipher = true;
			ParametersCheck();
		}
		else
		{
			try
			{
				m_cipherEngine = GetCipherMode(Header->CipherType(), (CEX::Enumeration::BlockCiphers)Header->EngineType(), (int)Header->BlockSize(), (int)Header->RoundCount(), Header->KdfEngine());
			}
			catch (...)
			{
#if defined(CPPEXCEPTIONS_ENABLED)
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!");
#endif
			}

			m_isStreamCipher = false;
			ParametersCheck();

			if (!m_isCounterMode)
				m_cipherPadding = GetPaddingMode(Header->PaddingType());
		}
	}

	/// <summary>
	/// Initialize the class with a Block Cipherand optional Padding instances.
	/// <para>This constructor requires an uninitialized CipherMode instance.
	/// If the PaddingMode parameter is null, X9.23 padding will be used if required.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The Block Cipher wrapped in a Cipher mode</param>
	/// <param name="Padding">The Block Cipher Padding instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null or uninitialized Cipher is used</exception>
	CipherStream(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding = 0)
		:
		m_blockCipher(0),
		m_cipherEngine(Cipher),
		m_destroyEngine(false),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(Cipher->IsEncryption()),
		m_isInitialized(false),
		m_isStreamCipher(false),
		m_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (m_cipherEngine->IsInitialized())
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");
#endif
		SetScope();
		ParametersCheck();

		// default padding
		if (Padding != 0)
			m_cipherPadding = Padding;
		else if (m_cipherEngine->Enumeral() != CEX::Enumeration::CipherModes::CTR)
			m_cipherPadding = GetPaddingMode(CEX::Enumeration::PaddingModes::X923);
	}

	/// <summary>
	/// Initialize the class with a Stream Cipher instance.
	/// <para>This constructor requires an uninitialized CipherStream instance.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The uninitialized Stream Cipher instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null or uninitialized Stream Cipher is used</exception>
	explicit CipherStream(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher)
		:
		m_blockCipher(0),
		m_cipherPadding(0),
		m_destroyEngine(false),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(),
		m_isInitialized(false),
		m_isStreamCipher(true),
		m_parallelBlockProfile(BlockProfiles::SpeedProfile),
		m_streamCipher(Cipher)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Cipher == 0)
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!");
		if (Cipher->IsInitialized())
			throw CEX::Exception::CryptoProcessingException("The cipher must be initialized through the local Initialize() method!");
#endif

		SetScope();
		ParametersCheck();
	}

	/// <summary>
	/// Destroy this class
	/// </summary>
	~CipherStream() 
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy();

	/// <summary>
	/// Initialize the cipher processing engine
	/// </summary>
	/// 
	/// <param name="Encryption">The cipher is used for encryption</param>
	/// <param name="KeyParam">The KeyParams containing the cipher key and initialization vector</param>
	void Initialize(bool Encryption, CEX::Common::KeyParams &KeyParam);

	/// <summary>
	/// Process using streams.
	/// <para>The input stream is processed and returned in the output stream.</para>
	/// </summary>
	/// 
	/// <param name="InStream">The Input Stream</param>
	/// <param name="OutStream">The Output Stream</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if Write is called before Initialize(), or the Input stream is empty</exception>
	void Write(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);

	/// <summary>
	/// Process using byte arrays.
	/// <para>The Input array is processed and returned by the Output array.</para>
	/// </summary>
	/// 
	/// <param name="Input">The Input array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Output">The Output array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if Write is called before Initialize(), or if array sizes are misaligned</exception>
	void Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

private:

	void BlockCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockCTR(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void BlockDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void BlockEncrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockEncrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void CalculateBlockSize(size_t Length);
	void CalculateProgress(size_t Length, size_t Processed);
	CEX::Cipher::Symmetric::Block::IBlockCipher* GetBlockEngine(CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine);
	CEX::Cipher::Symmetric::Block::Mode::ICipherMode* GetCipherMode(CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine);
	CEX::Cipher::Symmetric::Block::Padding::IPadding* GetPaddingMode(CEX::Enumeration::PaddingModes PaddingType);
	CEX::Cipher::Symmetric::Stream::IStreamCipher* GetStreamEngine(CEX::Enumeration::StreamCiphers EngineType, int RoundCount);
	void ParallelCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelCTR(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void ParallelDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelDecrypt(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void ParallelStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelStream(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void ProcessStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ProcessStream(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	bool IsParallelMin(size_t Length);
	void ParametersCheck();
	void SetScope();
};

NAMESPACE_PROCESSINGEND
#endif