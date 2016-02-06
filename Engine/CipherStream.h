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
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
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

protected:
	static constexpr unsigned int BLOCK_SIZE = 1024;
	static constexpr unsigned int MAXALLOC_MB100 = 100000000;
	static constexpr unsigned int PARALLEL_DEFBLOCK = 64000;

	CEX::Cipher::Symmetric::Block::IBlockCipher* _blockCipher;
	unsigned int _blockSize;
	CEX::Cipher::Symmetric::Block::Mode::ICipherMode* _cipherEngine;
	CEX::Cipher::Symmetric::Block::Padding::IPadding* _cipherPadding;
	bool _destroyEngine;
	bool _isBufferedIO;
	bool _isCounterMode;
	bool _isDestroyed;
	bool _isEncryption;
	bool _isInitialized;
	bool _isParallel;
	bool _isStreamCipher;
	unsigned int _parallelBlockSize;
	unsigned int _processorCount;
	BlockProfiles _parallelBlockProfile;
	CEX::Cipher::Symmetric::Stream::IStreamCipher* _streamCipher;

	CipherStream() {}

public:
	CEX::Event::Event<int> ProgressPercent;

	// *** Properties *** //

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	bool &IsParallel() { return _isParallel; }

	/// <summary>
	/// Get/Set: Determines how the size of a parallel block is calculated; using the <see cref="BlockProfiles">Block Profiles</see>
	/// </summary>
	BlockProfiles &ParallelBlockProfile() { return _parallelBlockProfile; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	unsigned int &ParallelBlockSize() { return _parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	const unsigned int ParallelMaximumSize() { return MAXALLOC_MB100; }

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	const unsigned int ParallelMinimumSize() { return _processorCount * _blockSize; }

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	const unsigned int ProcessorCount() { return _processorCount; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class with a CipherDescription Structure; containing the cipher implementation details, and a <see cref="CEX::Common::KeyParams"/> class containing the Key material.
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
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if an invalid <see cref="CEX::Common::CipherDescription">CipherDescription</see> or <see cref="CEX::Common::KeyParams">KeyParams</see> is used</exception>
	CipherStream(CEX::Enumeration::SymmetricEngines EngineType, int RoundCount = 22, CEX::Enumeration::CipherModes CipherType = CEX::Enumeration::CipherModes::CTR, CEX::Enumeration::PaddingModes PaddingType = CEX::Enumeration::PaddingModes::PKCS7, int BlockSize = 16, CEX::Enumeration::Digests KdfEngine = CEX::Enumeration::Digests::SHA512)
		:
		_destroyEngine(true),
		_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
		SetScope();

		if (EngineType == CEX::Enumeration::SymmetricEngines::ChaCha || EngineType == CEX::Enumeration::SymmetricEngines::Salsa)
		{
			try
			{
				_streamCipher = GetStreamEngine((CEX::Enumeration::StreamCiphers)EngineType, RoundCount);
			}
			catch (...)
			{
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!");
			}

			_isStreamCipher = true;
			ParametersCheck();
		}
		else
		{
			try
			{
				_cipherEngine = GetCipherMode(CipherType, (CEX::Enumeration::BlockCiphers)EngineType, BlockSize, RoundCount, KdfEngine);
			}
			catch (...)
			{
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check method parameters!");
			}

			_isStreamCipher = false;
			ParametersCheck();

			if (!_isCounterMode)
				_cipherPadding = GetPaddingMode(PaddingType);
		}
	}

	/// <summary>
	/// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
	/// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
	/// Cipher modes, padding, and engines are destroyed automatically through this classes Destruct() method.</para>
	/// </summary>
	/// 
	/// <param name="Header">A <see cref="CEX::Common::CipherDescription"/> containing the cipher description</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if an invalid <see cref="CEX::Common::CipherDescription">CipherDescription</see> is used</exception>
	CipherStream(CEX::Common::CipherDescription* Header)
		:
		_destroyEngine(true),
		_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
		if (Header == 0)
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");

		SetScope();

		if (Header->EngineType() == CEX::Enumeration::SymmetricEngines::ChaCha || Header->EngineType() == CEX::Enumeration::SymmetricEngines::Salsa)
		{
			try
			{
				_streamCipher = GetStreamEngine((CEX::Enumeration::StreamCiphers)Header->EngineType(), (int)Header->RoundCount());
			}
			catch (...)
			{
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!");
			}

			_isStreamCipher = true;
			ParametersCheck();
		}
		else
		{
			try
			{
				_cipherEngine = GetCipherMode(Header->CipherType(), (CEX::Enumeration::BlockCiphers)Header->EngineType(), (int)Header->BlockSize(), (int)Header->RoundCount(), Header->KdfEngine());
			}
			catch (...)
			{
				throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher could not be initialize, check description parameters!");
			}

			_isStreamCipher = false;
			ParametersCheck();

			if (!_isCounterMode)
				_cipherPadding = GetPaddingMode(Header->PaddingType());
		}
	}

	/// <summary>
	/// Initialize the class with a Block <see cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode">Cipher</see> and optional <see cref="CEX::Cipher::Symmetric::Block::Padding::IPadding">Padding</see> instances.
	/// <para>This constructor requires a fully initialized <see cref="CEX::Enumeration::CipherModes">CipherMode</see> instance.
	/// If the <see cref="CEX::Enumeration::PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The <see cref="CEX::Enumeration::SymmetricEngines">Block Cipher</see> wrapped in a <see cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode">Cipher</see> mode</param>
	/// <param name="Padding">The <see cref="CEX::Cipher::Symmetric::Block::Padding::IPadding">Padding</see> instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null or uninitialized <see cref="CEX::Cipher::Symmetric::Block::Mode::ICipherMode">Cipher</see> is used</exception>
	CipherStream(CEX::Cipher::Symmetric::Block::Mode::ICipherMode* Cipher, CEX::Cipher::Symmetric::Block::Padding::IPadding* Padding = 0)
		:
		_cipherEngine(Cipher),
		_destroyEngine(false),
		_isEncryption(Cipher->IsEncryption()),
		_isStreamCipher(false),
		_parallelBlockProfile(BlockProfiles::SpeedProfile)
	{
		if (_cipherEngine->IsInitialized())
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");

		SetScope();
		ParametersCheck();

		// default padding
		if (Padding != 0)
			_cipherPadding = Padding;
		else if (_cipherEngine->Enumeral() != CEX::Enumeration::CipherModes::CTR)
			_cipherPadding = GetPaddingMode(CEX::Enumeration::PaddingModes::X923);
	}

	/// <summary>
	/// Initialize the class with a <see cref="CEX::Cipher::Symmetric::Stream::IStreamCipher">Stream Cipher</see> instance.
	/// <para>This constructor requires a fully initialized <see cref="CEX::Enumeration::SymmetricEngines">CipherStream</see> instance.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The initialized <see cref="CEX::Cipher::Symmetric::Stream::IStreamCipher">Stream Cipher</see> instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null or uninitialized <see cref="CEX::Cipher::Symmetric::Stream::IStreamCipher">Stream Cipher</see> is used</exception>
	CipherStream(CEX::Cipher::Symmetric::Stream::IStreamCipher* Cipher)
		:
		_destroyEngine(false),
		_isStreamCipher(true),
		_parallelBlockProfile(BlockProfiles::SpeedProfile),
		_streamCipher(Cipher)
	{
		if (Cipher == 0)
			throw CEX::Exception::CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!");
		if (Cipher->IsInitialized())
			throw CEX::Exception::CryptoProcessingException("The cipher must be initialized through the local Initialize() method!");

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
	void Write(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);

protected:

	void BlockCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockCTR(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void BlockDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void BlockEncrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void BlockEncrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void CalculateBlockSize(unsigned int Length);
	void CalculateProgress(unsigned int Length, unsigned int Processed);
	CEX::Cipher::Symmetric::Block::IBlockCipher* GetBlockEngine(CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine);
	CEX::Cipher::Symmetric::Block::Mode::ICipherMode* GetCipherMode(CEX::Enumeration::CipherModes CipherType, CEX::Enumeration::BlockCiphers EngineType, int BlockSize, int RoundCount, CEX::Enumeration::Digests KdfEngine);
	CEX::Cipher::Symmetric::Block::Padding::IPadding* GetPaddingMode(CEX::Enumeration::PaddingModes PaddingType);
	CEX::Cipher::Symmetric::Stream::IStreamCipher* GetStreamEngine(CEX::Enumeration::StreamCiphers EngineType, int RoundCount);
	bool IsStreamCipher(CEX::Enumeration::SymmetricEngines EngineType);
	void ParallelCTR(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelCTR(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void ParallelDecrypt(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelDecrypt(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void ParallelStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ParallelStream(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	void ProcessStream(CEX::IO::IByteStream* InStream, CEX::IO::IByteStream* OutStream);
	void ProcessStream(const std::vector<byte> &Input, unsigned int InOffset, std::vector<byte> &Output, unsigned int OutOffset);
	bool IsParallelMin(unsigned int Length);
	void ParametersCheck();
	void SetScope();
};

NAMESPACE_PROCESSINGEND
#endif