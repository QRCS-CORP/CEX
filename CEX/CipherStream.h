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
// Written by John Underhill, January 21, 2015
// Updated December 9, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_CIPHERSTREAM_H
#define _CEX_CIPHERSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "CipherDescription.h"
#include "Event.h"
#include "IBlockCipher.h"
#include "IByteStream.h"
#include "ICipherMode.h"
#include "IPadding.h"
#include "IStreamCipher.h"
#include "SymmetricKeySize.h"
#include "SymmetricEngines.h"

NAMESPACE_PROCESSING

using Enumeration::BlockCiphers;
using Exception::CryptoProcessingException;
using Processing::CipherDescription;
using Enumeration::CipherModes;
using Enumeration::Digests;
using Routing::Event;
using Cipher::Symmetric::Block::IBlockCipher;
using IO::IByteStream;
using Cipher::Symmetric::Block::Mode::ICipherMode;
using Cipher::Symmetric::Block::Padding::IPadding;
using Cipher::Symmetric::Stream::IStreamCipher;
using Key::Symmetric::ISymmetricKey;
using Key::Symmetric::SymmetricKeySize;
using Enumeration::PaddingModes;
using Enumeration::StreamCiphers;
using Enumeration::SymmetricEngines;


/// <summary>
/// Used to wrap a streaming transformation.
/// <para>Wraps encryption stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a memory stream using a CipherDescription preset:</description>
/// <code>
/// SymmetricKey kp(key, iv);
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
/// <example>
/// <description>Encrypting a file in-place:</description>
/// <code>
/// // initialize file stream; input must be set with Read and output must be ReadWrite access
/// FileStream fIn("C:\\Tests\\test.txt", FileStream::FileAccess::Read);
/// FileStream fOut("C:\\Tests\\test.txt", FileStream::FileAccess::ReadWrite);
/// Key::Symmetric::SymmetricKey kp(key, iv);
///
/// // instantiate the cipher with AES-CBC
/// Processing::CipherStream cs(Enumeration::BlockCiphers::RHX, Enumeration::Digests::None, 14, Enumeration::CipherModes::CBC, Enumeration::PaddingModes::ISO7816);
/// // initialize the cipher for encryption
/// cs.Initialize(true, kp);
/// // write to file
/// cs.Write(&fIn, &fOut);
/// fIn.Close();
/// fOut.Close();
/// </code>
/// </example>
///
/// <example>
/// <description>Encrypting to a new file:</description>
/// <code>
/// // initialize file streams; input must be set with Read and output must be ReadWrite access
/// FileStream fIn("C:\\Tests\\test.txt", FileStream::FileAccess::Read);
/// FileStream fOut("C:\\Tests\\testenc.txt", FileStream::FileAccess::ReadWrite);
/// Key::Symmetric::SymmetricKey kp(key, iv);
///
/// // instantiate the cipher with AES-CTR
/// Processing::CipherStream cs(Enumeration::BlockCiphers::RHX, Enumeration::Digests::None, 14, Enumeration::CipherModes::CTR);
/// // initialize the cipher for encryption
/// cs.Initialize(true, kp);
/// // write to file
/// cs.Write(&fIn, &fOut);
/// fIn.Close();
/// fOut.Close();
/// </code>
/// </example>
///
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The CipherStream class is an easy to use wrapper that initializes and operates a symmetric cipher, automating many complex tasks down to just a couple of methods, 
/// in an extensible ease of use pattern.<br>
/// Either a block cipher and mode, or a stream cipher can be initialized through the classes constructor, using either the cipher (and options) enumeration members, or a cipher instance.<br>
/// The CipherStream class uses the IByteStream interface, and can encrypt either a byte array using MemoryStream, or a file with FileStream.<br>
/// This class supports parallel processing; if the cipher configuration supports parallelism (CTR/ICM, and CBC/CFB Decrypt), the IsParallel property will be set to true.<br>
/// The IsParallel property can be overrided and set to false, disabling parallel processing.<br>
/// If using the byte array Write method, the output array should be at least ParallelBlockSize in length to enable parallel processing.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>Uses any of the cipher mode wrapped block ciphers, or any of the implemented Stream Ciphers.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed during a Write call.</description></item>
/// <item><description>The Write methods can not be called until the Initialize(bool, ISymmetricKey) function has been called.</description></item>
/// <item><description>The Initialize function takes a boolean (Encrypt/Decrypt) flag and an ISymmetricKey, which can be either a SymmetricKey or SymmetricSecureKey container class.</description></item>
/// <item><description>Parallel processing is enabled by setting IsParallel() to true, and passing an output block of at least ParallelBlockSize to the Write function.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize() = data.size() - (data.size() % cipher.ParallelMinimumSize());</c></description></item>
/// </list>
/// </remarks>
class CipherStream
{
public:

private:
	const size_t MAX_PRLALLOC = 100000000;

	IBlockCipher* m_blockCipher;
	size_t m_blockSize;
	ICipherMode* m_cipherEngine;
	IPadding* m_cipherPadding;
	bool m_destroyEngine;
	bool m_isBufferedIO;
	bool m_isCounterMode;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isParallel;
	bool m_isStreamCipher;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	size_t m_parallelBlockSize;
	size_t m_parallelMinimumSize;
	IStreamCipher* m_streamCipher;

public:

	CipherStream() = delete;
	CipherStream(const CipherStream&) = delete;
	CipherStream& operator=(const CipherStream&) = delete;
	CipherStream& operator=(CipherStream&&) = delete;

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int> ProgressPercent;

	//~~~Properties~~~//

	/// <summary>
	/// Get/Set: Automatic processor parallelization capable.
	/// <para>This value is true if the host supports parallelization.
	/// If the system and cipher configuration both support parallelization, it can be disabled by setting this value to false.</para>
	/// </summary>
	bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get: The supported key, nonce, and info sizes for the selected cipher configuration
	/// </summary>
	const std::vector<SymmetricKeySize> LegalKeySizes() { return m_legalKeySizes; }

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: The maximum parallel input block size
	/// </summary>
	const size_t ParallelMaximumSize() { return MAX_PRLALLOC; }

	/// <summary>
	/// Get: The minimum parallel input block size
	/// </summary>
	const size_t ParallelMinimumSize() { return m_parallelBlockSize; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with block cipher enumeration parameters.
	/// <para>The default parameters are an HX extended Rijndael cipher with 22 transformation rounds, wrapped in a parallel CTR mode.</para>
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="KdfEngine">The extended HX ciphers key schedule engine; can be 'None'</param>
	/// <param name="RoundCount">The number of transformation rounds</param>
	/// <param name="ModeType">The cipher mode enumeration name</param>
	/// <param name="PaddingType">The padding mode enumeration name</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an invalid CipherDescription or SymmetricKey is used</exception>
	explicit CipherStream(BlockCiphers CipherType = BlockCiphers::RHX, Digests KdfEngine = Digests::SHA256, int RoundCount = 22, CipherModes ModeType = CipherModes::CTR, PaddingModes PaddingType = PaddingModes::None)
		:
		m_blockCipher(0),
		m_destroyEngine(true),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isStreamCipher(false),
		m_legalKeySizes(0),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_streamCipher(0)
	{
		m_cipherEngine = GetCipherMode(ModeType, CipherType, 16, RoundCount, KdfEngine);
		Scope();

		if (!m_isCounterMode)
			m_cipherPadding = GetPaddingMode(PaddingType);

	}

	/// <summary>
	/// Initialize this class with stream cipher enumeration parameters.
	/// <para>The default round count for Salsa and ChaCha is the standard 20 rounds.</para>
	/// </summary>
	/// 
	/// <param name="CipherType">The stream cipher enumeration name</param>
	/// <param name="RoundCount">The number of transformation rounds; the default for Salsa and ChaCha is 20 rounds</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an invalid cipher type or rounds count is used</exception>
	explicit CipherStream(StreamCiphers CipherType, size_t RoundCount = 20)
		:
		m_blockCipher(0),
		m_destroyEngine(true),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_isStreamCipher(true),
		m_legalKeySizes(0),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_streamCipher(0)
	{
		if (CipherType != StreamCiphers::ChaCha20 && CipherType != StreamCiphers::Salsa20)
			throw CryptoProcessingException("CipherStream:CTor", "The stream cipher is not recognized!");
		if (RoundCount < 10 || RoundCount > 30 || RoundCount % 2 != 0)
			throw CryptoProcessingException("CipherStream:CTor", "Invalid rounds count; must be an even number between 10 and 30!");

		m_streamCipher = GetStreamCipher(CipherType, RoundCount);
		Scope();
	}

	/// <summary>
	/// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
	/// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription.</para>
	/// </summary>
	/// 
	/// <param name="Header">A CipherDescription structure</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if an invalid CipherDescription is used</exception>
	explicit CipherStream(CipherDescription* Header)
		:
		m_blockCipher(0),
		m_destroyEngine(true),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(false),
		m_isInitialized(false),
		m_legalKeySizes(0),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_streamCipher(0)
	{
		if (Header == 0)
			throw CryptoProcessingException("CipherStream:CTor", "The key Header is invalid!");

		if (Header->EngineType() == SymmetricEngines::ChaCha20 || Header->EngineType() == SymmetricEngines::Salsa)
		{
			m_isStreamCipher = true;
			m_streamCipher = GetStreamCipher((StreamCiphers)Header->EngineType(), (int)Header->RoundCount());
		}
		else
		{
			m_isStreamCipher = false;
			m_cipherEngine = GetCipherMode(Header->CipherType(), (BlockCiphers)Header->EngineType(), (int)Header->BlockSize(), (int)Header->RoundCount(), Header->KdfEngine());

			if (!m_isCounterMode && Header->PaddingType() != PaddingModes::None)
				m_cipherPadding = GetPaddingMode(Header->PaddingType());
		}

		Scope();
	}

	/// <summary>
	/// Initialize the class with a block cipher mode and (optional) padding instances.
	/// <para>This constructor requires a non-null uninitialized ICipherMode instance.
	/// If the Padding parameter is null and the cipher requires padding, X9.23 padding will be used if required.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The block cipher wrapped in a cipher mode</param>
	/// <param name="Padding">The block cipher padding instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a null cipher mode is used</exception>
	explicit CipherStream(ICipherMode* Cipher, IPadding* Padding = 0)
		:
		m_blockCipher(0),
		m_cipherEngine(Cipher),
		m_cipherPadding(Padding),
		m_destroyEngine(false),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(Cipher->IsEncryption()),
		m_isInitialized(false),
		m_isStreamCipher(false),
		m_legalKeySizes(0),
		m_parallelBlockSize(0),
		m_parallelMinimumSize(0),
		m_streamCipher(0)
	{
		if (m_cipherEngine->IsInitialized())
			throw CryptoProcessingException("CipherStream:CTor", "The cipher must be initialized through the local Initialize() method!");
		if (m_cipherPadding == 0 && m_cipherEngine->Enumeral() != CipherModes::CTR)
			m_cipherPadding = GetPaddingMode(PaddingModes::X923);

		Scope();
	}

	/// <summary>
	/// Initialize the class with a stream cipher instance.
	/// <para>This constructor requires a non-null uninitialized IStreamCipher instance.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The stream cipher instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a null stream cipher is used</exception>
	explicit CipherStream(IStreamCipher* Cipher)
		:
		m_blockCipher(0),
		m_cipherPadding(0),
		m_destroyEngine(false),
		m_isBufferedIO(false),
		m_isDestroyed(false),
		m_isEncryption(),
		m_isInitialized(false),
		m_isStreamCipher(true),
		m_parallelBlockSize(0),
		m_streamCipher(Cipher)
	{
		if (Cipher == 0)
			throw CryptoProcessingException("CipherStream:CTor", "The Cipher can not be null!");
		if (Cipher->IsInitialized())
			throw CryptoProcessingException("The cipher must be initialized through the local Initialize() method!");

		Scope();
	}

	/// <summary>
	/// Destroy this class
	/// </summary>
	~CipherStream() 
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy();

	/// <summary>
	/// Initialize the cipher with a key.
	/// <para>The ISymmetricKey can be either a SymmetricKey or a SymmetricSecureKey container.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">The cipher is initialized for encryption</param>
	/// <param name="KeyParam">The ISymmetricKey containing the cipher key and initialization vector</param>
	void Initialize(bool Encryption, ISymmetricKey &KeyParam);

	/// <summary>
	/// Process using file or memory streams.
	/// <para>When using FileStreams the InStream must be initialized as Read, and the OutStream initialized as ReadWrite.</para>
	/// </summary>
	/// 
	/// <param name="InStream">The input stream containing the data to transform</param>
	/// <param name="OutStream">The output stream that receives the transformed bytes</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if Write is called before Initialize, or the Input stream is empty</exception>
	void Write(IByteStream* InStream, IByteStream* OutStream);

	/// <summary>
	/// Process using byte arrays.
	/// <para>The Input and Output arrays must be at least ParallelBlockSize to enable parallel processing.</para>
	/// </summary>
	/// 
	/// <param name="Input">The Input array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Output">The Output array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if Write is called before Initialize, or if array sizes are misaligned</exception>
	void Write(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);

private:
	void BlockTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void BlockTransform(IByteStream* InStream, IByteStream* OutStream);
	void CalculateProgress(size_t Length, size_t Processed);
	ICipherMode* GetCipherMode(CipherModes ModeType, BlockCiphers CipherType, int BlockSize, int RoundCount, Digests KdfEngine);
	IPadding* GetPaddingMode(PaddingModes PaddingType);
	IStreamCipher* GetStreamCipher(StreamCiphers CipherType, int RoundCount);
	void ParametersCheck();
	void StreamTransform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset);
	void StreamTransform(IByteStream* InStream, IByteStream* OutStream);
	void Scope();
};

NAMESPACE_PROCESSINGEND
#endif